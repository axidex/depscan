package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/axidex/depscan/internal/outdated"
	"github.com/axidex/depscan/internal/report"
	"github.com/axidex/depscan/internal/sarif"
	"github.com/axidex/depscan/internal/sbom"
	"github.com/axidex/depscan/internal/scan"
	"github.com/axidex/depscan/internal/verdict"
	"github.com/axidex/depscan/internal/vuln"
)

const informationURI = "https://github.com/axidex/depscan"

// newScanner builds the production scanner. It is a package variable so tests
// can inject a scanner backed by fake clients instead of reaching the network.
var newScanner = func(cfg config) *scan.Scanner {
	return scan.New(
		vuln.NewOSVClient(vuln.WithConcurrency(cfg.concurrency), vuln.WithLogger(cfg.logger)),
		outdated.NewChecker(outdated.DefaultRegistries(nil)...).WithLogger(cfg.logger),
	)
}

// newLogger builds a stderr logger. Without debug it discards everything so
// normal output is unchanged; with debug it emits text-formatted debug records.
func newLogger(stderr io.Writer, debug bool) *slog.Logger {
	if !debug {
		return slog.New(slog.DiscardHandler)
	}
	return slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// runScan executes a full scan. It returns nil on success, errGate when the
// --fail-on threshold is met, or a wrapped error on any runtime failure.
func runScan(ctx context.Context, cfg config, stdout, stderr io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	logger := newLogger(stderr, cfg.debug)
	cfg.logger = logger
	logger.DebugContext(ctx, "depscan: configuration resolved",
		"sbom", cfg.sbomPath, "out", cfg.outPath, "offline", cfg.offline,
		"failOn", cfg.failOn, "format", cfg.format,
		"concurrency", cfg.concurrency, "timeout", cfg.timeout.String())

	components, skipped, err := loadComponents(cfg.sbomPath)
	if err != nil {
		return err
	}
	fmt.Fprintf(stderr, "depscan: scanning %d component(s)", len(components))
	if skipped > 0 {
		fmt.Fprintf(stderr, " (%d without purl skipped)", skipped)
	}
	if cfg.offline {
		fmt.Fprint(stderr, " [offline: registry checks disabled]")
	}
	fmt.Fprintln(stderr)

	rep, err := newScanner(cfg).Scan(ctx, components, scan.Options{
		Offline:     cfg.offline,
		Concurrency: cfg.concurrency,
		Logger:      logger,
	})
	if err != nil {
		return err
	}
	for _, w := range rep.Warnings {
		fmt.Fprintln(stderr, "depscan: warning:", w)
	}

	if err := writeSARIF(cfg.outPath, rep.Verdicts, stdout); err != nil {
		return err
	}
	if cfg.format == "table" {
		if err := report.Table(stdout, rep.Verdicts); err != nil {
			return err
		}
	}

	printSummary(stderr, rep.Verdicts)

	if gateTriggered(rep.Verdicts, cfg.failOn) {
		fmt.Fprintf(stderr, "depscan: fail-on=%s threshold met\n", cfg.failOn)
		return errGate
	}
	return nil
}

func loadComponents(path string) ([]sbom.Component, int, error) {
	if path == "-" {
		return sbom.Parse(os.Stdin)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("open SBOM: %w", err)
	}
	defer f.Close()
	return sbom.Parse(f)
}

func writeSARIF(outPath string, verdicts []verdict.Verdict, stdout io.Writer) error {
	meta := sarif.ToolMeta{
		Name:           "depscan",
		Version:        version,
		InformationURI: informationURI,
	}

	if outPath == "-" {
		return sarif.Render(stdout, verdicts, meta)
	}
	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer f.Close()
	return sarif.Render(f, verdicts, meta)
}

func printSummary(stderr io.Writer, verdicts []verdict.Verdict) {
	var must, should, ok int
	for _, v := range verdicts {
		switch v.Level {
		case verdict.LevelMust:
			must++
		case verdict.LevelShould:
			should++
		default:
			ok++
		}
	}
	fmt.Fprintf(stderr, "depscan: %d must-update, %d should-update, %d ok\n", must, should, ok)
}

// gateTriggered reports whether any verdict meets or exceeds the fail-on level.
func gateTriggered(verdicts []verdict.Verdict, failOn string) bool {
	threshold := levelRank(verdict.Level(failOn))
	if threshold == 0 {
		return false
	}
	for _, v := range verdicts {
		if levelRank(v.Level) >= threshold {
			return true
		}
	}
	return false
}

func levelRank(l verdict.Level) int {
	switch l {
	case verdict.LevelMust:
		return 2
	case verdict.LevelShould:
		return 1
	default:
		return 0
	}
}
