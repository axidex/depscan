package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/axidex/depscan/internal/verdict"
)

// config is the resolved, validated runtime configuration for a scan.
type config struct {
	sbomPath    string
	outPath     string
	offline     bool
	failOn      string
	format      string
	concurrency int
	timeout     time.Duration
	debug       bool
	// logger is set by runScan from the resolved streams and debug flag.
	logger *slog.Logger
}

const longDescription = `depscan analyzes a CycloneDX JSON SBOM and writes a SARIF 2.1.0 report with an
update verdict for every component:

  must-update    a vulnerability with an available fix is present (SARIF error)
  should-update  a vulnerability without a fix, or a minor/major version lag (warning)
  ok             up to date, patch-only lag, or no data (no SARIF result)

Vulnerabilities come from OSV.dev; "is there a newer version" comes from the
npm, PyPI and Maven Central registries. Flags can also be set via DEPSCAN_*
environment variables or a config file (--config).`

// newRootCmd builds the root command with its own viper instance, so multiple
// commands (e.g. in tests) do not share global configuration state.
func newRootCmd() *cobra.Command {
	v := viper.New()
	var cfgFile string

	cmd := &cobra.Command{
		Use:           "depscan",
		Short:         "SBOM (CycloneDX JSON) → SARIF dependency verdicts",
		Long:          longDescription,
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				return &usageError{msg: fmt.Sprintf("unexpected arguments: %s", strings.Join(args, " "))}
			}
			return nil
		},
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			return initConfig(v, cfgFile)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := configFromViper(v)
			if err != nil {
				return err
			}
			return runScan(cmd.Context(), cfg, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}

	flags := cmd.Flags()
	flags.StringP("sbom", "s", "", "path to CycloneDX JSON SBOM ('-' for stdin) (required)")
	flags.StringP("out", "o", "results.sarif", "path to write the SARIF report ('-' for stdout)")
	flags.Bool("offline", false, "skip registry (outdated) lookups for air-gapped environments")
	flags.String("fail-on", "", "exit non-zero if any finding is at this level or higher: must-update|should-update")
	flags.String("format", "sarif", "stdout format: sarif (file only) or table (also print a table)")
	flags.Int("concurrency", 8, "max concurrent registry/OSV requests")
	flags.Duration("timeout", 2*time.Minute, "overall scan timeout")
	flags.Bool("debug", false, "enable verbose debug logging to stderr")
	cmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (optional; defaults to ./.depscan.yaml or $HOME/.depscan.yaml)")

	// Bind flags to viper so DEPSCAN_* env vars and a config file can supply
	// values, with explicit flags taking precedence.
	if err := v.BindPFlags(flags); err != nil {
		panic(fmt.Sprintf("depscan: bind flags: %v", err))
	}

	cmd.SetVersionTemplate("depscan {{.Version}}\n")
	// Map pflag parse errors (unknown flag, bad value) to usage errors (exit 2).
	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return &usageError{msg: err.Error()}
	})
	return cmd
}

// initConfig wires up environment-variable and config-file resolution. A
// missing default config file is not an error; an explicitly requested one is.
func initConfig(v *viper.Viper, cfgFile string) error {
	v.SetEnvPrefix("DEPSCAN")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		v.SetConfigName(".depscan")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		if home, err := os.UserHomeDir(); err == nil {
			v.AddConfigPath(home)
		}
	}

	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if cfgFile != "" || !errors.As(err, &notFound) {
			return fmt.Errorf("read config: %w", err)
		}
	}
	return nil
}

// configFromViper resolves and validates the configuration. Validation failures
// are usageErrors (exit code 2).
func configFromViper(v *viper.Viper) (config, error) {
	cfg := config{
		sbomPath:    v.GetString("sbom"),
		outPath:     v.GetString("out"),
		offline:     v.GetBool("offline"),
		failOn:      v.GetString("fail-on"),
		format:      v.GetString("format"),
		concurrency: v.GetInt("concurrency"),
		timeout:     v.GetDuration("timeout"),
		debug:       v.GetBool("debug"),
	}

	if cfg.sbomPath == "" {
		return config{}, &usageError{msg: "--sbom is required"}
	}
	if err := validateFailOn(cfg.failOn); err != nil {
		return config{}, &usageError{msg: err.Error()}
	}
	if cfg.format != "sarif" && cfg.format != "table" {
		return config{}, &usageError{msg: fmt.Sprintf("invalid --format %q: want sarif or table", cfg.format)}
	}
	if cfg.format == "table" && cfg.outPath == "-" {
		return config{}, &usageError{msg: "--format table cannot be combined with --out=-: both would write to stdout and corrupt the SARIF stream"}
	}
	return cfg, nil
}

func validateFailOn(v string) error {
	switch v {
	case "", string(verdict.LevelMust), string(verdict.LevelShould):
		return nil
	default:
		return fmt.Errorf("invalid --fail-on %q: want must-update or should-update", v)
	}
}
