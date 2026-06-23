// Package report renders verdicts in human-readable formats for local debugging.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/axidex/depscan/internal/verdict"
)

// Table writes verdicts as an aligned text table to w. Components are sorted by
// severity (must-update first) then name, and ok components are included so the
// table doubles as a full inventory.
func Table(w io.Writer, verdicts []verdict.Verdict) error {
	sorted := make([]verdict.Verdict, len(verdicts))
	copy(sorted, verdicts)
	sort.SliceStable(sorted, func(i, j int) bool {
		ri, rj := rank(sorted[i].Level), rank(sorted[j].Level)
		if ri != rj {
			return ri > rj
		}
		return sorted[i].Component.Name < sorted[j].Component.Name
	})

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "VERDICT\tPACKAGE\tCURRENT\tLATEST\tUPDATE\tCVES\tTARGET")
	for _, v := range sorted {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			string(v.Level),
			v.Component.Name,
			dash(v.Component.Version),
			latest(v),
			string(v.Outdated.Kind),
			cves(v),
			dash(v.TargetVersion),
		)
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("report: flush table: %w", err)
	}
	return nil
}

func rank(l verdict.Level) int {
	switch l {
	case verdict.LevelMust:
		return 2
	case verdict.LevelShould:
		return 1
	default:
		return 0
	}
}

func latest(v verdict.Verdict) string {
	if v.Outdated.Known() && v.Outdated.Latest != "" {
		return v.Outdated.Latest
	}
	return "-"
}

func cves(v verdict.Verdict) string {
	ids := verdict.CVEs(v.Vulns)
	if len(ids) == 0 {
		// Fall back to OSV IDs when no CVE alias is present.
		ids = verdict.VulnIDs(v.Vulns)
	}
	if len(ids) == 0 {
		return "-"
	}
	if len(ids) > 3 {
		return strings.Join(ids[:3], ",") + fmt.Sprintf(",+%d", len(ids)-3)
	}
	return strings.Join(ids, ",")
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
