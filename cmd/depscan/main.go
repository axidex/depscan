// Command depscan analyzes a CycloneDX SBOM and emits a SARIF 2.1.0 report with
// an update verdict (must-update / should-update / ok) for each component.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

// errGate signals that the --fail-on threshold was met. It is not a failure of
// the scan itself, so it maps to exit code 1 with no extra error output.
var errGate = errors.New("fail-on threshold met")

// usageError marks invalid flags/arguments, which map to exit code 2.
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func main() {
	os.Exit(Execute())
}

// Execute builds and runs the root command, returning a process exit code:
// 0 success, 1 runtime error or triggered fail-on gate, 2 usage error.
func Execute() int {
	return runRoot(newRootCmd(), os.Stdout, os.Stderr)
}

func runRoot(root *cobra.Command, stdout, stderr io.Writer) int {
	root.SetOut(stdout)
	root.SetErr(stderr)

	err := root.Execute()
	if err == nil {
		return 0
	}

	var ue *usageError
	switch {
	case errors.Is(err, errGate):
		return 1
	case errors.As(err, &ue):
		fmt.Fprintln(stderr, "depscan:", ue.msg)
		return 2
	default:
		fmt.Fprintln(stderr, "depscan:", err)
		return 1
	}
}
