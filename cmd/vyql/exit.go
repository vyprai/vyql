package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// The exit-code contract. Every command reports the same four codes, so a
// pipeline can act on the status alone.
//
//	0  the command run successfully
//	1  vyql could not complete
//	2  usage error -- the invocation cannot mean anything
//	3  the check ran, and did not pass
//
// Code 3 is what separates "this code has findings" from "the scanner could not
// run". Sharing a code between the two makes a pipeline unable to tell a real
// result from a broken tool.
const (
	exitOK        = 0
	exitFailed    = 1
	exitUsage     = 2
	exitCheckFail = 3
)

// errNoDataDirectory is a go install (or any other binary) that has nowhere to
// load packs and ontology from. Exit 1: the tool could not complete, distinct
// from a scan that ran and found nothing.
var errNoDataDirectory = errors.New(`could not locate the data directory; go install installs the engine only
  install the engine and the free definitions together:
    curl -fsSL https://dl.vyprsec.ai/vyql/install.sh | sh
  or download https://dl.vyprsec.ai/vyql/definitions/free/latest.tar.gz, unpack it,
  and set $VYQL_HOME or -data to the vyql/ directory
  Homebrew, Docker, and the GitHub release archive already include the free definitions`)

func commandNeedsData(cmd string) bool {
	return cmd != "cache"
}

func wantsHelp(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		if arg == "-h" || arg == "--help" {
			return true
		}
	}
	return false
}

// usageError is an invocation that cannot mean anything: an unknown command, a
// missing path, a flag value outside its set. It is detected before any work
// starts, so a mistake costs nothing.
type usageError struct {
	msg   string
	hints []string
}

func (e *usageError) Error() string {
	if len(e.hints) == 0 {
		return e.msg
	}
	return e.msg + "\n  " + strings.Join(e.hints, "\n  ")
}

// usageWith attaches guidance lines printed under the message, indented two
// spaces. A usage error that does not say what to do instead is half a message.
func usageWith(msg string, hints ...string) error {
	return &usageError{msg: msg, hints: hints}
}

// checkFailed is a command that ran correctly and whose answer is no: findings
// at or above -fail-on, a definition corpus that does not validate, a finding
// set that changed. It is not a fault, so it carries no diagnostic prefix.
type checkFailed struct{ msg string }

func (e *checkFailed) Error() string { return e.msg }

func checkFailedf(format string, args ...any) error {
	return &checkFailed{msg: fmt.Sprintf(format, args...)}
}

// exitCodeFor maps an error to its status and writes the diagnostic. A nil error
// is success and prints nothing.
//
// Errors go to stderr in every case: stdout carries the requested document and
// nothing else, so a caller redirecting it to a file gets that file uncorrupted
// even on the paths that fail.
func exitCodeFor(err error) int {
	code, msg := classify(err)
	if msg != "" {
		fmt.Fprintln(os.Stderr, msg)
	}
	return code
}

// classify maps an error to its status and the line to print, with no output of
// its own so the mapping can be asserted directly.
func classify(err error) (int, string) {
	if err == nil {
		return exitOK, ""
	}
	if check, ok := errors.AsType[*checkFailed](err); ok {
		// No "vyql:" prefix: a met threshold is a successful scan with a
		// non-zero status, not a fault, and prefixing it as an error makes
		// every gated build look like a broken one.
		return exitCheckFail, check.Error()
	}
	if usage, ok := errors.AsType[*usageError](err); ok {
		return exitUsage, "vyql: " + usage.Error()
	}
	return exitFailed, "vyql: " + err.Error()
}

// warnf writes a warning to stderr. The run continues; the reader is told
// something about it was not what they might assume.
func warnf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "vyql: warning: "+format+"\n", args...)
}
