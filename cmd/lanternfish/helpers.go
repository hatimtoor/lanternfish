package main

import (
	"flag"
	"fmt"
	"os"
)

// newFlagSet builds a flag set that prints usage to stderr on error.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

// mustParse parses args allowing flags and positionals to be interspersed
// (so "scan <url> --json" works), and returns the positional arguments in
// order. It exits on parse error.
func mustParse(fs *flag.FlagSet, args []string) []string {
	var positionals []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			fmt.Fprintln(os.Stderr)
			os.Exit(2)
		}
		rest = fs.Args()
		if len(rest) == 0 {
			break
		}
		positionals = append(positionals, rest[0])
		rest = rest[1:]
	}
	return positionals
}

// firstArg returns the first positional argument, or "".
func firstArg(pos []string) string {
	if len(pos) > 0 {
		return pos[0]
	}
	return ""
}
