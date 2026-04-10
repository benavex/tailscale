// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"text/tabwriter"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn/routecheck"
)

var routecheckCmd = &ffcli.Command{
	Name:       "routecheck",
	ShortUsage: "tailscale routecheck",
	ShortHelp:  "Print a reachability report for routes with multiple paths",
	Exec:       runRoutecheck,
	FlagSet:    routecheckFlagSet,
}

var routecheckFlagSet = func() *flag.FlagSet {
	fs := newFlagSet("routecheck")
	fs.BoolVar(&routecheckArgs.force, "force", false, "force probe to generate a new reachability report")
	fs.StringVar(&routecheckArgs.format, "format", "", `output format: empty (for human-readable), "json" or "json-line"`)
	return fs
}()

var routecheckArgs struct {
	force  bool
	format string
}

func runRoutecheck(ctx context.Context, args []string) error {
	report, err := localClient.RouteCheck(ctx, routecheckArgs.force)
	if err != nil {
		return fmt.Errorf("routecheck: %w", err)
	}
	if err := printRouteCheckReport(report); err != nil {
		return err
	}
	return nil
}

func printRouteCheckReport(report *routecheck.Report) error {
	var enc *jsontext.Encoder
	switch routecheckArgs.format {
	case "":
	case "json":
		enc = jsontext.NewEncoder(Stdout, jsontext.WithIndent("\t"))
	case "json-line":
		enc = jsontext.NewEncoder(Stdout, jsontext.Multiline(false))
	default:
		return fmt.Errorf("unknown output format %q", routecheckArgs.format)
	}
	if enc != nil {
		if err := jsonv2.MarshalEncode(enc, report); err != nil {
			return err
		}
		if _, err := Stdout.Write([]byte("\n")); err != nil {
			return err
		}
		return nil
	}

	w := tabwriter.NewWriter(Stdout, 10, 5, 5, ' ', 0)
	defer w.Flush()
	fmt.Fprintf(w, "\n %s\t%s\t", "IP", "HOSTNAME")
	for _, n := range report.Reachable {
		fmt.Fprintf(w, "\n %s\t%s\t", n.Addr, strings.Trim(n.Name, "."))
	}
	fmt.Fprintln(w)
	return nil
}
