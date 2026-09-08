// Command vexor is the CLI entry point wiring all pipeline stages together.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"vexor/internal/banner"
	"vexor/internal/engine"
)

func main() {
	target := flag.String("u", "", "target URL, e.g. https://example.com (required)")
	threads := flag.Int("t", 8, "concurrent worker threads")
	timeout := flag.Int("timeout", 15, "per-request timeout in seconds")
	maxPages := flag.Int("p", 40, "maximum pages to crawl")
	marker := flag.String("marker", "vexor.probe.invalid", "marker domain for redirect/CORS probes (use a host you control)")
	outDir := flag.String("o", "vexor-out", "output directory for reports")
	rawHeaders := flag.String("H", "", "extra request headers, comma-separated 'Name: value' pairs")
	showBanner := flag.Bool("banner", false, "print banner and exit")
	flag.Parse()

	banner.Print()
	if *showBanner {
		return
	}
	if *target == "" {
		fmt.Fprintln(os.Stderr, " "+banner.Fail+" target is required: vexor -u https://example.com")
		flag.Usage()
		os.Exit(2)
	}
	cfg := engine.Config{
		Target:       engine.TrimTrailingSlash(*target),
		Threads:      *threads,
		Timeout:      time.Duration(*timeout) * time.Second,
		MaxPages:     *maxPages,
		MarkerDomain: *marker,
		OutputDir:    *outDir,
		Headers:      parseHeaders(*rawHeaders),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rep, err := engine.Run(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, " "+banner.Fail+" %v\n", err)
		os.Exit(1)
	}
	rep.PrintSummary()
	jsonPath, err := rep.WriteJSON(*outDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, " "+banner.Warn+" failed writing JSON report: %v\n", err)
	} else {
		fmt.Printf(" %sJSON report : %s%s\n", banner.OK, jsonPath, "\033[0m")
	}
	pocPath, err := rep.WritePoCScript(*outDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, " "+banner.Warn+" failed writing PoC script: %v\n", err)
	} else {
		fmt.Printf(" %sPoC script  : %s%s\n", banner.OK, pocPath, "\033[0m")
	}
	if len(rep.Findings) > 0 {
		os.Exit(1) // findings present: nonzero exit for CI pipelines
	}
}

// parseHeaders converts "Name: value, Name2: value2" into a map.
func parseHeaders(raw string) map[string]string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	out := map[string]string{}
	for _, part := range strings.Split(raw, ",") {
		if i := strings.Index(part, ":"); i > 0 {
			out[strings.TrimSpace(part[:i])] = strings.TrimSpace(part[i+1:])
		}
	}
	return out
}
