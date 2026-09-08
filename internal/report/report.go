// Package report renders VEXOR results to the console and machine-readable
// artifacts (JSON report + PoC replay script).
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vexor/internal/banner"
	"vexor/internal/detect"
)

// Finding aliases the shared type for callers.
type Finding = detect.Finding

// Exploit mirrors exploit.Result without an import cycle.
type Exploit struct {
	FindingID string `json:"finding_id"`
	Kind      string `json:"kind"`
	Proof     string `json:"proof"`
	Runnable  string `json:"runnable,omitempty"`
}

// Report aggregates one full VEXOR run.
type Report struct {
	ToolVersion  string           `json:"tool_version"`
	Target       string           `json:"target"`
	StartedAt    time.Time        `json:"started_at"`
	FinishedAt   time.Time        `json:"finished_at"`
	Duration     string           `json:"duration"`
	Endpoints    string           `json:"endpoints_summary"`
	TotalPoints  int              `json:"total_points"`
	ChainedCount int              `json:"chained_findings"`
	Findings     []detect.Finding `json:"findings"`
	Exploits     []Exploit        `json:"exploits"`
}

// PrintSummary renders the human-readable console summary.
func (r *Report) PrintSummary() {
	dur := r.FinishedAt.Sub(r.StartedAt).Round(time.Second)
	banner.Divider()
	sevCount := map[detect.Severity]int{}
	for _, f := range r.Findings {
		sevCount[f.Severity]++
	}
	fmt.Printf(" Target      : %s\n", r.Target)
	fmt.Printf(" Duration    : %s\n", dur)
	fmt.Printf(" Findings    : %d total\n", len(r.Findings))
	fmt.Printf("   Critical  : %d\n", sevCount[detect.SeverityCritical])
	fmt.Printf("   High      : %d\n", sevCount[detect.SeverityHigh])
	fmt.Printf("   Medium    : %d\n", sevCount[detect.SeverityMedium])
	fmt.Printf("   Low       : %d\n", sevCount[detect.SeverityLow])
	fmt.Printf("   Info      : %d\n", sevCount[detect.SeverityInfo])
	if r.ChainedCount > 0 {
		fmt.Printf(" Chained     : %d (combined attacks)\n", r.ChainedCount)
	}
	if len(r.Exploits) > 0 {
		fmt.Printf(" Exploit PoCs: %d\n", len(r.Exploits))
	}
	fmt.Println()
	for _, f := range r.Findings {
		printFinding(f)
	}
	for _, e := range r.Exploits {
		fmt.Printf(" %s exploit %s: %s\n", banner.Chain, e.FindingID, e.Proof)
	}
	banner.Divider()
}

// printFinding renders one finding block.
func printFinding(f detect.Finding) {
	color := severityColor(f.Severity)
	fmt.Printf(" %s%s %s\033[0m\n", color, f.Severity, f.Title)
	fmt.Printf("   ID       : %s\n", f.ID)
	fmt.Printf("   Endpoint : %s %s\n", f.Method, f.Endpoint)
	if f.Param != "" {
		fmt.Printf("   Param    : %s\n", f.Param)
	}
	if f.Payload != "" {
		fmt.Printf("   Payload  : %s\n", oneLine(f.Payload))
	}
	fmt.Printf("   Evidence : %s\n", oneLine(f.Evidence))
	if f.PoCCurl != "" {
		fmt.Printf("   PoC      : %s\n", f.PoCCurl)
	}
	if len(f.ChainOf) > 0 {
		fmt.Printf("   Chain    : %s\n", strings.Join(f.ChainOf, " + "))
	}
	fmt.Println()
}

// severityColor maps severity to an ANSI color.
func severityColor(s detect.Severity) string {
	switch s {
	case detect.SeverityCritical:
		return "\033[1;31m"
	case detect.SeverityHigh:
		return "\033[31m"
	case detect.SeverityMedium:
		return "\033[33m"
	case detect.SeverityLow:
		return "\033[36m"
	default:
		return "\033[90m"
	}
}

// oneLine collapses whitespace for console printing.
func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	if len(s) > 160 {
		s = s[:157] + "..."
	}
	return s
}

// WriteJSON persists the machine-readable report.
func (r *Report) WriteJSON(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	r.Duration = r.FinishedAt.Sub(r.StartedAt).Round(time.Second).String()
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	host := sanitizeHost(r.Target)
	path := filepath.Join(dir, "vexor_"+host+"_"+r.StartedAt.Format("20060102_150405")+".json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// WritePoCScript emits a runnable bash script replaying every PoC curl.
func (r *Report) WritePoCScript(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("#!/usr/bin/env bash\n")
	b.WriteString("# VEXOR PoC replay script - for authorized testing only\n")
	b.WriteString("set -euo pipefail\n\n")
	for _, f := range r.Findings {
		if f.PoCCurl == "" {
			continue
		}
		fmt.Fprintf(&b, "echo '=== %s | %s ==='\n%s\n\n", f.ID, f.Title, f.PoCCurl)
	}
	host := sanitizeHost(r.Target)
	path := filepath.Join(dir, "vexor_poc_"+host+"_"+r.StartedAt.Format("20060102_150405")+".sh")
	if err := os.WriteFile(path, []byte(b.String()), 0o755); err != nil {
		return "", err
	}
	return path, nil
}

// sanitizeHost turns a URL into a filename-safe token.
func sanitizeHost(target string) string {
	s := strings.ReplaceAll(target, "://", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, "?", "_")
	s = strings.ReplaceAll(s, "&", "_")
	s = strings.ReplaceAll(s, "=", "_")
	if s == "" {
		return "target"
	}
	return s
}
