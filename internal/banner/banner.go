// Package banner renders the VEXOR startup banner and shared UI glyphs.
package banner

import (
	"fmt"
	"strings"
)

const (
	cyan    = "\033[36m"
	magenta = "\033[35m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	red     = "\033[31m"
	reset   = "\033[0m"
)

// Info / OK / Warn / Fail are colored status glyphs used across all reports.
const (
	Info  = "[*]"
	OK    = "[+]"
	Warn  = "[!]"
	Fail  = "[-]"
	Chain = "[>]"
)

// Logo is the ASCII art shown at startup.
const Logo = `  __   ___  ____  ___   ___  ____
  \ \ / / |/ /\ \/ /_\ \_\ \/ /\ \
   \ V /|   <  \ \ / _ \ \ \ /  \_/
    \_/ |_|\_\  \_/\___/_/\_\   v1.0`

// Print renders the banner with colors and the tagline.
func Print() {
	lines := strings.Split(Logo, "\n")
	fmt.Println()
	for _, l := range lines {
		fmt.Printf(" %s%s%s\n", cyan, l, reset)
	}
	fmt.Println()
	fmt.Printf(" %sVEXOR%s %s| Vulnerability EXploit & ORchestration%s\n", magenta, reset, magenta, reset)
	fmt.Printf(" %sdeep recon -> chained discovery -> proof-of-concept -> exploitation%s\n", magenta, reset)
	fmt.Printf(" %s%s for authorized security testing only%s\n", yellow, Warn, reset)
	fmt.Println()
}

// Divider prints a thin separator line.
func Divider() {
	fmt.Printf(" %s%s%s\n", cyan, strings.Repeat("-", 66), reset)
}
