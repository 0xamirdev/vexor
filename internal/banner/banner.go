// Package banner renders the VEXOR startup banner and shared UI glyphs.
package banner

import (
	"fmt"
	"strings"

	"vexor/internal/version"
)

const (
	cyan    = "\033[36m"
	bold    = "\033[1m"
	dim     = "\033[2m"
	magenta = "\033[35m"
	green   = "\033[32m"
	yellow  = "\033[33m"
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

// Logo is the ANSI-shadow wordmark. It stays under 45 columns wide so it
// renders cleanly in narrow terminals, including Termux.
const Logo = `██╗   ██╗███████╗██╗  ██╗ ██████╗ ██████╗
██║   ██║██╔════╝╚██╗██╔╝██╔═══██╗██╔══██╗
██║   ██║█████╗   ╚███╔╝ ██║   ██║██████╔╝
╚██╗ ██╔╝██╔══╝   ██╔██╗ ██║   ██║██╔══██╗
 ╚████╔╝ ███████╗██╔╝ ██╗╚██████╔╝██║  ██║
  ╚═══╝  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝`

// Print renders the banner: wordmark, version line, tagline, and the
// authorization notice.
func Print() {
	fmt.Println()
	for _, l := range strings.Split(Logo, "\n") {
		fmt.Printf(" %s%s%s\n", cyan, l, reset)
	}
	fmt.Println()
	fmt.Printf(" %s%s%s%s  %sv%s%s\n", bold, "VEXOR", reset, magenta, reset, version.Version, reset)
	fmt.Printf(" %sautonomous web exploit-chain discovery%s\n", dim, reset)
	fmt.Printf(" %s%s  authorized targets only — unauthorized testing is illegal%s\n", yellow, Warn, reset)
	fmt.Println()
}

// Divider prints a thin separator line.
func Divider() {
	fmt.Printf(" %s%s%s\n", cyan, strings.Repeat("-", 66), reset)
}
