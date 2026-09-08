// Package version holds the single source of truth for the VEXOR release
// version. Every user-facing surface (banner, --version flag, HTTP user
// agent) reads from here so a release bump is a one-line change.
package version

// Version is the current VEXOR release version.
const Version = "1.1.2"

// UserAgent returns the tool identifier embedded in scan requests.
func UserAgent() string {
	return "VEXOR/" + Version
}
