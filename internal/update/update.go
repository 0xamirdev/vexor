// Package update implements a lightweight, non-blocking release check
// against the GitHub Releases API. Every failure mode — offline network,
// rate limiting, malformed response — resolves silently so the scan is
// never delayed or interrupted.
package update

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const releasesAPI = "https://api.github.com/repos/0xamirdev/vexor/releases/latest"

// Check queries the latest published release and, when it is newer than
// current, sends its tag on the channel. The channel is buffered; on any
// error or when up to date, nothing is sent. Callers should pass a context
// with a short deadline.
func Check(ctx context.Context, current string, latest chan<- string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, releasesAPI, nil)
	if err != nil {
		return
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var payload struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return
	}
	tag := strings.TrimPrefix(payload.TagName, "v")
	if tag == "" || !isNewer(tag, current) {
		return
	}
	select {
	case latest <- "v" + tag:
	default:
	}
}

// isNewer reports whether candidate (e.g. "1.2.0") is strictly newer than
// current ("1.1.1"). Malformed versions never count as newer.
func isNewer(candidate, current string) bool {
	c, cOK := semverParts(candidate)
	u, uOK := semverParts(current)
	if !cOK || !uOK {
		return false
	}
	for i := 0; i < 3; i++ {
		if c[i] != u[i] {
			return c[i] > u[i]
		}
	}
	return false
}

// semverParts parses "1.2.3" (with optional "v" prefix and build suffix)
// into major/minor/patch ints. The bool result is false for malformed input.
func semverParts(v string) ([3]int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

// Notice renders the user-facing update warning.
func Notice(current, latest string) string {
	return fmt.Sprintf(
		"A newer VEXOR version is available: %s\n"+
			"    Current version: v%s\n"+
			"    Please update VEXOR: go install github.com/0xamirdev/vexor/cmd/vexor@latest",
		latest, current,
	)
}
