package detect

import (
	"context"
	"regexp"
	"strings"
)

// ssrfProbeURL points at the marker domain; if the server fetches it, a DNS
// interaction is observable by the operator (replace with a real OOB host).
const ssrfProbePath = "/ssrf-hit"

// ssrfInternalTargets are payloads aimed at cloud metadata and loopback.
var ssrfInternalTargets = []struct {
	payload  string
	evidence *regexp.Regexp
	title    string
}{
	{
		"http://127.0.0.1:80/",
		regexp.MustCompile(`(?is)<\s*(!doctype|html|head|body)[^>]*>`),
		"SSRF to Localhost HTTP Service",
	},
	{
		"http://localhost:80/",
		regexp.MustCompile(`(?is)<\s*(!doctype|html|head|body)[^>]*>`),
		"SSRF to Localhost HTTP Service (hostname)",
	},
	{
		"http://169.254.169.254/latest/meta-data/",
		regexp.MustCompile(`(?i)(^|\n|\r)\s*(ami-id|instance-id|local-ipv4|iam/security-credentials)`),
		"SSRF to AWS EC2 Instance Metadata",
	},
	{
		"http://metadata.google.internal/computeMetadata/v1/",
		regexp.MustCompile(`(?i)computeMetadata/v1/(instance|project)`),
		"SSRF to GCP Metadata Service",
	},
	{
		"file:///etc/passwd",
		regexp.MustCompile(`root:[x*!]:0:0:`),
		"SSRF with file:// Scheme (Local File Read)",
	},
	{
		"http://[::1]:80/",
		regexp.MustCompile(`(?is)<\s*(!doctype|html|head|body)[^>]*>`),
		"SSRF via IPv6 Loopback",
	},
}

// ssrfParamHints prioritize common URL-fetch parameter names.
var ssrfParamHints = []string{"url", "uri", "fetch", "proxy", "src", "source", "dest", "destination", "redirect", "next", "image", "img", "load", "file", "host", "site", "callback", "webhook", "feed", "import", "domain"}

// SSRF detects server-side request forgery by pointing URL-accepting
// parameters at internal targets and inspecting response evidence.
type SSRF struct{}

// Name implements Module.
func (SSRF) Name() string { return "ssrf" }

// Level implements Module.
func (SSRF) Level() Level { return LevelParam }

// Scan implements Module.
func (SSRF) Scan(ctx context.Context, s *Scanner, p Point) []Finding {
	var out []Finding
	// URL-shaped parameters are the primary SSRF surface; probing other
	// parameter types with URL payloads creates noise, so gate on hints.
	if !ssrfLooksURLish(p.Param) {
		return out
	}
	for _, t := range ssrfInternalTargets {
		if ctx.Err() != nil {
			return out
		}
		resp, err := s.Fire(ctx, p, p.Param, t.payload, false, nil)
		if err != nil {
			continue
		}
		m := t.evidence.FindString(resp.Body)
		if m == "" {
			continue
		}
		// The fingerprint must differ from what the payload text itself
		// triggered when merely reflected (reflection = no SSRF).
		base, _ := s.Baseline(ctx, p, false, nil)
		if base != nil && t.evidence.MatchString(base.Body) {
			continue // fingerprint present without injection; not SSRF proof
		}
		if reflectOnly(resp.Body, p, t.payload) {
			continue // payload echoed back verbatim: no server-side fetch
		}
		out = append(out, Finding{
			ID:       NewID("ssrf", p.URL, p.Param, t.payload),
			Module:   "ssrf",
			Title:    t.title,
			Severity: SeverityCritical,
			Endpoint: p.URL,
			Method:   p.Method,
			Param:    p.Param,
			Payload:  t.payload,
			Evidence: Snippet(resp.Body, m, 120),
			PoCCurl:  CurlFor(p, t.payload),
			Description: "The server fetched an attacker-chosen internal resource and exposed its response, " +
				"proving request forgery from the server's network position (metadata/loopback reachable).",
			Remediation: "Allow-list outbound hosts; block link-local & loopback ranges; disable unused URL schemes; use IMDSv2.",
		})
		return out // one confirmed internal fetch per parameter suffices
	}
	return out
}

// ssrfLooksURLish reports whether a param name implies URL fetching.
func ssrfLooksURLish(name string) bool {
	l := strings.ToLower(name)
	for _, h := range ssrfParamHints {
		if l == h || strings.Contains(l, h) {
			return true
		}
	}
	return false
}

// reflectOnly reports whether the response contains the raw payload but none
// of the expected content of the target resource — i.e. the server merely
// echoed the value instead of fetching it.
func reflectOnly(body string, p Point, payload string) bool {
	if !strings.Contains(body, payload) {
		return false
	}
	switch {
	case strings.Contains(payload, "169.254.169.254"):
		return !strings.Contains(body, "iam/security-credentials")
	case strings.Contains(payload, "metadata.google.internal"):
		return !strings.Contains(body, "computeMetadata/v1/instance")
	case strings.Contains(payload, "file://"):
		return !strings.Contains(body, "root:x:0:0:")
	default:
		return strings.Contains(body, payload)
	}
}

// ssrfMarkerURL returns the OOB marker URL for external-callback testing.
func ssrfMarkerURL(s *Scanner) string {
	return s.MarkedURL(ssrfProbePath)
}
