package detect

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// misconfigSecurityHeaders are expected hardening headers on modern apps.
var misconfigSecurityHeaders = []struct {
	name string
	why  string
}{
	{"Content-Security-Policy", "blocks inline/external script execution (XSS mitigation)"},
	{"X-Content-Type-Options", "prevents MIME-sniffing attacks"},
	{"X-Frame-Options", "mitigates clickjacking"},
	{"Strict-Transport-Security", "enforces HTTPS transport"},
	{"Referrer-Policy", "limits referrer leakage"},
}

// Misconfig probes each endpoint for CORS misconfiguration, missing security
// headers and directory listing exposure.
type Misconfig struct{}

// Name implements Module.
func (Misconfig) Name() string { return "misconfig" }

// Level implements Module.
func (Misconfig) Level() Level { return LevelEndpoint }

// Scan implements Module.
func (Misconfig) Scan(ctx context.Context, s *Scanner, p Point) []Finding {
	var out []Finding
	if isPublicStaticPath(p.URL) {
		return out
	}
	origin := "https://evil." + s.MarkerDomain
	resp, err := s.C.Do(ctx, "GET", p.URL, nil, false, map[string]string{"Origin": origin})
	if err != nil {
		return out
	}
	if f := misconfigCORS(resp, origin, p); f != nil {
		out = append(out, *f)
	}
	if f := misconfigHeaders(resp, p); f != nil {
		out = append(out, *f)
	}
	if strings.Contains(resp.Body, "Index of /") || strings.Contains(resp.Body, "Directory listing for") {
		out = append(out, Finding{
			ID:          NewID("misconfig", p.URL, "dirlisting"),
			Module:      "misconfig",
			Title:       "Directory Listing Enabled",
			Severity:    SeverityLow,
			Endpoint:    p.URL,
			Method:      "GET",
			Evidence:    "Autoindex/directory listing markup present",
			PoCCurl:     "curl -sk '" + p.URL + "'",
			Description: "The web server exposes a browsable file index, potentially leaking backups, sources or internal paths.",
			Remediation: "Disable autoindex; move sensitive files outside the web root.",
		})
	}
	return out
}

// misconfigCORS inspects ACAO reflection for arbitrary origins.
func misconfigCORS(resp *Resp, origin string, p Point) *Finding {
	acao := resp.Headers.Get("Access-Control-Allow-Origin")
	if acao == "" || acao != origin {
		return nil
	}
	acac := resp.Headers.Get("Access-Control-Allow-Credentials")
	sev := SeverityMedium
	if strings.EqualFold(acac, "true") {
		sev = SeverityHigh
	}
	title := "CORS Misconfiguration (origin reflected)"
	if sev == SeverityHigh {
		title = "CORS Misconfiguration with Credentials (origin reflected)"
	}
	return &Finding{
		ID:          NewID("misconfig", p.URL, "cors"),
		Module:      "misconfig",
		Title:       title,
		Severity:    sev,
		Endpoint:    p.URL,
		Method:      "GET",
		Payload:     "Origin: " + origin,
		Evidence:    fmt.Sprintf("Access-Control-Allow-Origin: %s | Access-Control-Allow-Credentials: %s", acao, acac),
		PoCCurl:     "curl -sk -H 'Origin: " + origin + "' '" + p.URL + "'",
		Description: corsDescription(strings.EqualFold(acac, "true")),
		Remediation: "Allow-list exact origins server-side; never reflect arbitrary Origin values.",
	}
}

// corsDescription builds the finding description based on credential mode.
func corsDescription(credentialed bool) string {
	if credentialed {
		return "The endpoint echoes arbitrary Origin headers into Access-Control-Allow-Origin and permits " +
			"credentialed cross-origin reads, enabling full data exfiltration from victim browsers."
	}
	return "The endpoint echoes arbitrary Origin headers into Access-Control-Allow-Origin, allowing " +
		"cross-origin JavaScript to read responses."
}

// misconfigHeaders reports missing security headers as a single finding.
func misconfigHeaders(resp *Resp, p Point) *Finding {
	var missing []string
	for _, h := range misconfigSecurityHeaders {
		if resp.Headers.Get(h.name) == "" {
			missing = append(missing, h.name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return &Finding{
		ID:       NewID("misconfig", p.URL, "headers"),
		Module:   "misconfig",
		Title:    "Missing Security Headers",
		Severity: SeverityLow,
		Endpoint: p.URL,
		Method:   "GET",
		Evidence: "Missing: " + strings.Join(missing, ", "),
		Description: "The response lacks hardening headers, weakening the site against XSS, clickjacking " +
			"and mixed-content attacks.",
		Remediation: "Add CSP, X-Content-Type-Options, X-Frame-Options, HSTS and Referrer-Policy headers.",
	}
}

// publicStaticPaths are well-known public files. Hardening headers and CORS
// probes on them carry no security signal — they are served to every client
// by design (robots.txt is the canonical example).
var publicStaticPaths = []string{
	"/robots.txt", "/sitemap.xml", "/favicon.ico", "/security.txt",
	"/.well-known/security.txt", "/humans.txt",
}

// publicStaticExt are asset extensions exempt from header hardening checks.
var publicStaticExt = []string{
	".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
	".woff", ".woff2", ".ttf", ".eot", ".map",
}

// isPublicStaticPath reports whether a URL is a public static file for which
// misconfiguration findings would be noise.
func isPublicStaticPath(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	p := strings.ToLower(u.Path)
	for _, k := range publicStaticPaths {
		if strings.HasSuffix(p, k) {
			return true
		}
	}
	for _, e := range publicStaticExt {
		if strings.HasSuffix(p, e) {
			return true
		}
	}
	return false
}

// AggregateHeaderFindings merges per-endpoint "Missing Security Headers"
// findings into one aggregated finding listing the affected endpoints, so a
// site-wide gap produces a single actionable report instead of duplicates.
func AggregateHeaderFindings(fs []Finding) []Finding {
	var affected []string
	var rest []Finding
	for _, f := range fs {
		if f.Module == "misconfig" && strings.Contains(f.Title, "Missing Security Headers") {
			affected = append(affected, f.Endpoint)
			continue
		}
		rest = append(rest, f)
	}
	if len(affected) < 2 {
		return fs
	}
	seen := map[string]bool{}
	uniq := make([]string, 0, len(affected))
	for _, e := range affected {
		if !seen[e] {
			seen[e] = true
			uniq = append(uniq, e)
		}
	}
	if len(uniq) < 2 {
		return fs
	}
	const maxList = 8
	list := uniq
	extra := 0
	if len(list) > maxList {
		list, extra = list[:maxList], len(list)-maxList
	}
	agg := Finding{
		ID:       NewID("misconfig", "headers", "aggregated", strings.Join(uniq, "|")),
		Module:   "misconfig",
		Title:    fmt.Sprintf("Missing Security Headers (site-wide, %d endpoints)", len(uniq)),
		Severity: SeverityLow,
		Endpoint: uniq[0],
		Method:   "GET",
		Evidence: fmt.Sprintf("%d endpoints served without the full hardening header set, including:\n%s",
			len(uniq), strings.Join(list, "\n")),
		Description: "Security hardening headers are absent across the site rather than on a single page. " +
			"Site-wide absence indicates a server/CDN configuration gap rather than isolated page issues." +
			map[bool]string{true: fmt.Sprintf(" (%d more endpoints affected)", extra), false: ""}[extra > 0],
		Remediation: "Set CSP, X-Content-Type-Options, X-Frame-Options, HSTS and Referrer-Policy globally at the server or CDN layer.",
	}
	return append(rest, agg)
}
