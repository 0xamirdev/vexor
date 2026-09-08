package detect

import (
	"context"
	"fmt"
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
		PoCCurl:  "curl -skI '" + p.URL + "'",
		Description: "The response lacks hardening headers, weakening the site against XSS, clickjacking " +
			"and mixed-content attacks.",
		Remediation: "Add CSP, X-Content-Type-Options, X-Frame-Options, HSTS and Referrer-Policy headers.",
	}
}
