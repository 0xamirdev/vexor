package detect

import (
	"context"
	"net/url"
	"strings"
)

// redirectPayloads combine classic, protocol-relative, scheme-obfuscation
// and auth-trust bypass vectors.
var redirectPayloads = []string{
	"https://vexor.example.net",
	"//vexor.example.net",
	"///vexor.example.net",
	`\/\/vexor.example.net`,
	"https:/\\/vexor.example.net",
	"//vexor.example.net%2f..",
	"https://vexor.example.net#?//trusted.com",
	"https://trusted.com@vexor.example.net",
	"https://vexor.example.net\t/",
	"%2F%2Fvexor.example.net",
}

// Redirect detects open redirects: a controlled marker host appears in the
// Location header or in an HTML/JS-driven client redirect.
type Redirect struct{}

// Name implements Module.
func (Redirect) Name() string { return "redirect" }

// Level implements Module.
func (Redirect) Level() Level { return LevelParam }

// Scan implements Module.
func (Redirect) Scan(ctx context.Context, s *Scanner, p Point) []Finding {
	var out []Finding
	marker := s.MarkerDomain
	for _, tpl := range redirectPayloads {
		if ctx.Err() != nil {
			return out
		}
		payload := strings.ReplaceAll(tpl, "vexor.example.net", "rd."+marker)
		resp, err := s.Fire(ctx, p, p.Param, payload, false, nil)
		if err != nil {
			continue
		}
		if loc := resp.Headers.Get("Location"); loc != "" && redirectsOut(loc, "rd."+marker) {
			out = append(out, Finding{
				ID:       NewID("redirect", p.URL, p.Param, "header", tpl),
				Module:   "redirect",
				Title:    "Open Redirect (Location Header)",
				Severity: SeverityMedium,
				Endpoint: p.URL,
				Method:   p.Method,
				Param:    p.Param,
				Payload:  payload,
				Evidence: "Location: " + loc,
				PoCURL:   PoCGet(p, payload),
				PoCCurl:  CurlFor(p, payload),
				Description: "The application redirects to an attacker-supplied off-site URL, enabling phishing " +
					"chains and OAuth token theft via trusted-domain redirect allow-list abuse.",
				Remediation: "Validate destination against exact allow-list; reject protocol-relative URLs and non-http schemes.",
			})
			return out
		}
		// client-side redirect: meta refresh or location= in reflected HTML
		if resp.StatusCode == 200 && strings.Contains(resp.Body, "rd."+marker) {
			if strings.Contains(strings.ToLower(resp.Body), "meta http-equiv=\"refresh\"") ||
				strings.Contains(strings.ToLower(resp.Body), "window.location") ||
				strings.Contains(strings.ToLower(resp.Body), "location.href") {
				out = append(out, Finding{
					ID:       NewID("redirect", p.URL, p.Param, "client", tpl),
					Module:   "redirect",
					Title:    "Open Redirect (Client-Side)",
					Severity: SeverityLow,
					Endpoint: p.URL,
					Method:   p.Method,
					Param:    p.Param,
					Payload:  payload,
					Evidence: Snippet(resp.Body, "rd."+marker, 100),
					PoCURL:   PoCGet(p, payload),
					Description: "The reflected URL is wired into a client-side redirect primitive (meta refresh / JS), " +
						"allowing attacker-controlled navigation from a trusted origin.",
					Remediation: "Do not build redirect targets from raw user input client-side.",
				})
				return out
			}
		}
	}
	return out
}

// redirectsOut reports whether a Location header leaves the target origin
// toward the marker host.
func redirectsOut(loc, markerHost string) bool {
	u, err := url.Parse(loc)
	if err != nil {
		return false
	}
	return strings.HasSuffix(u.Host, markerHost)
}
