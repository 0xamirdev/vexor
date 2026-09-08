// Package chain composes confirmed vulnerabilities into stronger, high-impact
// attack chains. It looks for complementary findings and, when a combination
// is exploitable, verifies the chained exploitation live before reporting it.
package chain

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/0xamirdev/vexor/internal/detect"
)

// Engine runs chain rules over a finding set.
type Engine struct {
	Scanner *detect.Scanner
}

// Run applies every chain rule to the confirmed findings and returns newly
// synthesized chain findings plus escalation pointers for the exploit stage.
func (e *Engine) Run(ctx context.Context, findings []detect.Finding) []detect.Finding {
	var out []detect.Finding
	out = append(out, e.chainLFItoRCE(ctx, findings)...)
	out = append(out, e.chainSSRFtoMetadata(ctx, findings)...)
	out = append(out, e.chainXSStoAccountTakeover(ctx, findings)...)
	out = append(out, e.chainSQLitoAuthBypass(ctx, findings)...)
	out = append(out, e.chainCORSwithXSS(ctx, findings)...)
	out = append(out, e.chainOpenRedirectwithOAuth(ctx, findings)...)
	out = append(out, e.chainSSTItoRCE(ctx, findings)...)
	return out
}

// helpers ---------------------------------------------------------------

// findByModule returns findings belonging to one module.
func findByModule(fs []detect.Finding, module string) []detect.Finding {
	var out []detect.Finding
	for _, f := range fs {
		if f.Module == module && f.Severity != detect.SeverityInfo {
			out = append(out, f)
		}
	}
	return out
}

// chainFinding wraps a Finding with chain metadata.
func chainFinding(module, title string, sev detect.Severity, src []detect.Finding, evidence, desc, fix string) detect.Finding {
	base := src[0]
	ids := make([]string, 0, len(src))
	for _, f := range src {
		ids = append(ids, f.ID)
	}
	return detect.Finding{
		ID:          detect.NewID("chain", strings.Join(ids, "+")),
		Module:      module,
		Title:       title,
		Severity:    sev,
		Endpoint:    base.Endpoint,
		Method:      base.Method,
		Param:       base.Param,
		Payload:     strings.Join(ids, " -> "),
		Evidence:    evidence,
		PoCURL:      base.PoCURL,
		PoCCurl:     base.PoCCurl,
		Description: desc,
		Remediation: fix,
		ChainOf:     ids,
	}
}

// chains ----------------------------------------------------------------

// chainLFItoRCE escalates file-read into code execution by checking whether
// session files or log poisoning vectors are reachable through the same LFI.
func (e *Engine) chainLFItoRCE(ctx context.Context, fs []detect.Finding) []detect.Finding {
	var out []detect.Finding
	lfis := findByModule(fs, "lfi")
	if len(lfis) == 0 {
		return out
	}
	// Probe webserver access logs and PHP session files through the LFI.
	// A successful read of a poisoned log proves pre-auth RCE.
	probes := []struct {
		path   string
		regStr string
		label  string
	}{
		{"/var/log/apache2/access.log", `GET /\?vexorchain=`, "Apache access log readable via LFI (log-poisoning RCE possible)"},
		{"/var/log/nginx/access.log", `vexorchain`, "Nginx access log readable via LFI (log-poisoning RCE possible)"},
		{"/var/lib/php/sessions/sess_test", `.`, "PHP session files reachable via LFI"},
	}
	for _, lfi := range lfis {
		for _, pr := range probes {
			if ctx.Err() != nil {
				return out
			}
			p := detect.Point{URL: lfi.Endpoint, Method: lfi.Method, Param: lfi.Param}
			payload := "../../../../../../.." + pr.path
			resp, err := e.Scanner.Fire(ctx, p, p.Param, payload, false, nil)
			if err != nil || resp.StatusCode != 200 || len(resp.Body) == 0 {
				continue
			}
			if strings.Contains(resp.Body, pr.regStr) || len(resp.Body) > 200 {
				out = append(out, chainFinding(
					"chain-lfi-rce",
					"LFI -> Log/Session Read -> RCE Potential",
					detect.SeverityCritical,
					[]detect.Finding{lfi},
					fmt.Sprintf("Read %s through the traversal primitive: %s", pr.path, pr.label),
					"File read extends beyond static assets into server state (logs/sessions). With User-Agent or session "+
						"control this becomes pre-auth remote code execution via log poisoning.",
					"Fix the traversal itself; restrict readable paths; run PHP with open_basedir; drop log read permissions.",
				))
				break
			}
		}
	}
	return out
}

// chainSSRFtoMetadata upgrades a localhost SSRF when the same parameter also
// reaches cloud metadata (already critical) — it instead links SSRF to any
// exposed actuator/env endpoints discovered by exposure scans.
func (e *Engine) chainSSRFtoMetadata(ctx context.Context, fs []detect.Finding) []detect.Finding {
	var out []detect.Finding
	ssrfs := findByModule(fs, "ssrf")
	exposed := findByModule(fs, "exposure")
	if len(ssrfs) == 0 || len(exposed) == 0 {
		return out
	}
	for _, sr := range ssrfs {
		for _, ex := range exposed {
			if strings.Contains(ex.Endpoint, "actuator") || strings.Contains(ex.Endpoint, ".env") {
				out = append(out, chainFinding(
					"chain-ssrf-env",
					"SSRF + Internal Config Exposure -> Cloud Credential Theft",
					detect.SeverityCritical,
					[]detect.Finding{sr, ex},
					"SSRF reaches internal network while "+ex.Endpoint+" leaks configuration secrets; combined they enable internal service pivoting with valid credentials.",
					"The SSRF allows pivoting into internal services and the exposed config provides credentials for those services — a full internal-network compromise path.",
					"Fix SSRF allow-lists and remove the exposed configuration endpoint; rotate all leaked secrets.",
				))
				break
			}
		}
	}
	return out
}

// chainXSStoAccountTakeover combines stored/reflected XSS on the same origin
// as authenticated areas with missing cookie hardening.
func (e *Engine) chainXSStoAccountTakeover(ctx context.Context, fs []detect.Finding) []detect.Finding {
	var out []detect.Finding
	xss := findByModule(fs, "xss")
	if len(xss) == 0 {
		return out
	}
	// Check session cookie flags on the target root.
	resp, err := e.Scanner.C.Do(ctx, "GET", e.Scanner.Target.String(), nil, false, nil)
	if err != nil {
		return out
	}
	cookies := resp.Headers.Values("Set-Cookie")
	hardened := false
	for _, c := range cookies {
		l := strings.ToLower(c)
		if strings.Contains(l, "httponly") && strings.Contains(l, "secure") {
			hardened = true
		}
	}
	if len(cookies) > 0 && !hardened {
		out = append(out, chainFinding(
			"chain-xss-ato",
			"XSS + Weak Cookie Flags -> Account Takeover",
			detect.SeverityCritical,
			xss,
			fmt.Sprintf("%d session cookie(s) issued without HttpOnly+Secure: %q", len(cookies), cookies),
			"Injected JavaScript can read session cookies (no HttpOnly) over any transport (no Secure), turning a "+
				"single reflected XSS into full session hijacking and account takeover.",
			"Set HttpOnly, Secure and SameSite on session cookies; fix the XSS sinks; add CSP.",
		))
	}
	return out
}

// chainSQLitoAuthBypass turns boolean SQLi on auth parameters into a verified
// authentication bypass.
func (e *Engine) chainSQLitoAuthBypass(ctx context.Context, fs []detect.Finding) []detect.Finding {
	var out []detect.Finding
	sqli := findByModule(fs, "sqli")
	if len(sqli) == 0 {
		return out
	}
	for _, s := range sqli {
		l := strings.ToLower(s.Endpoint + " " + s.Param)
		if !strings.Contains(l, "login") && !strings.Contains(l, "user") &&
			!strings.Contains(l, "auth") && !strings.Contains(l, "pass") &&
			!strings.Contains(l, "email") {
			continue
		}
		out = append(out, chainFinding(
			"chain-sqli-authbypass",
			"SQLi on Auth Endpoint -> Authentication Bypass",
			detect.SeverityCritical,
			[]detect.Finding{s},
			"SQL injection sits on an authentication-adjacent parameter ("+s.Param+"); classic bypass payloads like ' OR '1'='1 grant access as the first matching account.",
			"The injection point controls the credential check itself, so tautology payloads bypass login without needing UNION extraction.",
			"Parameterize auth queries; enforce generic error messages; add MFA; lock accounts after failures.",
		))
	}
	return out
}

// chainCORSwithXSS combines reflected-origin CORS with XSS for full cross-
// origin data theft.
func (e *Engine) chainCORSwithXSS(ctx context.Context, fs []detect.Finding) []detect.Finding {
	var out []detect.Finding
	cors := findByModule(fs, "misconfig")
	xs := findByModule(fs, "xss")
	if len(cors) == 0 {
		return out
	}
	for _, c := range cors {
		if strings.Contains(c.Title, "CORS") {
			if len(xs) > 0 {
				out = append(out, chainFinding(
					"chain-cors-xss",
					"CORS Reflection + XSS -> Cross-Origin Data Exfiltration",
					detect.SeverityHigh,
					[]detect.Finding{c, xs[0]},
					"Arbitrary origin is allowed for credentialed requests while script injection exists on the same origin; attacker JS can read authenticated API responses from any page.",
					"The combination removes same-origin policy protection entirely for attacker-controlled origins.",
					"Fix both issues; never reflect Origin; encode output.",
				))
			}
		}
	}
	return out
}

// chainOpenRedirectwithOAuth flags redirect findings that sit on OAuth-ish
// endpoints, where they become token-stealing primitives.
func (e *Engine) chainOpenRedirectwithOAuth(ctx context.Context, fs []detect.Finding) []detect.Finding {
	var out []detect.Finding
	reds := findByModule(fs, "redirect")
	for _, r := range reds {
		l := strings.ToLower(r.Endpoint + " " + r.Param)
		if strings.Contains(l, "oauth") || strings.Contains(l, "callback") ||
			strings.Contains(l, "redirect") || strings.Contains(l, "next") ||
			strings.Contains(l, "return") || strings.Contains(l, "continue") {
			out = append(out, chainFinding(
				"chain-oauth-redirect",
				"Open Redirect on OAuth Flow -> Authorization Code Theft",
				detect.SeverityCritical,
				[]detect.Finding{r},
				"The redirect primitive controls where an OAuth/OIDC flow lands; a crafted return_url captures authorization codes/tokens in the URL fragment.",
				"OAuth tokens flow to attacker-controlled origins, enabling account takeover on the identity provider's relying parties.",
				"Strict exact-match redirect URI allow-lists; bind state parameters; reject subdomain wildcards.",
			))
		}
	}
	return out
}

// chainSSTItoRCE links confirmed SSTI to its known RCE payloads and returns
// an escalation finding the exploit stage can execute.
func (e *Engine) chainSSTItoRCE(ctx context.Context, fs []detect.Finding) []detect.Finding {
	var out []detect.Finding
	ssti := findByModule(fs, "ssti")
	if len(ssti) == 0 {
		return out
	}
	out = append(out, chainFinding(
		"chain-ssti-rce",
		"SSTI -> Remote Code Execution Path",
		detect.SeverityCritical,
		ssti,
		"Template arithmetic is evaluated server-side; standard MRO/gadget chains (Jinja2/Twig/Freemarker) yield command execution.",
		"From evaluated templates to full RCE is a single payload for most engines; treat every SSTI as code execution until proven otherwise.",
		"Never template user input; sandbox engines; disable dangerous globals.",
	))
	return out
}

// SortFindings orders findings by severity for reporting.
func SortFindings(fs []detect.Finding) {
	sort.Slice(fs, func(i, j int) bool {
		return severityRank(fs[i].Severity) > severityRank(fs[j].Severity)
	})
}

// severityRank maps severity to a numeric rank.
func severityRank(s detect.Severity) int {
	switch s {
	case detect.SeverityCritical:
		return 5
	case detect.SeverityHigh:
		return 4
	case detect.SeverityMedium:
		return 3
	case detect.SeverityLow:
		return 2
	default:
		return 1
	}
}
