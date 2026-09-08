package detect

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// exposureSecretRes match high-value credentials leaked in responses.
var exposureSecretRes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*(A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`(?i)private\s+key\s*-----BEGIN`),
	regexp.MustCompile(`-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*['"][A-Za-z0-9_\-]{20,}['"]`),
	regexp.MustCompile(`(?i)(secret|token|password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]`),
	regexp.MustCompile(`(?i)bearer\s+[a-z0-9\-_.~+/]+=*`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_=-]{10,}\.[A-Za-z0-9_=-]{10,}\.[A-Za-z0-9_.+/=-]{10,}`), // JWT
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`),                                          // GitHub tokens
	regexp.MustCompile(`sk_live_[A-Za-z0-9]{20,}`),                                            // Stripe
}

// exposureFiles map well-known sensitive files to severity and fingerprint.
var exposureFiles = []struct {
	path      string
	mustMatch *regexp.Regexp
	title     string
	sev       Severity
}{
	{"/.env", regexp.MustCompile(`(?i)^(APP_KEY|DB_PASSWORD|AWS_SECRET|API_KEY|SECRET)\w*=.{4,}`), "Exposed .env File", SeverityCritical},
	{"/.git/HEAD", regexp.MustCompile(`ref:\s*refs/`), "Exposed .git Repository", SeverityCritical},
	{"/robots.txt", regexp.MustCompile(`(?i)(disallow|allow|sitemap):`), "robots.txt (informational)", SeverityInfo},
	{"/phpinfo.php", regexp.MustCompile(`(?i)phpinfo\(\)|PHP Version`), "Exposed phpinfo()", SeverityMedium},
	{"/server-status", regexp.MustCompile(`(?i)Apache Server Status|Server uptime`), "Exposed Apache server-status", SeverityMedium},
	{"/actuator", regexp.MustCompile(`(?i)(_links|health|beans|env)`), "Exposed Spring Boot Actuator", SeverityHigh},
	{"/swagger.json", regexp.MustCompile(`(?i)("swagger"|"openapi")`), "Exposed Swagger/OpenAPI Spec", SeverityMedium},
	{"/debug", regexp.MustCompile(`(?i)(debug|stack trace|traceback)`), "Debug Endpoint Exposed", SeverityLow},
	{"/backup.zip", regexp.MustCompile(`PK\x03\x04`), "Backup Archive Exposed", SeverityCritical},
}

// exposureDebugSignatures match framework/stack traces.
var exposureDebugSignatures = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(traceback \(most recent call last\))`),
	regexp.MustCompile(`(?i)(fatal error|uncaught exception|warning:|notice:).*on line \d+`),
	regexp.MustCompile(`(?i)(at [\w.$]+\([\w]+\.java:\d+\))`),
	regexp.MustCompile(`(?i)(django debug page|exception value|request method:\s*\w+)`),
	regexp.MustCompile(`(?i)(system\.nullreferenceexception|stack trace:)`),
}

// Exposure detects leaked secrets, exposed sensitive files and verbose
// debug output. It runs at both endpoint and host level.
type Exposure struct{}

// Name implements Module.
func (Exposure) Name() string { return "exposure" }

// Level implements Module.
func (Exposure) Level() Level { return LevelEndpoint }

// Scan implements Module.
func (Exposure) Scan(ctx context.Context, s *Scanner, p Point) []Finding {
	var out []Finding
	resp, err := s.C.Do(ctx, "GET", p.URL, nil, false, nil)
	if err != nil {
		return out
	}
	out = append(out, exposureSecrets(p, resp)...)
	out = append(out, exposureDebug(p, resp)...)
	if p.URL == s.Target.String() {
		out = append(out, exposureFilesScan(ctx, s)...)
	}
	return out
}

// exposureSecrets scans a response body for credential patterns.
func exposureSecrets(p Point, resp *Resp) []Finding {
	var out []Finding
	for _, re := range exposureSecretRes {
		m := re.FindString(resp.Body)
		if m == "" {
			continue
		}
		out = append(out, Finding{
			ID:       NewID("exposure", p.URL, "secret", m),
			Module:   "exposure",
			Title:    "Potential Secret Leakage in Response",
			Severity: SeverityHigh,
			Endpoint: p.URL,
			Method:   "GET",
			Evidence: Snippet(resp.Body, m, 80),
			PoCCurl:  "curl -sk '" + p.URL + "'",
			Description: "A string matching a credential/token pattern is exposed in the response body. " +
				"Verify and report with the matched value redacted as appropriate.",
			Remediation: "Rotate the credential; strip secrets from responses and repositories.",
		})
		break // one secret finding per endpoint avoids noise
	}
	return out
}

// exposureDebug flags stack traces and verbose errors.
func exposureDebug(p Point, resp *Resp) []Finding {
	for _, re := range exposureDebugSignatures {
		m := re.FindString(resp.Body)
		if m == "" {
			continue
		}
		return []Finding{{
			ID:       NewID("exposure", p.URL, "debug"),
			Module:   "exposure",
			Title:    "Verbose Error / Stack Trace Disclosure",
			Severity: SeverityLow,
			Endpoint: p.URL,
			Method:   "GET",
			Evidence: Snippet(resp.Body, m, 150),
			PoCCurl:  "curl -sk '" + p.URL + "'",
			Description: "Detailed error output leaks internal paths, versions or source fragments, " +
				"helping attackers map the stack before exploitation.",
			Remediation: "Return generic errors to clients; log details server-side.",
		}}
	}
	return nil
}

// exposureFilesScan probes well-known sensitive files from the target root.
func exposureFilesScan(ctx context.Context, s *Scanner) []Finding {
	var out []Finding
	base := *s.Target
	base.Path = ""
	base.RawQuery = ""
	root := strings.TrimSuffix(base.String(), "/")
	for _, f := range exposureFiles {
		if ctx.Err() != nil {
			return out
		}
		resp, err := s.C.Do(ctx, "GET", root+f.path, nil, false, nil)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		m := f.mustMatch.FindString(resp.Body)
		if m == "" {
			continue
		}
		out = append(out, Finding{
			ID:       NewID("exposure", root+f.path, "file"),
			Module:   "exposure",
			Title:    f.title,
			Severity: f.sev,
			Endpoint: root + f.path,
			Method:   "GET",
			Evidence: Snippet(resp.Body, m, 100),
			PoCCurl:  fmt.Sprintf("curl -sk '%s%s'", root, f.path),
			Description: "A sensitive file is publicly reachable at " + f.path +
				", disclosing configuration, source control data or server internals.",
			Remediation: "Block access to dotfiles and metadata endpoints at the web server or CDN layer.",
		})
	}
	return out
}
