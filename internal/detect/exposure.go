package detect

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// secretCategory describes how dangerous a leaked credential pattern is.
// severityBase is the ceiling: the exposure module downgrades it whenever the
// token is demonstrably public by design and cannot be verified otherwise.
type secretCategory struct {
	name         string
	re           *regexp.Regexp
	severityBase Severity
	// redact controls whether the matched value is trimmed in the report.
	redact bool
}

// secretCategories lists credential patterns worth hunting, ordered from
// most to least dangerous. Unauthenticated JavaScript SDK keys, analytics
// identifiers and captcha site keys are intentionally absent: those are
// public by design and their presence proves nothing.
var secretCategories = []secretCategory{
	{"AWS Access Key ID", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), SeverityCritical, true},
	{"AWS Secret Access Key", regexp.MustCompile(`(?i)aws(.{0,12})?(secret|private)(.{0,8})?[:=]\s*['"]?[A-Za-z0-9/+=]{40}['"]?`), SeverityCritical, true},
	{"Private Key Block", regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY( BLOCK)?-----`), SeverityCritical, true},
	{"GitHub Token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,255}`), SeverityCritical, true},
	{"Stripe Live Secret Key", regexp.MustCompile(`sk_live_[A-Za-z0-9]{20,}`), SeverityCritical, true},
	{"Slack Bot Token", regexp.MustCompile(`xoxb-[0-9A-Za-z-]{10,}`), SeverityCritical, true},
	{"JWT", regexp.MustCompile(`eyJ[A-Za-z0-9_=-]{10,}\.[A-Za-z0-9_=-]{10,}\.[A-Za-z0-9_.+/=-]{10,}`), SeverityHigh, true},
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`), SeverityHigh, true},
	{"Mailgun API Key", regexp.MustCompile(`key-[0-9A-Za-z]{32}`), SeverityHigh, true},
	{"Twilio API Key", regexp.MustCompile(`SK[0-9a-fA-F]{32}`), SeverityMedium, true},
	{"Generic api_key/secret Assignment", regexp.MustCompile(`(?i)(api[_-]?key|secret[_-]?key|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['"][A-Za-z0-9_\-\.]{24,}['"]`), SeverityHigh, true},
	{"Bearer Token Literal", regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-_.~+/]{24,}={0,2}`), SeverityMedium, true},
	{"Hardcoded Password Assignment", regexp.MustCompile(`(?i)(password|passwd|db[_-]?pass)\s*[:=]\s*['"][^'"\s]{8,}['"]`), SeverityHigh, true},
	{"Connection String with Credentials", regexp.MustCompile(`(?i)(mongodb|postgres(ql)?|mysql|redis|amqp)://[^\s:@]+:[^\s@]+@[^\s"']{4,}`), SeverityCritical, true},
}

// publicByDesign are assignment names that are part of client-side SDK
// configuration. They are sent to every visitor's browser on purpose, so
// their exposure is informational, not a vulnerability.
var publicByDesign = []string{
	"websitetoken", "sitekey", "site_key", "publickey", "public_key",
	"publishable", "pk_live", "pk_test", "clientid", "client_id",
	"apikey_pub", "appkey", "app_key", "trackingid", "analyticsid",
	"recaptcha_site", "hcaptcha_site", "turnstile_site",
}

// privilegedSignals marks body regions that suggest the token gates real
// access: server-side config dumps, auth headers, internal API responses.
var privilegedSignals = []string{
	"authorization:", "x-api-key:", "set-cookie:",
	"\"role\"", "\"isadmin\"", "\"admin\"", "\"scope\"", "\"permissions\"",
	"private", "secret", "internal",
}

// verifyStatus classifies a secret finding before it is reported.
type verifyStatus int

const (
	// verifyPublic means the value is emitted by client SDK config and is
	// therefore public by design.
	verifyPublic verifyStatus = iota
	// verifyUnverified means the token pattern is sensitive-looking but the
	// scanner could not demonstrate any use of it.
	verifyUnverified
	// verifyConfirmed means a probe used the token and the server accepted it.
	verifyConfirmed
)

// Exposure detects leaked secrets, exposed sensitive files and verbose
// debug output, with impact verification before severity assignment.
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
	if f := exposureSecrets(ctx, s, p, resp); f != nil {
		out = append(out, *f)
	}
	out = append(out, exposureDebug(p, resp)...)
	if p.URL == s.Target.String() {
		out = append(out, exposureFilesScan(ctx, s)...)
	}
	return out
}

// exposureSecrets hunts credential patterns in one response and applies the
// verification model: confirmed > unverified > public-by-design.
func exposureSecrets(ctx context.Context, s *Scanner, p Point, resp *Resp) *Finding {
	for _, cat := range secretCategories {
		loc := cat.re.FindStringIndex(resp.Body)
		if loc == nil {
			continue
		}
		matched := resp.Body[loc[0]:loc[1]]

		// Assignment-style matches: check whether the KEY is public-by-design
		// (e.g. websiteToken in a JS SDK config).
		status, label := classifySecret(matched)
		if status == verifyPublic {
			return &Finding{
				ID:       NewID("exposure", p.URL, "public-config", cat.name),
				Module:   "exposure",
				Title:    "Public Client-Side Configuration Value (" + label + ")",
				Severity: SeverityInfo,
				Endpoint: p.URL,
				Method:   "GET",
				Payload:  cat.name,
				Evidence: redact(matched, cat.redact) + " — emitted as client SDK configuration; public by design",
				PoCCurl:  "curl -sk '" + p.URL + "'",
				Description: "The value matches the " + cat.name + " pattern but appears under a name that is " +
					"exposed to every visitor by design (client-side SDK / site key). No privilege is implied.",
				Remediation: "No action required. Ensure the corresponding private/secret counterpart is never shipped client-side.",
			}
		}
		return buildSecretFinding(ctx, s, p, cat, matched)
	}
	return nil
}

// classifySecret inspects the matched string (and, for assignment-style
// matches, its key name) to decide the verification status.
func classifySecret(matched string) (verifyStatus, string) {
	lower := strings.ToLower(matched)
	for _, pub := range publicByDesign {
		if strings.Contains(lower, pub) {
			return verifyPublic, pub
		}
	}
	return verifyUnverified, ""
}

// buildSecretFinding probes whether the token actually gates access before
// choosing a severity. Unverified high-pattern secrets are reported as
// "Potential" with severity capped at medium.
func buildSecretFinding(ctx context.Context, s *Scanner, p Point, cat secretCategory, matched string) *Finding {
	title := cat.name + " Exposure"
	desc := "A value matching the " + cat.name + " pattern is present in the response body. " +
		"Confirm whether it is live and rotate it if so."
	remed := "Remove the secret from client-visible responses and rotate it."

	sev := cat.severityBase
	verified := verifySecretUse(ctx, s, matched)
	switch {
	case verified:
		title = cat.name + " Exposure (verified accepted by server)"
		desc = "The token was replayed against " + s.Target.String() + " and the server accepted it, " +
			"demonstrating live privileged access. This is exploitation-verified, not pattern-matched."
		remed = "Rotate the credential immediately and audit its usage history."
	case cat.severityBase.Rank() >= SeverityHigh.Rank():
		// Sensitive pattern, but zero proof of impact: downgrade + label.
		title = "Potential " + cat.name + " (unverified)"
		sev = SeverityMedium
		desc = "A value matching the " + cat.name + " pattern appears in the response. VEXOR could not " +
			"demonstrate that the token is live or privileged — verify manually before reporting."
	default:
		title = "Potential " + cat.name + " (unverified)"
	}

	return &Finding{
		ID:          NewID("exposure", p.URL, "secret", cat.name),
		Module:      "exposure",
		Title:       title,
		Severity:    sev,
		Endpoint:    p.URL,
		Method:      "GET",
		Payload:     cat.name,
		Evidence:    redact(matched, cat.redact),
		PoCCurl:     secretPoCCurl(ctx, s, matched, verified),
		Description: desc,
		Remediation: remed,
	}
}

// verifySecretUse replays the token where a server would judge it. A token
// is only "verified" when a gated endpoint answers 2xx/403-with-different-
// body compared to an anonymous request. Probes are read-only GETs.
func verifySecretUse(ctx context.Context, s *Scanner, token string) bool {
	if len(token) < 16 {
		return false
	}
	hdr := map[string]string{"Authorization": "Bearer " + token}
	base, err := s.C.Do(ctx, "GET", s.Target.String(), nil, false, nil)
	if err != nil {
		return false
	}
	with, err := s.C.Do(ctx, "GET", s.Target.String(), nil, false, hdr)
	if err != nil {
		return false
	}
	// Same status AND similar body => the server ignored the token entirely.
	if with.StatusCode == base.StatusCode && Similarity(base.Body, with.Body) > 0.97 {
		return false
	}
	return privilegedSignalsPresent(with)
}

// privilegedSignalsPresent reports whether a response shows the token
// unlocked something private.
func privilegedSignalsPresent(resp *Resp) bool {
	if resp.StatusCode >= 500 {
		return false
	}
	body := strings.ToLower(resp.Body)
	for _, sig := range privilegedSignals {
		if strings.Contains(body, sig) {
			return true
		}
	}
	return false
}

// secretPoCCurl returns a reproduction that demonstrates impact, not just
// presence: for verified tokens the replay request itself; for unverified
// ones the plain read command.
func secretPoCCurl(ctx context.Context, s *Scanner, token string, verified bool) string {
	if verified {
		return "curl -sk -H 'Authorization: Bearer " + token + "' '" + s.Target.String() + "'"
	}
	return ""
}

// redact shortens a credential for report safety.
func redact(v string, do bool) string {
	if !do || len(v) <= 12 {
		return v
	}
	return v[:8] + strings.Repeat("*", 6) + v[len(v)-4:]
}

// assignmentRe matches KEY=value or "KEY": "value" pairs for evidence masking.
var assignmentRe = regexp.MustCompile(`[A-Za-z0-9_.-]{3,40}(\s*[:=]\s*)("[^"]{8,}"|'[^']{8,}'|[A-Za-z0-9/+=_.-]{8,})`)

// maskAssignments hides the values of KEY=value pairs (and "key": "value"
// JSON pairs) in evidence snippets, while keeping the key names visible.
func maskAssignments(s string) string {
	repl := func(m string) string {
		sep := strings.IndexAny(m, "=:")
		if sep < 0 {
			return m
		}
		val := strings.Trim(m[sep+1:], " \"',")
		if val == "" {
			return m
		}
		return m[:sep+1] + " " + redact(val, true)
	}
	return assignmentRe.ReplaceAllStringFunc(s, repl)
}

// exposureFiles map well-known sensitive files to severity and fingerprint.
// robots.txt is deliberately absent: it is a public routing directive and
// its presence is never a finding.
var exposureFiles = []struct {
	path      string
	mustMatch *regexp.Regexp
	title     string
	sev       Severity
}{
	{"/.env", regexp.MustCompile(`(?i)^(APP_KEY|DB_PASSWORD|AWS_SECRET|API_KEY|SECRET)\w*=.{4,}`), "Exposed .env File", SeverityCritical},
	{"/.git/HEAD", regexp.MustCompile(`ref:\s*refs/`), "Exposed .git Repository", SeverityCritical},
	{"/phpinfo.php", regexp.MustCompile(`(?i)phpinfo\(\)|PHP Version`), "Exposed phpinfo()", SeverityMedium},
	{"/server-status", regexp.MustCompile(`(?i)Apache Server Status|Server uptime`), "Exposed Apache server-status", SeverityMedium},
	{"/actuator", regexp.MustCompile(`(?i)(_links|health|beans|env)`), "Exposed Spring Boot Actuator", SeverityHigh},
	{"/swagger.json", regexp.MustCompile(`(?i)("swagger"|"openapi")`), "Exposed Swagger/OpenAPI Spec", SeverityMedium},
	{"/debug", regexp.MustCompile(`(?i)(debug|stack trace|traceback)`), "Debug Endpoint Exposed", SeverityLow},
	{"/backup.zip", regexp.MustCompile(`PK\x03\x04`), "Backup Archive Exposed", SeverityCritical},
	{"/.svn/entries", regexp.MustCompile(`(?m)^\d+\s*$`), "Exposed SVN Metadata", SeverityHigh},
	{"/.DS_Store", regexp.MustCompile(`\x00\x00\x00\x01Bud1`), "Exposed .DS_Store", SeverityLow},
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
			Description: "Detailed error output leaks internal paths, versions or source fragments, " +
				"helping attackers map the stack before exploitation.",
			Remediation: "Return generic errors to clients; log details server-side.",
		}}
	}
	return nil
}

// exposureFilesScan probes well-known sensitive files from the target root.
// robots.txt is exempt: it is a public directive file by definition.
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
			Evidence: maskAssignments(Snippet(resp.Body, m, 100)),
			PoCCurl:  fmt.Sprintf("curl -sk '%s%s'", root, f.path),
			Description: "A sensitive file is publicly reachable at " + f.path +
				", disclosing configuration, source control data or server internals. " +
				"Credential values inside are redacted here; verify them manually.",
			Remediation: "Block access to dotfiles and metadata endpoints at the web server or CDN layer.",
		})
	}
	return out
}

// exposureDebugSignatures match framework/stack traces.
var exposureDebugSignatures = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(traceback \(most recent call last\))`),
	regexp.MustCompile(`(?i)(fatal error|uncaught exception|warning:|notice:).*on line \d+`),
	regexp.MustCompile(`(?i)(at [\w.$]+\([\w]+\.java:\d+\))`),
	regexp.MustCompile(`(?i)(django debug page|exception value|request method:\s*\w+)`),
	regexp.MustCompile(`(?i)(system\.nullreferenceexception|stack trace:)`),
}
