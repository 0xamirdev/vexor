// Package detect hosts every vulnerability probe module. Each module is an
// independent, concurrent-safe unit that turns one injection Point into zero
// or more evidence-backed Findings with ready-to-run PoCs.
package detect

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"vexor/internal/httpc"
)

// Resp aliases the shared HTTP response type for probe modules.
type Resp = httpc.Response

// Severity ranks findings from informational to critical.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Level selects how often a module runs: once per host, per endpoint or per
// individual injectable parameter.
type Level int

const (
	LevelHost Level = iota
	LevelEndpoint
	LevelParam
)

// Finding is a single evidence-backed vulnerability report.
type Finding struct {
	ID          string   `json:"id"`
	Module      string   `json:"module"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Endpoint    string   `json:"endpoint"`
	Method      string   `json:"method"`
	Param       string   `json:"param,omitempty"`
	Payload     string   `json:"payload,omitempty"`
	Evidence    string   `json:"evidence"`
	PoCURL      string   `json:"poc_url,omitempty"`
	PoCCurl     string   `json:"poc_curl,omitempty"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
	ChainOf     []string `json:"chain_of,omitempty"`
}

// Point is one injectable surface: a URL/method pair plus the original
// parameter values. Param is empty for host- and endpoint-level probes.
type Point struct {
	URL    string
	Method string
	Values url.Values
	Param  string
}

// Scanner carries shared state every module needs: the HTTP client, the
// target base URL and the marker domain used for redirect/CORS probes.
type Scanner struct {
	C            *httpc.Client
	Target       *url.URL
	MarkerDomain string
}

// Module is the contract every vulnerability probe implements.
type Module interface {
	Name() string
	Level() Level
	Scan(ctx context.Context, s *Scanner, p Point) []Finding
}

// Fire sends one probe for a Point, substituting param with payload while
// keeping every other original parameter intact. For GET the values become
// the query string; for POST they become the form body.
func (s *Scanner) Fire(ctx context.Context, p Point, param, payload string, follow bool, extra map[string]string) (*httpc.Response, error) {
	vals := url.Values{}
	for k, vs := range p.Values {
		for _, v := range vs {
			vals.Add(k, v)
		}
	}
	if param != "" {
		vals.Set(param, payload)
	}
	if p.Method == "GET" || p.Method == "" {
		base := p.URL
		if i := strings.IndexByte(base, '?'); i >= 0 {
			base = base[:i]
		}
		return s.C.Do(ctx, "GET", base+"?"+vals.Encode(), nil, follow, extra)
	}
	return s.C.Do(ctx, p.Method, p.URL, vals, follow, extra)
}

// Baseline fires the original, untouched request for a Point.
func (s *Scanner) Baseline(ctx context.Context, p Point, follow bool, extra map[string]string) (*httpc.Response, error) {
	return s.Fire(ctx, p, "", "", follow, extra)
}

// MarkedURL returns a URL on the marker domain, used as an out-of-band
// placeholder the operator should replace with a host they control.
func (s *Scanner) MarkedURL(path string) string {
	return "https://" + s.MarkerDomain + path
}

// All returns the full probe registry in execution order.
func All() []Module {
	return []Module{
		SQLi{},
		XSS{},
		CMDi{},
		SSTI{},
		LFI{},
		SSRF{},
		Redirect{},
		Misconfig{},
		Exposure{},
	}
}

// NewID derives a stable, dedup-friendly finding ID from its coordinates.
func NewID(module string, parts ...string) string {
	h := fnvNew32a()
	h.Write([]byte(module))
	for _, p := range parts {
		h.Write([]byte{0})
		h.Write([]byte(p))
	}
	return fmt.Sprintf("VXR-%08X", h.Sum32())
}

// Snippet extracts up to limit bytes of context around a match inside body.
func Snippet(body, match string, limit int) string {
	idx := strings.Index(body, match)
	if idx < 0 {
		return match
	}
	start := idx - limit/2
	if start < 0 {
		start = 0
	}
	end := idx + len(match) + limit/2
	if end > len(body) {
		end = len(body)
	}
	return strings.TrimSpace(body[start:end])
}

// Similarity scores two bodies by 4-gram Jaccard overlap (0..1). It ignores
// volatile content so boolean-based SQLi diffs stay usable.
func Similarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	if len(a) < 4 || len(b) < 4 {
		return 0.0
	}
	ga := grams(a)
	gb := grams(b)
	inter := 0
	for g := range ga {
		if gb[g] {
			inter++
		}
	}
	return float64(inter) / float64(len(ga)+len(gb)-inter)
}

func grams(s string) map[string]bool {
	out := make(map[string]bool, len(s)/4+1)
	for i := 0; i+4 <= len(s); i++ {
		out[s[i:i+4]] = true
	}
	return out
}

// findMatch is a helper that returns the first regex hit, if any.
func findMatch(re *regexp.Regexp, body string) string {
	if m := re.FindString(body); m != "" {
		return m
	}
	return ""
}
