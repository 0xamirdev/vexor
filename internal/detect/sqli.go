package detect

import (
	"context"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// errorSignatures maps DBMS error fingerprints to the database engine.
var errorSignatures = []struct {
	re *regexp.Regexp
	db string
}{
	{regexp.MustCompile(`(?i)you have an error in your sql syntax[^"]*near`), "MySQL"},
	{regexp.MustCompile(`(?i)warning:\s*mysql`), "MySQL"},
	{regexp.MustCompile(`(?i)unclosed quotation mark after the character`), "MSSQL"},
	{regexp.MustCompile(`(?i)microsoft sql server.*error|sql server native client`), "MSSQL"},
	{regexp.MustCompile(`(?i)unterminated quoted string at or near`), "PostgreSQL"},
	{regexp.MustCompile(`(?i)pg_query\(\)|pg_exec\(\)`), "PostgreSQL"},
	{regexp.MustCompile(`(?i)ORA-\d{5}`), "Oracle"},
	{regexp.MustCompile(`(?i)sqlite_query\(\)|SQLite3::|SQLSTATE HY000`), "SQLite"},
}

// payloadSets holds contextual payloads: signature probes (fast, error-based)
// and union probes (numeric columns attempts).
var (
	// sqlErrorProbes break out of the quote context to trigger a DB error.
	sqlErrorProbes = []string{
		`'`,
		`"`,
		`')`,
		`'))`,
		`1' ORDER BY 100-- -`,
		`1' UNION SELECT NULL-- -`,
	}
	// sqlBooleanProbes compare a true and a false expression for the same page.
	sqlBooleanProbes = []struct{ True, False string }{
		{`' AND '1'='1`, `' AND '1'='2`},
		{` AND 1=1`, ` AND 1=2`},
		{` AND 2>1`, ` AND 2>1 AND 2<1`},
	}
	// unionColumnCounts tries UNION SELECT with NULL counts 3..8.
	unionColumnCounts = []int{3, 4, 5, 6, 7, 8}
)

// SQLi detects SQL injection via three techniques in one module:
// error-based fingerprints, boolean-based differential and UNION column count.
type SQLi struct{}

// Name implements Module.
func (SQLi) Name() string { return "sqli" }

// Level implements Module.
func (SQLi) Level() Level { return LevelParam }

// Scan implements Module.
func (SQLi) Scan(ctx context.Context, s *Scanner, p Point) []Finding {
	mod := SQLi{}
	var out []Finding
	if f := mod.sqlErrorProbe(ctx, s, p); f != nil {
		out = append(out, *f)
	}
	if len(out) == 0 {
		if f := mod.sqlBooleanProbe(ctx, s, p); f != nil {
			out = append(out, *f)
		}
	}
	if f := mod.sqlUnionProbe(ctx, s, p); f != nil {
		out = append(out, *f)
	}
	return out
}

// sqlErrorProbe injects break-out characters and matches DBMS error strings.
func (SQLi) sqlErrorProbe(ctx context.Context, s *Scanner, p Point) *Finding {
	base, err := s.Baseline(ctx, p, false, nil)
	if err != nil {
		return nil
	}
	for _, payload := range sqlErrorProbes {
		if ctx.Err() != nil {
			return nil
		}
		resp, err := s.Fire(ctx, p, p.Param, payload, false, nil)
		if err != nil {
			continue
		}
		for _, sig := range errorSignatures {
			if m := sig.re.FindString(resp.Body); m != "" && !strings.Contains(base.Body, m) {
				return &Finding{
					ID:       NewID("sqli", p.URL, p.Param, "error", sig.db),
					Module:   "sqli",
					Title:    "SQL Injection (Error-Based) - " + sig.db,
					Severity: SeverityCritical,
					Endpoint: p.URL,
					Method:   p.Method,
					Param:    p.Param,
					Payload:  payload,
					Evidence: Snippet(resp.Body, m, 120),
					PoCURL:   PoCGet(p, payload),
					PoCCurl:  CurlFor(p, payload),
					Description: "The parameter reflects a database error fingerprint (" + sig.db +
						") when a quote-breaking payload is injected, proving unsanitized SQL concatenation.",
					Remediation: "Use parameterized queries / prepared statements; never concatenate user input into SQL.",
				}
			}
		}
	}
	return nil
}

// sqlBooleanProbe compares page similarity for TRUE vs FALSE payloads.
func (SQLi) sqlBooleanProbe(ctx context.Context, s *Scanner, p Point) *Finding {
	base, err := s.Baseline(ctx, p, false, nil)
	if err != nil {
		return nil
	}
	for _, pair := range sqlBooleanProbes {
		if ctx.Err() != nil {
			return nil
		}
		t, err1 := s.Fire(ctx, p, p.Param, pair.True, false, nil)
		f, err2 := s.Fire(ctx, p, p.Param, pair.False, false, nil)
		if err1 != nil || err2 != nil {
			continue
		}
		simTF := Similarity(t.Body, f.Body)
		simBT := Similarity(base.Body, t.Body)
		simBF := Similarity(base.Body, f.Body)
		// True condition stays close to baseline, false diverges strongly.
		if simTF < 0.90 && simBT > 0.94 && simBF < 0.90 {
			return &Finding{
				ID:       NewID("sqli", p.URL, p.Param, "boolean", pair.True),
				Module:   "sqli",
				Title:    "SQL Injection (Boolean-Based Blind)",
				Severity: SeverityCritical,
				Endpoint: p.URL,
				Method:   p.Method,
				Param:    p.Param,
				Payload:  pair.True + "  /  " + pair.False,
				Evidence: sprintf("TRUE/FALSE responses diverge: sim(true,false)=%.2f sim(base,true)=%.2f sim(base,false)=%.2f",
					simTF, simBT, simBF),
				PoCCurl: CurlFor(p, pair.True),
				Description: "The application returns meaningfully different responses for a tautology versus an " +
					"impossible condition, allowing data extraction one bit at a time.",
				Remediation: "Use parameterized queries; return consistent error pages; avoid verbose DB errors.",
			}
		}
	}
	return nil
}

// sqlUnionProbe walks UNION SELECT NULL counts and detects a stable hit by
// comparing against the baseline and a broken variant.
func (SQLi) sqlUnionProbe(ctx context.Context, s *Scanner, p Point) *Finding {
	if !isNumericParam(p) {
		return nil
	}
	base, err := s.Baseline(ctx, p, false, nil)
	if err != nil {
		return nil
	}
	for _, n := range unionColumnCounts {
		if ctx.Err() != nil {
			return nil
		}
		cols := make([]string, n)
		for i := range cols {
			cols[i] = "NULL"
		}
		payload := "-1 UNION SELECT " + strings.Join(cols, ",") + "-- -"
		resp, err := s.Fire(ctx, p, p.Param, payload, false, nil)
		if err != nil {
			continue
		}
		sim := Similarity(base.Body, resp.Body)
		if sim < 0.85 && (strings.Contains(resp.Body, "grepable") || resp.StatusCode == 200) &&
			!strings.Contains(strings.ToLower(resp.Body), "error") {
			return &Finding{
				ID:       NewID("sqli", p.URL, p.Param, "union", strconv.Itoa(n)),
				Module:   "sqli",
				Title:    "SQL Injection (UNION) - " + strconv.Itoa(n) + " columns",
				Severity: SeverityCritical,
				Endpoint: p.URL,
				Method:   p.Method,
				Param:    p.Param,
				Payload:  payload,
				Evidence: "UNION with " + strconv.Itoa(n) + " NULL columns rendered (similarity to baseline: " +
					strconv.FormatFloat(sim, 'f', 2, 64) + ")",
				PoCCurl: CurlFor(p, payload),
				Description: "A UNION SELECT with " + strconv.Itoa(n) + " columns executed, proving attacker-controlled " +
					"query structure and full read access to other tables.",
				Remediation: "Parameterize queries; validate numeric inputs; apply least-privilege DB accounts.",
			}
		}
	}
	return nil
}

// isNumericParam reports whether the original value looks like an integer id.
func isNumericParam(p Point) bool {
	v := p.Values.Get(p.Param)
	if v == "" {
		return false
	}
	_, err := strconv.Atoi(v)
	return err == nil
}

// PoCGet renders a full GET URL for a payload (empty for POST points).
func PoCGet(p Point, payload string) string {
	if p.Method != "GET" && p.Method != "" {
		return ""
	}
	base := p.URL
	if i := strings.IndexByte(base, '?'); i >= 0 {
		base = base[:i]
	}
	vals := url.Values{}
	for k, vs := range p.Values {
		for _, v := range vs {
			vals.Add(k, v)
		}
	}
	if p.Param != "" {
		vals.Set(p.Param, payload)
	}
	return base + "?" + vals.Encode()
}

// CurlFor renders a curl reproduction for any method, injecting payload into
// the query string (GET) or the form body (POST).
func CurlFor(p Point, payload string) string {
	method := p.Method
	if method == "" {
		method = "GET"
	}
	vals := pointValuesWith(p, payload)
	if method == "GET" {
		base := p.URL
		if i := strings.IndexByte(base, '?'); i >= 0 {
			base = base[:i]
		}
		return httpcCurl("GET", base+"?"+vals.Encode(), nil)
	}
	return httpcCurl(method, p.URL, vals)
}
