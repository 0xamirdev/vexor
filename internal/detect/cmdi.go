package detect

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Echo probes use a marker arithmetic expression whose result we look for.
const cmdEchoA = 19
const cmdEchoB = 23 // 19*23 = 437

// sleepSeconds is the time-based blind delay used for CMDi blind detection.
const sleepSeconds = 4

// cmdSyntaxes maps injection wrapper templates per shell-quote context.
var cmdSyntaxes = []struct {
	name string
	make func(expr string) string
}{
	{"append-semicolon", func(e string) string { return "; " + e }},
	{"append-pipe", func(e string) string { return "| " + e }},
	{"append-newline", func(e string) string { return "\n" + e }},
	{"substitution-backtick", func(e string) string { return "`" + e + "`" }},
	{"substitution-dollar", func(e string) string { return "$( " + e + " )" }},
	{"append-amp", func(e string) string { return "& " + e + " &" }},
	{"append-and", func(e string) string { return "&& " + e }},
	{"append-or", func(e string) string { return "|| " + e }},
}

// sleepSyntaxes are time-based payloads per syntax, echo variants reused.
var cmdSleepSyntaxes = []struct {
	name string
	make func(string) string
}{
	{"semicolon", func(s string) string { return "; sleep " + s }},
	{"pipe", func(s string) string { return "| sleep " + s }},
	{"dollar", func(s string) string { return "$( sleep " + s + " )" }},
	{"backtick", func(s string) string { return "`sleep " + s + "`" }},
}

// CMDi detects OS command injection with echo-based (arithmetic marker) and
// time-based (sleep) techniques across eight shell syntaxes.
type CMDi struct{}

// Name implements Module.
func (CMDi) Name() string { return "cmdi" }

// Level implements Module.
func (CMDi) Level() Level { return LevelParam }

// Scan implements Module.
func (CMDi) Scan(ctx context.Context, s *Scanner, p Point) []Finding {
	var out []Finding
	if f := cmdEcho(ctx, s, p); f != nil {
		out = append(out, *f)
	}
	if len(out) == 0 {
		if f := cmdBlind(ctx, s, p); f != nil {
			out = append(out, *f)
		}
	}
	return out
}

// cmdEcho injects "$(expr)" / backtick arithmetic and looks for the computed
// value echoed back in the response body.
func cmdEcho(ctx context.Context, s *Scanner, p Point) *Finding {
	expected := strconv.Itoa(cmdEchoA * cmdEchoB)
	expr := fmt.Sprintf("echo $((%d*%d))", cmdEchoA, cmdEchoB)
	for _, syn := range cmdSyntaxes {
		if ctx.Err() != nil {
			return nil
		}
		payload := syn.make(expr)
		resp, err := s.Fire(ctx, p, p.Param, payload, false, nil)
		if err != nil {
			continue
		}
		if strings.Contains(resp.Body, expected) {
			if baselineHit, _ := s.Baseline(ctx, p, false, nil); baselineHit != nil &&
				strings.Contains(baselineHit.Body, expected) {
				continue // value already present; not injection evidence
			}
			return &Finding{
				ID:       NewID("cmdi", p.URL, p.Param, "echo", syn.name),
				Module:   "cmdi",
				Title:    "OS Command Injection (Echo-Based) - " + syn.name,
				Severity: SeverityCritical,
				Endpoint: p.URL,
				Method:   p.Method,
				Param:    p.Param,
				Payload:  payload,
				Evidence: "Arithmetic marker " + expected + " computed by the shell appeared in the response",
				PoCCurl:  CurlFor(p, payload),
				Description: "The parameter value reaches a shell interpreter: the injected command substitution " +
					"executed and its output (" + expected + ") was returned to the client.",
				Remediation: "Avoid shelling out; use language-native APIs. If unavoidable, allow-list inputs and use exec arrays (no shell).",
			}
		}
	}
	return nil
}

// cmdBlind measures response delay for sleep payloads. Only a delay far above
// baseline AND close to the sleep constant is treated as evidence.
func cmdBlind(ctx context.Context, s *Scanner, p Point) *Finding {
	base, err := s.Baseline(ctx, p, false, nil)
	if err != nil {
		return nil
	}
	baseMs := base.Duration.Milliseconds()
	for _, syn := range cmdSleepSyntaxes {
		if ctx.Err() != nil {
			return nil
		}
		payload := syn.make(strconv.Itoa(sleepSeconds))
		resp, err := s.Fire(ctx, p, p.Param, payload, false, nil)
		if err != nil {
			continue
		}
		ms := resp.Duration.Milliseconds()
		if ms > int64(sleepSeconds*1000)+1500 && ms > baseMs+int64(sleepSeconds*1000)-1000 {
			return &Finding{
				ID:       NewID("cmdi", p.URL, p.Param, "blind", syn.name),
				Module:   "cmdi",
				Title:    "OS Command Injection (Time-Based Blind) - " + syn.name,
				Severity: SeverityCritical,
				Endpoint: p.URL,
				Method:   p.Method,
				Param:    p.Param,
				Payload:  payload,
				Evidence: fmt.Sprintf("Response delayed %dms vs baseline %dms with sleep(%ds) payload",
					ms, baseMs, sleepSeconds),
				PoCCurl: CurlFor(p, payload),
				Description: "Injected sleep command delayed the response by roughly the sleep duration, proving " +
					"server-side command execution even without output reflection.",
				Remediation: "Never pass user input to a shell; use exec-style APIs with argument arrays.",
			}
		}
	}
	return nil
}

// cmdErrSig matches shell error leakage (kept as supporting evidence source).
var cmdErrSig = regexp.MustCompile(`(?i)(sh:\s*\d+:|bash:|/bin/sh|command not found)`)
