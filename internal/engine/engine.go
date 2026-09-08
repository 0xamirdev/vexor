// Package engine orchestrates the VEXOR pipeline: crawl -> probe -> chain ->
// exploit -> report. It owns the worker pool and stage logging.
package engine

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/0xamirdev/vexor/internal/banner"
	"github.com/0xamirdev/vexor/internal/chain"
	"github.com/0xamirdev/vexor/internal/crawler"
	"github.com/0xamirdev/vexor/internal/detect"
	"github.com/0xamirdev/vexor/internal/exploit"
	"github.com/0xamirdev/vexor/internal/httpc"
	"github.com/0xamirdev/vexor/internal/report"
	"github.com/0xamirdev/vexor/internal/version"
)

// Config controls a full VEXOR run.
type Config struct {
	Target       string
	Threads      int
	Timeout      time.Duration
	MaxPages     int
	MarkerDomain string
	Headers      map[string]string
	OutputDir    string
}

// Run executes the full pipeline and returns the final report.
func Run(ctx context.Context, cfg Config) (*report.Report, error) {
	client := httpc.New(cfg.Timeout)
	client.UserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36 " + version.UserAgent()
	base, err := url.Parse(cfg.Target)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("target must be http(s), got scheme %q", base.Scheme)
	}
	if base.Host == "" {
		return nil, fmt.Errorf("target must include a host")
	}

	rep := &report.Report{
		Target:    cfg.Target,
		StartedAt: time.Now(),
	}

	// Stage 1: crawl --------------------------------------------------
	banner.Divider()
	fmt.Printf(" %s[1/5]%s crawling target (max %d pages)...\n", cyan(), reset(), cfg.MaxPages)
	crawl, err := crawler.Crawl(ctx, client, cfg.Target, cfg.MaxPages)
	if err != nil && ctx.Err() == nil {
		return nil, fmt.Errorf("crawl failed: %w", err)
	}
	rep.Endpoints = crawl.Stats()
	fmt.Printf("   %s%s%s\n", magenta(), rep.Endpoints, reset())

	// Build scanner shared by all probes.
	sc := &detect.Scanner{C: client, Target: base, MarkerDomain: cfg.MarkerDomain}

	// Stage 2: parameter-level probes ---------------------------------
	fmt.Printf(" %s[2/5]%s probing injection points...\n", cyan(), reset())
	findings := runParamProbes(ctx, sc, crawl, cfg, rep)

	// Stage 3: chaining -------------------------------------------------
	fmt.Printf(" %s[3/5]%s correlating & chaining vulnerabilities...\n", cyan(), reset())
	chainEng := &chain.Engine{Scanner: sc}
	chained := chainEng.Run(ctx, findings)
	rep.ChainedCount = len(chained)

	// Stage 4: exploit PoCs ---------------------------------------------
	fmt.Printf(" %s[4/5]%s generating exploit PoCs...\n", cyan(), reset())
	expSuite := &exploit.Suite{Scanner: sc}
	expResults := expSuite.Run(ctx, findings)
	rep.Exploits = make([]report.Exploit, 0, len(expResults))
	for _, r := range expResults {
		rep.Exploits = append(rep.Exploits, report.Exploit{
			FindingID: r.FindingID,
			Kind:      r.Kind,
			Proof:     r.Proof,
			Runnable:  r.Runnable,
		})
	}

	// Stage 5: report ----------------------------------------------------
	findings = append(findings, chained...)
	findings = dedupe(findings)
	findings = detect.AggregateHeaderFindings(findings)
	chain.SortFindings(findings)
	rep.FinishedAt = time.Now()
	rep.ToolVersion = version.Version
	rep.Findings = findings
	fmt.Printf(" %s[5/5]%s scan complete.\n", cyan(), reset())
	return rep, nil
}

// runParamProbes builds injection points from crawl results and fans module
// probes out over a bounded worker pool.
func runParamProbes(ctx context.Context, sc *detect.Scanner, crawl *crawler.Result, cfg Config, rep *report.Report) []detect.Finding {
	points := buildPoints(crawl)
	hosts := map[string]bool{sc.Target.Host: true}
	for ep := range crawl.Endpoints {
		if u, err := url.Parse(ep); err == nil {
			hosts[u.Host] = true
		}
	}
	rep.TotalPoints = len(points)

	modules := detect.All()
	type job struct {
		module detect.Module
		point  detect.Point
	}
	jobs := make(chan job)
	var mu sync.Mutex
	var results []detect.Finding
	var wg sync.WaitGroup

	threads := cfg.Threads
	if threads <= 0 {
		threads = 8
	}
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					continue
				}
				found := j.module.Scan(ctx, sc, j.point)
				if len(found) > 0 {
					mu.Lock()
					results = append(results, found...)
					mu.Unlock()
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		// Host- and endpoint-level modules run once per unique URL.
		paramModules := make([]detect.Module, 0, len(modules))
		for _, m := range modules {
			switch m.Level() {
			case detect.LevelHost:
				for h := range hosts {
					zero := detect.Point{URL: "http://" + h}
					jobs <- job{module: m, point: zero}
				}
			case detect.LevelEndpoint:
				for _, ep := range crawl.SortedEndpoints() {
					jobs <- job{module: m, point: detect.Point{URL: ep, Method: "GET"}}
				}
			default:
				paramModules = append(paramModules, m)
			}
		}
		for _, p := range points {
			for _, m := range paramModules {
				jobs <- job{module: m, point: p}
			}
		}
	}()
	wg.Wait()

	// Endpoint-level exposure also needs the param-attached points skipped:
	// exposure files scan lives on LevelEndpoint so the loop above covers it.
	return results
}

// buildPoints converts crawl results into injectable Points. GET endpoints
// contribute one Point per query parameter; forms contribute one Point per
// input field.
func buildPoints(crawl *crawler.Result) []detect.Point {
	seen := map[string]bool{}
	var out []detect.Point
	add := func(p detect.Point) {
		key := p.Method + "|" + p.URL + "|" + p.Param
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, p)
	}
	for ep, params := range crawl.Params {
		vals := url.Values{}
		for _, pr := range params {
			v := pr.Value
			if v == "" {
				v = "1"
			}
			vals.Set(pr.Key, v)
		}
		u, _ := url.Parse(ep)
		if u == nil {
			continue
		}
		u.RawQuery = ""
		for _, pr := range params {
			add(detect.Point{URL: u.String(), Method: "GET", Values: cloneValues(vals), Param: pr.Key})
		}
	}
	for page, forms := range crawl.Forms {
		for _, f := range forms {
			vals := url.Values{}
			for _, fld := range f.Fields {
				v := fld.Value
				if v == "" {
					v = "vexor"
				}
				vals.Set(fld.Name, v)
			}
			method := f.Method
			if method == "" {
				method = "GET"
			}
			for _, fld := range f.Fields {
				add(detect.Point{URL: f.Action, Method: method, Values: cloneValues(vals), Param: fld.Name})
			}
		}
		_ = page
	}
	return out
}

// dedupe removes findings with duplicate IDs, preserving order.
func dedupe(fs []detect.Finding) []detect.Finding {
	seen := map[string]bool{}
	var out []detect.Finding
	for _, f := range fs {
		if seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		out = append(out, f)
	}
	return out
}

// ANSI color helpers (kept local so engine output stays self-contained).
func cyan() string    { return "\033[36m" }
func magenta() string { return "\033[35m" }
func reset() string   { return "\033[0m" }

// TrimTrailingSlash normalizes a user-supplied target.
func TrimTrailingSlash(s string) string {
	return strings.TrimRight(s, "/")
}

// cloneValues deep-copies url.Values so concurrent points never share state.
func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}
