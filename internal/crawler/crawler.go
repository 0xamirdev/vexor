// Package crawler enumerates the attack surface of a single web target:
// links, forms, JSON API keys and interesting files. Every discovered
// endpoint is kept raw (no assumptions) for later probe modules.
package crawler

import (
	"context"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"vexor/internal/httpc"
)

// Form models one HTML <form> discovered on a page.
type Form struct {
	Action string
	Method string
	Fields []Field
}

// Field is a single form input.
type Field struct {
	Name  string
	Type  string
	Value string
}

// Param is a parameter observed in a URL query string.
type Param struct {
	Key   string
	Value string
}

// Result aggregates everything the crawler learned about the target.
type Result struct {
	Target    string
	Host      string
	Endpoints map[string]bool // path -> visited
	Params    map[string][]Param
	Forms     map[string][]Form
	JSONKeys  map[string][]string
	Scripts   []string
}

var (
	linkRe = regexp.MustCompile(`(?i)<a[^>]+href\s*=\s*["']?([^"'>\s]+)`)
	formRe = regexp.MustCompile(`(?is)<form[^>]*>(.*?)</form>`)
	// actRe captures the opening <form> tag to read action/method attributes.
	actRe   = regexp.MustCompile(`(?i)<form[^>]*action\s*=\s*["']?([^"'>\s]+)`)
	methRe  = regexp.MustCompile(`(?i)<form[^>]*method\s*=\s*["']?([^"'>\s]+)`)
	inputRe = regexp.MustCompile(`(?i)<input[^>]*>`)
	nameRe  = regexp.MustCompile(`(?i)name\s*=\s*["']([^"']+)["']`)
	typRe   = regexp.MustCompile(`(?i)type\s*=\s*["']([^"']+)["']`)
	valRe   = regexp.MustCompile(`(?i)value\s*=\s*["']([^"']*)["']`)
	srcRe   = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']?([^"'>\s]+)`)
	// jsonKeyRe pulls identifier-like keys out of JSON-ish bodies.
	jsonKeyRe = regexp.MustCompile(`"([A-Za-z_][A-Za-z0-9_]{2,30})"\s*:`)
)

// Interesting paths are probed quietly after the crawl finishes.
var interestingPaths = []string{
	"/robots.txt", "/.env", "/.git/HEAD", "/admin", "/login", "/api",
	"/api/v1", "/wp-login.php", "/debug", "/console", "/backup.zip",
	"/phpinfo.php", "/server-status", "/actuator", "/swagger.json",
	"/graphql", "/signup", "/register", "/user", "/search", "/upload",
}

// Crawl walks same-origin pages breadth-first and harvests the attack surface.
func Crawl(ctx context.Context, client *httpc.Client, target string, maxPages int) (*Result, error) {
	base, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	res := &Result{
		Target:    target,
		Host:      base.Host,
		Endpoints: map[string]bool{},
		Params:    map[string][]Param{},
		Forms:     map[string][]Form{},
		JSONKeys:  map[string][]string{},
	}
	queue := []string{target}
	seen := map[string]bool{target: true}
	visited := 0
	for len(queue) > 0 && visited < maxPages {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}
		current := queue[0]
		queue = queue[1:]
		resp, err := client.Do(ctx, "GET", current, nil, true, nil)
		if err != nil || resp.StatusCode >= 500 {
			continue
		}
		visited++
		res.Endpoints[current] = true
		harvest(res, base, current, resp.Body)
		for _, raw := range extractLinks(resp.Body) {
			next := absoluteURL(current, raw)
			if next == "" || seen[next] || !sameHost(next, base.Host) {
				continue
			}
			seen[next] = true
			queue = append(queue, next)
		}
	}
	probeInteresting(ctx, client, res, base)
	return res, nil
}

// extractLinks pulls hrefs out of an HTML body.
func extractLinks(body string) []string {
	matches := linkRe.FindAllStringSubmatch(body, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m[1])
	}
	return out
}

// harvest records forms, script srcs, JSON keys and query parameters of a page.
func harvest(res *Result, base *url.URL, pageURL, body string) {
	for _, fm := range formRe.FindAllStringSubmatch(body, -1) {
		inner := fm[1]
		f := Form{Method: "GET"}
		openTag := fm[0]
		if m := actRe.FindStringSubmatch(openTag); m != nil {
			f.Action = absoluteURL(pageURL, m[1])
		} else {
			f.Action = pageURL
		}
		if m := methRe.FindStringSubmatch(openTag); m != nil {
			f.Method = strings.ToUpper(m[1])
		}
		for _, in := range inputRe.FindAllString(inner, -1) {
			fld := Field{}
			if m := nameRe.FindStringSubmatch(in); m != nil {
				fld.Name = m[1]
			}
			if m := typRe.FindStringSubmatch(in); m != nil {
				fld.Type = strings.ToLower(m[1])
			}
			if m := valRe.FindStringSubmatch(in); m != nil {
				fld.Value = m[1]
			}
			if fld.Name != "" {
				f.Fields = append(f.Fields, fld)
			}
		}
		if len(f.Fields) > 0 {
			res.Forms[pageURL] = append(res.Forms[pageURL], f)
		}
	}
	for _, s := range srcRe.FindAllStringSubmatch(body, -1) {
		if u := absoluteURL(pageURL, s[1]); u != "" {
			res.Scripts = append(res.Scripts, u)
		}
	}
	for _, k := range jsonKeyRe.FindAllStringSubmatch(body, -1) {
		res.JSONKeys[pageURL] = append(res.JSONKeys[pageURL], k[1])
	}
	u, err := url.Parse(pageURL)
	if err != nil {
		return
	}
	for key, vals := range u.Query() {
		res.Params[pageURL] = append(res.Params[pageURL], Param{Key: key, Value: vals[0]})
	}
}

// probeInteresting quietly checks well-known sensitive paths with HEAD first,
// falling back to GET for anything that answers 200.
func probeInteresting(ctx context.Context, client *httpc.Client, res *Result, base *url.URL) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, p := range interestingPaths {
		wg.Add(1)
		sem <- struct{}{}
		go func(path string) {
			defer wg.Done()
			defer func() { <-sem }()
			u := *base
			u.Path = path
			u.RawQuery = ""
			full := u.String()
			resp, err := client.Do(ctx, "GET", full, nil, false, nil)
			if err != nil || resp.StatusCode != 200 {
				return
			}
			mu.Lock()
			res.Endpoints[full] = true
			harvest(res, base, full, resp.Body)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
}

// absoluteURL resolves a reference against the page URL.
func absoluteURL(page, ref string) string {
	if ref == "" || strings.HasPrefix(ref, "#") ||
		strings.HasPrefix(ref, "javascript:") || strings.HasPrefix(ref, "mailto:") ||
		strings.HasPrefix(ref, "tel:") || strings.HasPrefix(ref, "data:") {
		return ""
	}
	base, err := url.Parse(page)
	if err != nil {
		return ""
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return base.ResolveReference(r).String()
}

// sameHost reports whether a URL belongs to the crawled host.
func sameHost(raw, host string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Host == host
}

// SortedEndpoints returns discovered endpoints in stable order.
func (r *Result) SortedEndpoints() []string {
	out := make([]string, 0, len(r.Endpoints))
	for e := range r.Endpoints {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

// Stats returns a one-line crawl summary for the console.
func (r *Result) Stats() string {
	nParams := 0
	for _, ps := range r.Params {
		nParams += len(ps)
	}
	return time.Now().Format("15:04:05") + " endpoints=" + itoa(len(r.Endpoints)) +
		" params=" + itoa(nParams) + " forms=" + itoa(len(r.Forms))
}

// itoa is a tiny helper to avoid fmt in hot loops.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
