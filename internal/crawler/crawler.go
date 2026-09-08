// Package crawler enumerates the attack surface of a single web target:
// links, forms, JSON API keys and interesting files. Every discovered
// endpoint is kept raw (no assumptions) for later probe modules.
//
// Scope safety: the crawler never lets an off-site redirect expand the
// crawl queue, strips fragments before deduplication, and enforces
// same-origin on every discovered URL.
package crawler

import (
	"context"
	"errors"
	"html"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/0xamirdev/vexor/internal/httpc"
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

// Param is a parameter observed in a URL query string. A key repeated in
// the query string yields one Param per value, in order of appearance.
type Param struct {
	Key   string
	Value string
}

// Result aggregates everything the crawler learned about the target.
type Result struct {
	Target    string
	Host      string
	Endpoints map[string]bool // visited canonical URL -> true
	Params    map[string][]Param
	Forms     map[string][]Form
	JSONKeys  map[string][]string
	Scripts   []string
}

// errNoHost rejects targets without an authority component.
var errNoHost = errors.New("crawler: target must include a host")

// schemeRe matches URL schemes; used to reject non-HTTP references.
var schemeRe = regexp.MustCompile(`(?i)^[a-z][a-z0-9+.-]*:`)

var (
	linkRe = regexp.MustCompile(`(?i)<a[^>]+href\s*=\s*["']?([^"'>\s]+)`)
	formRe = regexp.MustCompile(`(?is)<form[^>]*>(.*?)</form>`)
	// actRe captures the opening <form> tag to read the action attribute.
	actRe   = regexp.MustCompile(`(?i)<form[^>]*action\s*=\s*["']?([^"'>\s]+)`)
	methRe  = regexp.MustCompile(`(?i)<form[^>]*method\s*=\s*["']?([^"'>\s]+)`)
	inputRe = regexp.MustCompile(`(?i)<input[^>]*>`)
	// attribute patterns require a quote pair or a bounded unquoted token;
	// the trailing boundary keeps data-value from matching as value=.
	nameRe = regexp.MustCompile(`(?i)name\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))`)
	typRe  = regexp.MustCompile(`(?i)type\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))`)
	valRe  = regexp.MustCompile(`(?i)(?:^|\s)value\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))`)
	srcRe  = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']?([^"'>\s]+)`)
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

// maxProbeWorkers bounds probeInteresting concurrency.
const maxProbeWorkers = 8

// Crawl walks same-origin pages breadth-first and harvests the attack surface.
//
// Redirect handling: when a request redirects, the resource that actually
// answered lives at FinalURL. Same-host final URLs become the canonical
// endpoint (visited, harvested, deduplicated); a cross-host redirect counts
// the requested URL as visited but never harvests the foreign body, so an
// off-site redirect cannot expand the crawl scope.
func Crawl(ctx context.Context, client *httpc.Client, target string, maxPages int) (*Result, error) {
	base, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	if base.Host == "" {
		return nil, errNoHost
	}
	originHost := strings.ToLower(base.Host)
	originPrefix := base.Scheme + "://" + originHost

	res := &Result{
		Target:    target,
		Host:      base.Host,
		Endpoints: map[string]bool{},
		Params:    map[string][]Param{},
		Forms:     map[string][]Form{},
		JSONKeys:  map[string][]string{},
	}

	start := canonical(target)
	queue := []string{start}
	seen := map[string]bool{start: true}
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

		// Redirect handling: same-host final URLs replace the requested URL
		// as the canonical endpoint. A final URL already visited means we
		// were bounced back to known content — merge the body and move on.
		page := current
		if final := canonical(resp.FinalURL); final != current && final != "" {
			if sameHost(final, originHost) {
				if seen[final] {
					harvest(res, final, resp.Body)
					continue
				}
				page = final
				seen[page] = true
			} else {
				// Cross-host redirect: the requested URL exists but its
				// content belongs to another origin. Record the URL, skip
				// the foreign body entirely.
				visited++
				res.Endpoints[current] = true
				continue
			}
		}

		visited++
		res.Endpoints[page] = true
		harvest(res, page, resp.Body)
		for _, raw := range extractLinks(resp.Body) {
			next := absoluteURL(page, raw)
			if next == "" || seen[next] || !sameHost(next, originHost) {
				continue
			}
			seen[next] = true
			queue = append(queue, next)
		}
	}

	probeInteresting(ctx, client, res, originPrefix, originHost)
	return res, nil
}

// canonical strips the fragment so fragment-only variants deduplicate to a
// single crawl target.
func canonical(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Fragment = ""
	u.RawFragment = ""
	return u.String()
}

// extractLinks pulls hrefs out of an HTML body. Entity references (&amp;)
// are decoded before returning: the raw HTML encoding must not leak into
// URLs or query parameters.
func extractLinks(body string) []string {
	matches := linkRe.FindAllStringSubmatch(body, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, html.UnescapeString(m[1]))
	}
	return out
}

// harvest records forms, script srcs, JSON keys and query parameters of one
// page. pageURL must be the canonical (fragment-free) page URL.
func harvest(res *Result, pageURL, body string) {
	for _, fm := range formRe.FindAllStringSubmatch(body, -1) {
		inner := fm[1]
		f := Form{Method: "GET"}
		if m := actRe.FindStringSubmatch(fm[0]); m != nil {
			f.Action = absoluteURL(pageURL, html.UnescapeString(m[1]))
		}
		if f.Action == "" {
			// Empty action, action="#", or no action at all: per the HTML
			// spec the form submits to the current page.
			f.Action = pageURL
		}
		if m := methRe.FindStringSubmatch(fm[0]); m != nil {
			if method := strings.ToUpper(strings.TrimSpace(m[1])); method == "GET" || method == "POST" {
				f.Method = method
			}
		}
		for _, in := range inputRe.FindAllString(inner, -1) {
			if fld := parseInput(in); fld.Name != "" {
				f.Fields = append(f.Fields, fld)
			}
		}
		if len(f.Fields) > 0 {
			res.Forms[pageURL] = append(res.Forms[pageURL], f)
		}
	}
	for _, s := range srcRe.FindAllStringSubmatch(body, -1) {
		if u := absoluteURL(pageURL, html.UnescapeString(s[1])); u != "" {
			res.Scripts = append(res.Scripts, u)
		}
	}
	for _, k := range jsonKeyRe.FindAllStringSubmatch(body, -1) {
		res.JSONKeys[pageURL] = append(res.JSONKeys[pageURL], k[1])
	}
	if u, err := url.Parse(pageURL); err == nil {
		// Every value of a repeated key is preserved.
		for key, vals := range u.Query() {
			for _, v := range vals {
				res.Params[pageURL] = append(res.Params[pageURL], Param{Key: key, Value: v})
			}
		}
	}
}

// parseInput extracts name/type/value from one <input> tag. Attribute values
// may be double-quoted, single-quoted, or unquoted, and entity references are
// decoded. The value pattern is boundary-anchored so data-value and friends
// never read as value=. An empty name (common for submit placeholders) is
// preserved as-is; the caller decides whether to keep the field.
func parseInput(tag string) Field {
	var fld Field
	if m := nameRe.FindStringSubmatch(tag); m != nil {
		fld.Name = html.UnescapeString(firstNonEmpty(m[1:]...))
	}
	if m := typRe.FindStringSubmatch(tag); m != nil {
		fld.Type = strings.ToLower(html.UnescapeString(firstNonEmpty(m[1:]...)))
	}
	if m := valRe.FindStringSubmatch(tag); m != nil {
		fld.Value = html.UnescapeString(firstNonEmpty(m[1:]...))
	}
	return fld
}

// firstNonEmpty returns the first non-empty string among the alternatives.
func firstNonEmpty(alts ...string) string {
	for _, a := range alts {
		if a != "" {
			return a
		}
	}
	return ""
}

// probeInteresting quietly checks well-known sensitive paths on the crawl
// origin. Requests use the no-follow client, so an off-site redirect cannot
// drag the crawler onto another host: a 3xx answer is simply not an
// interesting endpoint, and the final URL is re-verified against the origin
// before anything is recorded. Concurrent goroutines merge results under a
// mutex; callers must not harvest the same Result concurrently.
func probeInteresting(ctx context.Context, client *httpc.Client, res *Result, originPrefix, originHost string) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxProbeWorkers)
	for _, p := range interestingPaths {
		wg.Add(1)
		sem <- struct{}{}
		go func(path string) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			resp, err := client.Do(ctx, "GET", originPrefix+path, nil, false, nil)
			if err != nil || resp.StatusCode != 200 {
				return
			}
			full := canonical(resp.FinalURL)
			if !sameHost(full, originHost) {
				return // defense in depth: never record off-origin URLs
			}
			mu.Lock()
			defer mu.Unlock()
			if res.Endpoints[full] {
				return // already crawled organically
			}
			res.Endpoints[full] = true
			harvest(res, full, resp.Body)
		}(p)
	}
	wg.Wait()
}

// absoluteURL resolves a reference against the page URL and returns a
// canonical (fragment-free) absolute URL. Scheme-relative, root-relative,
// query-only and ordinary relative references resolve per RFC 3986.
// Fragments are dropped — they never define a distinct resource. Empty
// references and non-HTTP schemes yield "".
func absoluteURL(page, ref string) string {
	if ref == "" || strings.HasPrefix(ref, "#") {
		return ""
	}
	if schemeRe.MatchString(ref) {
		lower := strings.ToLower(ref)
		if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
			return ""
		}
	}
	base, err := url.Parse(page)
	if err != nil || base.Host == "" {
		return ""
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	out := base.ResolveReference(r)
	out.Fragment = ""
	out.RawFragment = ""
	return out.String()
}

// sameHost reports whether a URL belongs to the crawl origin. The host
// comparison is case-insensitive (DNS names are); the port must match
// exactly. An empty origin never matches anything.
func sameHost(raw, originHost string) bool {
	if originHost == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, originHost)
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
	return "endpoints=" + itoa(len(r.Endpoints)) +
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
