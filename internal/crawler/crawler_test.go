package crawler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0xamirdev/vexor/internal/httpc"
)

// newTestClient builds a crawler-grade httpc client with a short timeout.
func newTestClient(t *testing.T) *httpc.Client {
	t.Helper()
	return httpc.New(5 * time.Second)
}

// srv wires a handler into an httptest server and returns its base URL.
func srv(t *testing.T, h http.Handler) string {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return s.URL
}

func mux(mapHandler map[string]http.HandlerFunc) *http.ServeMux {
	m := http.NewServeMux()
	for path, h := range mapHandler {
		m.HandleFunc(path, h)
	}
	return m
}

// Crawl wraps Crawl for tests: fixed budget, 5s timeout, panics on error.
func crawlForTest(t *testing.T, client *httpc.Client, target string, maxPages int) *Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := Crawl(ctx, client, target, maxPages)
	if err != nil {
		t.Fatalf("Crawl returned error: %v", err)
	}
	return res
}

// ---------------------------------------------------------------- redirects

func TestRedirectToDashboardUsesFinalURL(t *testing.T) {
	// https://host/ redirects to /dashboard; the final URL must become the
	// visited endpoint.
	target := srv(t, mux(map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
		},
		"/dashboard": func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `<html><body><a href="/reports">Reports</a></body></html>`)
		},
		"/reports": func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `<html><body>reports page</body></html>`)
		},
	}))

	res := crawlForTest(t, newTestClient(t), target, 10)

	if res.Endpoints[target+"/dashboard"] {
		// /dashboard was discovered through the redirect and crawled.
		if !res.Endpoints[target+"/reports"] {
			t.Errorf("links on the redirect target were not followed; endpoints=%v", res.Endpoints)
		}
	} else {
		t.Errorf("final URL %s/dashboard missing from endpoints; got %v", target, res.Endpoints)
	}
}

func TestRedirectAliasDoesNotDoubleCount(t *testing.T) {
	// Two links point to /alias and /real; /alias redirects to /real. The
	// shared resource must appear exactly once as /real.
	target := srv(t, mux(map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `<html><body><a href="/alias">a</a><a href="/other">o</a></body></html>`)
		},
		"/alias": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/real", http.StatusFound)
		},
		"/other": func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `<html><body>other</body></html>`)
		},
		"/real": func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `<html><body><a href="/deep">d</a></body></html>`)
		},
		"/deep": func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `<html><body>deep</body></html>`)
		},
	}))

	res := crawlForTest(t, newTestClient(t), target, 10)

	for _, e := range res.SortedEndpoints() {
		if strings.HasSuffix(e, "/alias") {
			t.Errorf("redirect alias /alias was recorded as an endpoint: %v", res.Endpoints)
		}
	}
	if !res.Endpoints[target+"/real"] {
		t.Errorf("canonical /real missing from endpoints: %v", res.Endpoints)
	}
}

func TestCrossHostRedirectDoesNotExpandScope(t *testing.T) {
	target := srv(t, mux(map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `<html><body><a href="/offsite">off</a></body></html>`)
		},
		"/offsite": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, extURLHolder+"/landing", http.StatusFound)
		},
	}))

	// A second server plays the external host.
	ext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body><a href="/injected">inject</a></body></html>`)
	}))
	defer ext.Close()
	extURLHolder = ext.URL

	res := crawlForTest(t, newTestClient(t), target, 10)

	if res.Endpoints[extURLHolder+"/landing"] {
		t.Errorf("cross-host redirect target was crawled: %v", res.Endpoints)
	}
	for _, s := range res.Scripts {
		if strings.Contains(s, extURLHolder) {
			t.Errorf("off-host script harvested: %s", s)
		}
	}
}

// extURLHolder carries the external server URL into redirect handlers that
// need it at request time (declared before the tests that use it).
var extURLHolder string

// ------------------------------------------------------- same-origin rules

func TestCrossHostLinkRejected(t *testing.T) {
	ext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body>external page must never be crawled</body></html>`)
	}))
	defer ext.Close()
	extURL := ext.URL

	target := srv(t, mux(map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `<html><body><a href="%s/ext">ext</a><a href="//%s/rootrel">rr</a></body></html>`,
				extURL, strings.TrimPrefix(extURL, "http://"))
		},
	}))

	res := crawlForTest(t, newTestClient(t), target, 10)
	for _, e := range res.SortedEndpoints() {
		if strings.Contains(e, strings.TrimPrefix(extURL, "http://")) {
			t.Errorf("external host crawled: %s (endpoints: %v)", e, res.Endpoints)
		}
	}
}

func TestRelativeAndRootRelativeLinks(t *testing.T) {
	target := srv(t, mux(map[string]http.HandlerFunc{
		"/a/b/page": func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `<html><body>
				<a href="sibling">sib</a>
				<a href="/top">top</a>
				<a href="../up">up</a>
				<a href="?only=query">q</a>
			</body></html>`)
		},
		"/a/b/sibling":    func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "s") },
		"/top":            func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "t") },
		"/a/up":           func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "u") },
		"/a/b/page&extra": func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "x") },
	}))

	res := crawlForTest(t, newTestClient(t), target+"/a/b/page", 10)

	for _, want := range []string{
		target + "/a/b/sibling",
		target + "/top",
		target + "/a/up",
		// Query-only reference: RFC 3986 keeps the existing path.
		target + "/a/b/page?only=query",
	} {
		if !res.Endpoints[want] {
			t.Errorf("expected endpoint %s missing; got %v", want, res.SortedEndpoints())
		}
	}
}

func TestFragmentLinksDeduplicate(t *testing.T) {
	target := srv(t, mux(map[string]http.HandlerFunc{
		// Register an exact root handler ("/" would catch every
		// interesting-path probe and pollute the endpoint set).
		"/{$}": func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `<html><body>
				<a href="/doc#intro">i</a>
				<a href="/doc#usage">u</a>
				<a href="/doc">plain</a>
				<a href="#self">self</a>
			</body></html>`)
		},
		"/doc": func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `<html><body>doc content</body></html>`)
		},
	}))

	res := crawlForTest(t, newTestClient(t), target, 10)

	for e := range res.Endpoints {
		if strings.Contains(e, "#") {
			t.Errorf("fragment leaked into endpoints: %s", e)
		}
	}
	if !res.Endpoints[target+"/doc"] {
		t.Errorf("/doc not discovered: %v", res.Endpoints)
	}
	// #self resolves to the start page; /doc is the only other target.
	if len(res.Endpoints) != 2 {
		t.Errorf("fragment variants created duplicate endpoints: %v", res.SortedEndpoints())
	}
}

func TestDangerousSchemesRejected(t *testing.T) {
	target := srv(t, mux(map[string]http.HandlerFunc{
		"/{$}": func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `<html><body>
				<a href="javascript:alert(1)">js</a>
				<a href="mailto:x@y.z">mail</a>
				<a href="data:text/html,hi">data</a>
				<a href="tel:+1234">tel</a>
			</body></html>`)
		},
	}))
	res := crawlForTest(t, newTestClient(t), target, 10)
	// Only the start page may exist.
	if len(res.Endpoints) != 1 {
		t.Errorf("scheme links created endpoints: %v", res.SortedEndpoints())
	}
}

// ------------------------------------------------------------------- forms

func TestFormExtractionWithCSRFAndMethod(t *testing.T) {
	target := srv(t, mux(map[string]http.HandlerFunc{
		"/login": func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `<html><body>
			<form action="/auth" method="POST">
				<input type="hidden" name="csrf_token" value="tok-123">
				<input type="text" name="user" value="">
				<input type="password" name='pass' value=''>
				<input type=submit name=go value=Login>
			</form>
			<form>
				<input type="text" name="q" value="default">
			</form>
			<form action="#" method="get">
				<input type="text" name="frag" value="1">
			</form>
			</body></html>`)
		},
	}))

	res := crawlForTest(t, newTestClient(t), target+"/login", 5)

	forms := res.Forms[target+"/login"]
	if len(forms) != 3 {
		t.Fatalf("expected 3 forms, got %d: %+v", len(forms), forms)
	}

	// Form 1: explicit action, POST method, hidden CSRF preserved.
	f := forms[0]
	if f.Action != target+"/auth" {
		t.Errorf("form action = %q, want %s/auth", f.Action, target)
	}
	if f.Method != "POST" {
		t.Errorf("form method = %q, want POST", f.Method)
	}
	var csrf *Field
	for i := range f.Fields {
		if f.Fields[i].Name == "csrf_token" {
			csrf = &f.Fields[i]
		}
	}
	if csrf == nil {
		t.Fatalf("hidden csrf_token field lost: %+v", f.Fields)
	}
	if csrf.Type != "hidden" || csrf.Value != "tok-123" {
		t.Errorf("csrf field = %+v, want hidden/tok-123", *csrf)
	}
	// Unquoted attributes must parse too (submit input).
	var submit *Field
	for i := range f.Fields {
		if f.Fields[i].Name == "go" {
			submit = &f.Fields[i]
		}
	}
	if submit == nil || submit.Value != "Login" {
		t.Errorf("unquoted attribute input parsed wrong: %+v", f.Fields)
	}

	// Form 2: missing action -> current page; missing method -> GET.
	f2 := forms[1]
	if f2.Action != target+"/login" {
		t.Errorf("actionless form resolved to %q, want %s/login", f2.Action, target+"/login")
	}
	if f2.Method != "GET" {
		t.Errorf("methodless form = %q, want GET", f2.Method)
	}

	// Form 3: action="#" must resolve to the current page, not "".
	f3 := forms[2]
	if f3.Action != target+"/login" {
		t.Errorf(`action="#" resolved to %q, want %s/login`, f3.Action, target+"/login")
	}
}

func TestRelativeFormActionResolved(t *testing.T) {
	target := srv(t, mux(map[string]http.HandlerFunc{
		"/area/form": func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `<html><body>
				<form action="submit" method="post">
					<input type="text" name="a" value="1">
				</form>
				<form action="/abs" method="post">
					<input type="text" name="b" value="2">
				</form>
				<form action="../parent">
					<input type="text" name="c" value="3">
				</form>
			</body></html>`)
		},
		"/area/submit": func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "s") },
		"/abs":         func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "a") },
		"/parent":      func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "p") },
	}))

	res := crawlForTest(t, newTestClient(t), target+"/area/form", 5)
	forms := res.Forms[target+"/area/form"]
	if len(forms) != 3 {
		t.Fatalf("expected 3 forms, got %d", len(forms))
	}
	want := []string{target + "/area/submit", target + "/abs", target + "/parent"}
	for i, w := range want {
		if forms[i].Action != w {
			t.Errorf("form %d action = %q, want %q", i, forms[i].Action, w)
		}
	}
}

// ----------------------------------------------------------------- params

func TestQueryParameterExtraction(t *testing.T) {
	target := srv(t, mux(map[string]http.HandlerFunc{
		"/list": func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `<html><body>listing</body></html>`)
		},
		"/{$}": func(w http.ResponseWriter, r *http.Request) {
			// Realistic HTML: entities inside the href. The crawler must
			// decode &amp; before parsing the query.
			href := "/list?page=2&amp;page=3&amp;sort=desc&amp;tag=a+b"
			fmt.Fprint(w, `<html><body><a href="`+href+`">next</a></body></html>`)
		},
	}))

	res := crawlForTest(t, newTestClient(t), target, 10)
	listURL := target + "/list?page=2&page=3&sort=desc&tag=a+b"
	params := res.Params[listURL]
	if len(params) == 0 {
		t.Fatalf("no params captured for %s: %v", listURL, res.Params)
	}
	// page appears twice: both values must survive.
	var pageCount int
	for _, p := range params {
		if p.Key == "page" && (p.Value == "2" || p.Value == "3") {
			pageCount++
		}
	}
	if pageCount != 2 {
		t.Errorf("repeated key lost values; params = %+v", params)
	}
	// Plus-encoded space decoded exactly once.
	found := false
	for _, p := range params {
		if p.Key == "tag" && p.Value == "a b" {
			found = true
		}
	}
	if !found {
		t.Errorf("encoded param value mangled: %+v", params)
	}
	// The &amp; entity must not leak into stored keys or values.
	for _, p := range params {
		if strings.Contains(p.Key, "amp") || strings.Contains(p.Value, "amp") {
			t.Errorf("HTML entity leaked into params: %+v", params)
		}
	}
}

// ------------------------------------------------------ interesting paths

func TestInterestingPathsRespectHost(t *testing.T) {
	ext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Pretend every path exists off-host with sensitive content.
		if r.URL.Path == "/.env" {
			fmt.Fprint(w, "SECRET=should-never-appear")
			return
		}
		fmt.Fprint(w, "external")
	}))
	defer ext.Close()
	extURL := ext.URL

	target := srv(t, mux(map[string]http.HandlerFunc{
		"/robots.txt": func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "User-agent: *\nDisallow: /\n")
		},
		"/login": func(w http.ResponseWriter, r *http.Request) {
			// Cross-host redirect for an interesting path: must be ignored.
			http.Redirect(w, r, extURL+"/.env", http.StatusFound)
		},
	}))

	res := crawlForTest(t, newTestClient(t), target, 5)

	for e := range res.Endpoints {
		if strings.Contains(e, strings.TrimPrefix(extURL, "http://")) {
			t.Errorf("interesting-path probing escaped the origin: %s", e)
		}
	}
	// Same-host interesting paths that answer 200 are still discovered.
	if !res.Endpoints[target+"/robots.txt"] {
		t.Errorf("same-origin robots.txt missing: %v", res.SortedEndpoints())
	}
	if res.Endpoints[target+"/login"] {
		t.Errorf("redirecting interesting path recorded despite off-host redirect: %v", res.SortedEndpoints())
	}
	for _, p := range res.Params {
		for _, v := range p {
			if strings.Contains(v.Value, "should-never-appear") {
				t.Errorf("off-host content harvested: %+v", v)
			}
		}
	}
}

// -------------------------------------------------------------- semantics

func TestSortedEndpointsDeterministic(t *testing.T) {
	res := &Result{Endpoints: map[string]bool{
		"http://x/c": true, "http://x/a": true, "http://x/b": true,
	}}
	first := res.SortedEndpoints()
	want := []string{"http://x/a", "http://x/b", "http://x/c"}
	for i := range want {
		if first[i] != want[i] {
			t.Fatalf("sort mismatch: %v", first)
		}
	}
	for i := 0; i < 5; i++ {
		again := res.SortedEndpoints()
		for j := range first {
			if again[j] != first[j] {
				t.Fatalf("sort not deterministic: %v vs %v", first, again)
			}
		}
	}
}

func TestTargetWithoutHostRejected(t *testing.T) {
	client := newTestClient(t)
	if _, err := Crawl(context.Background(), client, "not-a-url", 5); err == nil {
		t.Fatal("expected error for target without host")
	}
}

func TestCancellationStopsCrawl(t *testing.T) {
	release := make(chan struct{})
	target := srv(t, mux(map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `<html><body><a href="/p1">1</a><a href="/p2">2</a><a href="/p3">3</a></body></html>`)
		},
		"/p1": func(w http.ResponseWriter, r *http.Request) { <-release; fmt.Fprint(w, "1") },
		"/p2": func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "2") },
		"/p3": func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "3") },
	}))

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()
	res, err := Crawl(ctx, newTestClient(t), target, 10)
	close(release)
	// Either context.Canceled or a clean partial result is acceptable; the
	// crawl must not hang and must not error on anything else.
	if err != nil && err != context.Canceled {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = res
}

func TestSameHostUnit(t *testing.T) {
	cases := []struct {
		raw    string
		origin string
		want   bool
	}{
		{"http://example.com/a", "example.com", true},
		{"http://EXAMPLE.com/a", "example.com", true}, // DNS case-insensitive
		{"http://example.com:8080/a", "example.com", false},
		{"http://sub.example.com/a", "example.com", false}, // no subdomain creep
		{"http://evilexample.com/a", "example.com", false}, // no suffix match
		{"https://example.com/b", "example.com", true},     // scheme irrelevant
		{"//example.com/c", "example.com", true},           // scheme-relative
		{"/relative/path", "example.com", false},           // no host at all
		{"http://other.com/d", "example.com", false},
		{"http://other.com/d", "", false}, // empty origin matches nothing
	}
	for _, c := range cases {
		if got := sameHost(c.raw, c.origin); got != c.want {
			t.Errorf("sameHost(%q, %q) = %v, want %v", c.raw, c.origin, got, c.want)
		}
	}
}

func TestAbsoluteURLUnit(t *testing.T) {
	base := "http://example.com/dir/page"
	cases := []struct{ ref, want string }{
		{"", ""},
		{"#frag", ""},
		{"other", "http://example.com/dir/other"},
		{"/root", "http://example.com/root"},
		{"../up", "http://example.com/up"},
		{"?q=1", "http://example.com/dir/page?q=1"},
		{"http://other.com/x", "http://other.com/x"},
		{"https://other.com/x", "https://other.com/x"},
		{"//cdn.example.com/lib.js", "http://cdn.example.com/lib.js"},
		{"javascript:alert(1)", ""},
		{"mailto:a@b.c", ""},
		{"tel:+123", ""},
		{"data:text/html,x", ""},
		{"/page#section", "http://example.com/page"}, // fragment stripped
	}
	for _, c := range cases {
		if got := absoluteURL(base, c.ref); got != c.want {
			t.Errorf("absoluteURL(%q) = %q, want %q", c.ref, got, c.want)
		}
	}
}

func TestParseInputUnquotedAndEdgeCases(t *testing.T) {
	cases := []struct {
		tag  string
		want Field
	}{
		{`<input type="hidden" name="csrf" value="abc">`,
			Field{Name: "csrf", Type: "hidden", Value: "abc"}},
		{`<input name='user' value='bob'>`,
			Field{Name: "user", Value: "bob"}},
		{`<input name=page value=7>`,
			Field{Name: "page", Value: "7"}},
		{`<input data-value="nope" type="text" value="yes" name="x">`,
			Field{Name: "x", Type: "text", Value: "yes"}},
		{`<input type="checkbox" name="agree">`,
			Field{Name: "agree", Type: "checkbox"}},
		{`<input type="text">`,
			Field{Name: "", Type: "text", Value: ""}},
	}
	for _, c := range cases {
		got := parseInput(c.tag)
		if got != c.want {
			t.Errorf("parseInput(%q) = %+v, want %+v", c.tag, got, c.want)
		}
	}
}

func TestNoPanicOnUnusualURLs(t *testing.T) {
	// Feed pathological inputs straight into the pure helpers; none may panic.
	weird := []string{
		"", " ", "http://", "://", "http://[::1", "%zz", "http://ex%2Foo/",
		"a?b#c", "//", "http://user:pass@host/p", "http://host/\x00",
	}
	for _, w := range weird {
		_ = absoluteURL("http://example.com/", w)
		_ = absoluteURL(w, "/x")
		_ = sameHost(w, "example.com")
		_ = canonical(w)
	}
	// Repeated-key query on a page URL must not panic either.
	res := &Result{Params: map[string][]Param{}}
	harvest(res, "http://example.com/p?a=1&a=2&a=%zz", "")
	if len(res.Params["http://example.com/p?a=1&a=2&a=%zz"]) == 0 {
		t.Error("expected params even for partially invalid query")
	}
}

func TestMaxPagesRespected(t *testing.T) {
	m := http.NewServeMux()
	m.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		var b strings.Builder
		b.WriteString("<html><body>")
		for i := 0; i < 30; i++ {
			fmt.Fprintf(&b, `<a href="/p%d">p%d</a>`, i, i)
		}
		b.WriteString("</body></html>")
		fmt.Fprint(w, b.String())
	})
	for i := 0; i < 30; i++ {
		p := fmt.Sprintf("/p%d", i)
		m.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "page")
		})
	}
	target := srv(t, m)

	res := crawlForTest(t, newTestClient(t), target, 5)
	visited := len(res.Endpoints)
	if visited > 5 {
		t.Errorf("maxPages=5 but %d endpoints visited: %v", visited, res.SortedEndpoints())
	}
	if visited != 5 {
		t.Errorf("expected exactly 5 visited endpoints, got %d: %v", visited, res.SortedEndpoints())
	}
}

func TestStatsCounts(t *testing.T) {
	res := &Result{
		Endpoints: map[string]bool{"a": true, "b": true},
		Params:    map[string][]Param{"a": {{Key: "x", Value: "1"}, {Key: "x", Value: "2"}}, "b": {{Key: "y", Value: "3"}}},
		Forms:     map[string][]Form{"a": {{Action: "a"}}},
	}
	s := res.Stats()
	for _, want := range []string{"endpoints=2", "params=3", "forms=1"} {
		if !strings.Contains(s, want) {
			t.Errorf("Stats() = %q, missing %q", s, want)
		}
	}
}
