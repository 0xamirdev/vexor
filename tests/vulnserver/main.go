// Vulnserver is a deliberately vulnerable test target used by the VEXOR
// acceptance suite (tests/acceptance.py). It reproduces the exact false
// positives reported against app.tlyn.ir plus controlled real findings.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
	mux := http.NewServeMux()

	// Home page with links + a client-side SDK token (public by design).
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Add("Set-Cookie", "session=abc123; Path=/")
		fmt.Fprint(w, `<!doctype html><html><head><title>App</title>
		<script>gapifySDK.run({ websiteToken: 'VgcYWjYJ2Dr3rXh5roFWcFwF', baseUrl: 'https://api.gapify.local' });</script>
		</head><body>
		<h1>Test App</h1>
		<a href="/login">Login</a>
		<a href="/item?id=42">Item 42</a>
		<a href="/greet?name=world">Greet</a>
		<a href="/api/profile">Profile API</a>
		<form action="/login" method="post">
			<input type="text" name="user" value="">
			<input type="password" name="pass" value="">
		</form>
		</body></html>`)
	})

	// Login page carrying the same public websiteToken (tlyn scenario).
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<!doctype html><html><head><title>Login</title>
		<script>gapifySDK.run({ websiteToken: 'VgcYWjYJ2Dr3rXh5roFWcFwF', baseUrl: 'https://api.gapify.local' });</script>
		</head><body><form method="post">
		<input type="text" name="user"><input type="password" name="pass">
		</form></body></html>`)
	})

	// SQLi: error injection on id.
	mux.HandleFunc("/item", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "'") {
			w.WriteHeader(500)
			fmt.Fprintf(w, `Warning: mysql_query(): You have an error in your SQL syntax; check the manual near '%s' at line 1`, id)
			return
		}
		fmt.Fprintf(w, "<html><body>Item %s: detail page</body></html>", id)
	})

	// Reflected XSS.
	mux.HandleFunc("/greet", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body>Hello, %s! Welcome back.</body></html>", r.URL.Query().Get("name"))
	})

	// robots.txt: plain public directives. Must produce zero findings.
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "User-agent: *\nDisallow: /\n")
	})

	// .env with a real-format AWS key (unverified: server ignores replays).
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "APP_KEY=base64:SuperSecretKey123\nDB_PASSWORD=Sup3rS3cret!\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
	})

	// API that reflects any origin (CORS misconfig).
	mux.HandleFunc("/api/profile", func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		fmt.Fprint(w, `{"user":"admin","email":"admin@test.local"}`)
	})

	// Public-by-design publishable key in JS config (no finding allowed).
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "stripe.config({ publishableKey: 'pk_test_51AbcdefGhIjKlMnOp' });")
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8099"
	}
	log.Println("vulnserver on :" + port)
	log.Fatal(http.ListenAndServe("127.0.0.1:"+port, mux))
}
