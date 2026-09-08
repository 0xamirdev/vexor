// Package httpc wraps net/http with redirect control, cookie persistence,
// body caps and response timing tailored for security probing.
package httpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// maxBodyBytes caps how much of a response body is read (3 MiB).
const maxBodyBytes = 3 << 20

// Response is a captured HTTP response with timing metadata.
type Response struct {
	StatusCode int
	StatusText string
	Headers    http.Header
	Body       string
	FinalURL   string
	Duration   time.Duration
}

// Client issues probe requests with a shared cookie jar.
type Client struct {
	follow    *http.Client
	nofollow  *http.Client
	Timeout   time.Duration
	UserAgent string
}

// New builds a client with the given per-request timeout. TLS verification is
// disabled on purpose: bug bounty targets often have broken certificate chains.
func New(timeout time.Duration) *Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		jar = nil
	}
	transport := &http.Transport{
		MaxIdleConns:        128,
		MaxIdleConnsPerHost: 24,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   false,
	}
	mk := func(follow bool) *http.Client {
		c := &http.Client{Timeout: timeout, Jar: jar, Transport: transport}
		c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if !follow || len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		}
		return c
	}
	return &Client{
		follow:    mk(true),
		nofollow:  mk(false),
		Timeout:   timeout,
		UserAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 VEXOR/1.0 SecurityScanner",
	}
}

// Do sends one probe request. data is encoded as the body for non-GET methods.
// extraHeaders are applied last so they can override defaults (e.g. Origin).
func (c *Client) Do(ctx context.Context, method, rawURL string, data url.Values, followRedirects bool, extraHeaders map[string]string) (*Response, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	var body io.Reader
	if data != nil && len(data) > 0 && method != http.MethodGet {
		body = strings.NewReader(data.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	if data != nil && len(data) > 0 && method != http.MethodGet {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	client := c.follow
	if !followRedirects {
		client = c.nofollow
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return &Response{
		StatusCode: resp.StatusCode,
		StatusText: resp.Status,
		Headers:    resp.Header,
		Body:       string(raw),
		FinalURL:   resp.Request.URL.String(),
		Duration:   time.Since(start),
	}, nil
}

// Curl renders a copy-pasteable curl command reproducing a probe.
func Curl(method, rawURL string, data url.Values) string {
	cmd := "curl -sk"
	if method != http.MethodGet && method != "" {
		cmd += " -X " + method
	}
	cmd += " '" + rawURL + "'"
	if data != nil && len(data) > 0 && method != http.MethodGet {
		cmd += " --data '" + data.Encode() + "'"
	}
	return cmd
}

// String renders a compact response summary for evidence fields.
func (r *Response) String() string {
	return fmt.Sprintf("%s (%d bytes, %s)", r.StatusText, len(r.Body), r.Duration.Round(time.Millisecond))
}
