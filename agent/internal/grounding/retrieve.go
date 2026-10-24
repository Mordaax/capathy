// Package grounding retrieves bounded excerpts from exact operator-approved official documentation URLs.
package grounding

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"capathy/agent/internal/request"
	"golang.org/x/net/html"
)

// Policy permits only explicitly configured exact URLs and official host names.
type Policy struct {
	URLs       []string
	Domains    []string
	MaxBytes   int64
	MaxExcerpt int
}

// DocRef is cited inert documentation data, never a command source.
type DocRef struct {
	ID         string    `json:"id"`
	URL        string    `json:"url"`
	Title      string    `json:"title"`
	AccessedAt time.Time `json:"accessed_at"`
	SHA256     string    `json:"sha256"`
	Excerpt    string    `json:"excerpt"`
}

// Fetcher supports deterministic tests without network access.
type Fetcher interface {
	Fetch(context.Context, string, int64) ([]byte, error)
}

// HTTPFetcher confines DNS, connects directly to public addresses and forbids redirects/proxies.
type HTTPFetcher struct{}

func publicIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return false
	}
	v4 := ip.To4()
	return v4 == nil || !(v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127)
}

// Fetch downloads one approved public HTTPS URL with byte/time limits.
func (HTTPFetcher) Fetch(ctx context.Context, raw string, max int64) ([]byte, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return nil, errors.New("unsupported documentation URL")
	}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, errors.New("no public address")
		}
		for _, ip := range ips {
			if !publicIP(ip.IP) {
				return nil, errors.New("non-public documentation address blocked")
			}
		}
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("documentation redirects are disabled") }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, errors.New("documentation fetch failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("documentation HTTP status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, errors.New("documentation size limit exceeded")
	}
	return body, nil
}

// Retrieve applies policy before invoking the network and emits a bounded text-only provenance record.
func Retrieve(ctx context.Context, raw string, policy Policy, fetcher Fetcher) (DocRef, error) {
	var out DocRef
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Fragment != "" {
		return out, errors.New("invalid documentation URL")
	}
	allowedURL, allowedHost := false, false
	for _, s := range policy.URLs {
		if s == raw {
			allowedURL = true
		}
	}
	for _, s := range policy.Domains {
		if s == u.Hostname() {
			allowedHost = true
		}
	}
	if !allowedURL || !allowedHost {
		return out, errors.New("documentation URL and host must both be allowlisted")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && !publicIP(ip) {
		return out, errors.New("private documentation address blocked")
	}
	if policy.MaxBytes <= 0 || policy.MaxBytes > 1<<20 {
		policy.MaxBytes = 1 << 20
	}
	if policy.MaxExcerpt <= 0 || policy.MaxExcerpt > 16384 {
		policy.MaxExcerpt = 8192
	}
	body, err := fetcher.Fetch(ctx, raw, policy.MaxBytes)
	if err != nil {
		return out, err
	}
	if int64(len(body)) > policy.MaxBytes {
		return out, errors.New("documentation size limit exceeded")
	}
	z := html.NewTokenizer(bytes.NewReader(body))
	var text strings.Builder
	var title strings.Builder
	skip, inTitle := false, false
	for {
		kind := z.Next()
		if kind == html.ErrorToken {
			if z.Err() != io.EOF {
				return out, z.Err()
			}
			break
		}
		token := z.Token()
		switch kind {
		case html.StartTagToken:
			if token.Data == "script" || token.Data == "style" {
				skip = true
			}
			if token.Data == "title" {
				inTitle = true
			}
		case html.EndTagToken:
			if token.Data == "script" || token.Data == "style" {
				skip = false
			}
			if token.Data == "title" {
				inTitle = false
			}
		case html.TextToken:
			if !skip {
				if inTitle && title.Len() < 256 {
					part := token.Data
					if len(part) > 256-title.Len() {
						part = part[:256-title.Len()]
					}
					title.WriteString(part)
				}
				if text.Len() < policy.MaxExcerpt {
					part := strings.Join(strings.Fields(token.Data), " ")
					if len(part) > policy.MaxExcerpt-text.Len() {
						part = part[:policy.MaxExcerpt-text.Len()]
					}
					text.WriteString(part)
					if text.Len() < policy.MaxExcerpt {
						text.WriteByte(' ')
					}
				}
			}
		}
	}
	out = DocRef{URL: raw, Title: title.String(), AccessedAt: time.Now().UTC(), SHA256: request.Hash(body), Excerpt: strings.TrimSpace(text.String())}
	out.ID = "doc-" + request.Hash([]byte(raw + ":" + out.SHA256))[:24]
	return out, nil
}
