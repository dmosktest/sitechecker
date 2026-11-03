package ssrf

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

const (
	MaxBodyBytes     = 1 << 20
	RequestTimeout   = 10 * time.Second
	MaxRedirects     = 5
	UserAgent        = "SiteChecker/0.1 (+https://sitechecker.dmosk.net/)"
)

var (
	ErrInvalidURL   = errors.New("invalid_domain")
	ErrBlockedTarget = errors.New("blocked_target")
)

type Response struct {
	URL        string
	StatusCode int
	Header     http.Header
	Body       []byte
	TLS        *tls.ConnectionState
	FinalHost  string
}

func NormalizeDomain(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "http://")
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.Split(raw, "/")[0]
	raw = strings.Split(raw, "?")[0]
	raw = strings.TrimSuffix(raw, ".")
	raw = strings.ToLower(raw)
	if raw == "" || strings.Contains(raw, "@") || strings.Contains(raw, ":") {
		return "", ErrInvalidURL
	}
	if net.ParseIP(raw) != nil {
		return "", ErrInvalidURL
	}
	ascii, err := idna.Lookup.ToASCII(raw)
	if err != nil || ascii == "" {
		return "", ErrInvalidURL
	}
	if strings.Contains(ascii, "..") || strings.HasPrefix(ascii, ".") {
		return "", ErrInvalidURL
	}
	return ascii, nil
}

func IsBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
		a, b := ip[0], ip[1]
		switch {
		case a == 0:
			return true
		case a == 10:
			return true
		case a == 127:
			return true
		case a == 169 && b == 254:
			return true
		case a == 172 && b >= 16 && b <= 31:
			return true
		case a == 192 && b == 168:
			return true
		case a == 100 && b >= 64 && b <= 127:
			return true
		case a >= 224:
			return true
		}
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsPrivate() || ip.IsUnspecified() {
		return true
	}
	if ip.To4() == nil && len(ip) == net.IPv6len {
		if ip[0]&0xfe == 0xfc {
			return true
		}
	}
	return false
}

func resolveSafe(ctx context.Context, host string) (net.IP, error) {
	resolver := &net.Resolver{}
	addrs, err := resolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		return nil, ErrBlockedTarget
	}
	var first net.IP
	for _, a := range addrs {
		if IsBlockedIP(a.IP) {
			return nil, ErrBlockedTarget
		}
		if first == nil {
			first = a.IP
		}
	}
	if first == nil {
		return nil, ErrBlockedTarget
	}
	return first, nil
}

func dialFixed(ctx context.Context, network, addr string, fixed net.IP) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if port != "80" && port != "443" {
		return nil, ErrBlockedTarget
	}
	_ = host
	d := net.Dialer{Timeout: RequestTimeout}
	return d.DialContext(ctx, network, net.JoinHostPort(fixed.String(), port))
}

type Client struct {
	ua string
}

func NewClient() *Client {
	return &Client{ua: UserAgent}
}

func (c *Client) Fetch(ctx context.Context, rawURL string) (*Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, ErrInvalidURL
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, ErrInvalidURL
	}
	if u.User != nil {
		return nil, ErrInvalidURL
	}
	if u.Port() != "" && u.Port() != "80" && u.Port() != "443" {
		return nil, ErrInvalidURL
	}
	if net.ParseIP(u.Hostname()) != nil {
		return nil, ErrInvalidURL
	}

	current := u
	var last *Response
	for i := 0; i <= MaxRedirects; i++ {
		host := strings.ToLower(current.Hostname())
		ip, err := resolveSafe(ctx, host)
		if err != nil {
			return nil, err
		}

		transport := &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialFixed(ctx, network, addr, ip)
			},
			TLSClientConfig:     &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
			DisableCompression:  false,
			MaxResponseHeaderBytes: 1 << 16,
		}
		client := &http.Client{
			Transport: transport,
			Timeout:   RequestTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", c.ua)
		req.Header.Set("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8")

		res, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBlockedTarget, err)
		}
		body, _ := io.ReadAll(io.LimitReader(res.Body, MaxBodyBytes+1))
		_ = res.Body.Close()
		if len(body) > MaxBodyBytes {
			body = body[:MaxBodyBytes]
		}

		out := &Response{
			URL:        current.String(),
			StatusCode: res.StatusCode,
			Header:     res.Header.Clone(),
			Body:       body,
			FinalHost:  host,
		}
		if res.TLS != nil {
			cs := *res.TLS
			out.TLS = &cs
		}
		last = out

		if res.StatusCode >= 300 && res.StatusCode < 400 {
			loc := res.Header.Get("Location")
			if loc == "" {
				break
			}
			next, err := current.Parse(loc)
			if err != nil {
				break
			}
			if next.Scheme != "http" && next.Scheme != "https" {
				return nil, ErrBlockedTarget
			}
			if next.User != nil || (next.Port() != "" && next.Port() != "80" && next.Port() != "443") {
				return nil, ErrBlockedTarget
			}
			if net.ParseIP(next.Hostname()) != nil {
				return nil, ErrBlockedTarget
			}
			if !sameSite(host, next.Hostname()) {
				return nil, ErrBlockedTarget
			}
			current = next
			continue
		}
		break
	}
	return last, nil
}

func (c *Client) HeadOrGet(ctx context.Context, rawURL string) (*Response, error) {
	return c.Fetch(ctx, rawURL)
}

func sameSite(base, other string) bool {
	base = strings.ToLower(strings.TrimSuffix(base, "."))
	other = strings.ToLower(strings.TrimSuffix(other, "."))
	if base == other {
		return true
	}
	return strings.HasSuffix(other, "."+base)
}

func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
