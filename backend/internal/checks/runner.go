package checks

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	dom "sitechecker/internal/domain"
	"sitechecker/internal/fixes"
	"sitechecker/internal/ssrf"
)

type EventFunc func(evt map[string]any)

type Runner struct {
	Client *ssrf.Client
}

func NewRunner() *Runner {
	return &Runner{Client: ssrf.NewClient()}
}

func (r *Runner) Run(ctx context.Context, domainName string, level int, onEvent EventFunc) ([]dom.Finding, []dom.GroupProgress, error) {
	if level < 1 {
		level = 1
	}
	filesTotal := 1
	if level >= 2 {
		filesTotal = 7
	}
	groups := []dom.GroupProgress{
		{ID: dom.GroupHeaders, State: "pending", Total: 8},
		{ID: dom.GroupTLS, State: "pending", Total: 6},
		{ID: dom.GroupCookie, State: "pending", Total: 4},
		{ID: dom.GroupFiles, State: "pending", Total: filesTotal},
		{ID: dom.GroupSoft, State: "pending", Total: 4},
		{ID: dom.GroupDNS, State: "pending", Total: 6},
	}
	emitProgress := func() {
		if onEvent == nil {
			return
		}
		cp := append([]dom.GroupProgress(nil), groups...)
		onEvent(map[string]any{"type": "progress", "progress": cp})
	}
	setGroup := func(id dom.GroupID, state string, done int) {
		for i := range groups {
			if groups[i].ID == id {
				groups[i].State = state
				groups[i].Done = done
			}
		}
		emitProgress()
	}
	emitProgress()

	httpsURL := "https://" + domainName + "/"
	httpURL := "http://" + domainName + "/"

	var (
		mu       sync.Mutex
		findings []dom.Finding
		httpsRes *ssrf.Response
		httpRes  *ssrf.Response
	)
	add := func(f dom.Finding) {
		if f.Fixes.Nginx == "" && f.Fixes.Apache == "" && f.Fixes.Other == "" &&
			f.Fixes.Cloudflare == "" && f.Fixes.WordPress == "" &&
			f.Fixes.Htaccess == "" && f.Fixes.Traefik == "" && f.Fixes.Caddy == "" {
			f.Fixes = fixes.For(f.ID, domainName)
		} else {
			f.Fixes = fixes.ApplyHost(f.Fixes, domainName)
		}
		mu.Lock()
		findings = append(findings, f)
		mu.Unlock()
		if onEvent != nil {
			onEvent(map[string]any{"type": "finding", "finding": f})
		}
	}

	setGroup(dom.GroupHeaders, "running", 0)
	var err error
	httpsRes, err = r.Client.Fetch(ctx, httpsURL)
	if err != nil {
		httpsRes, err = r.Client.Fetch(ctx, httpURL)
		if err != nil {
			return nil, groups, err
		}
	}
	httpRes, _ = r.Client.FetchNoFollow(ctx, httpURL)

	hdr := httpsRes.Header
	pageURL := httpsRes.URL
	body := string(httpsRes.Body)

	add(checkH1(pageURL, hdr))
	setGroup(dom.GroupHeaders, "running", 1)
	add(checkH2(pageURL, hdr))
	setGroup(dom.GroupHeaders, "running", 2)
	add(checkH3(pageURL, hdr))
	setGroup(dom.GroupHeaders, "running", 3)
	add(checkH4(pageURL, hdr))
	setGroup(dom.GroupHeaders, "running", 4)
	add(checkH5(pageURL, hdr))
	setGroup(dom.GroupHeaders, "running", 5)
	add(checkH6(pageURL, hdr))
	setGroup(dom.GroupHeaders, "running", 6)
	add(checkH7(pageURL, hdr))
	setGroup(dom.GroupHeaders, "running", 7)
	add(checkH8(pageURL, hdr))
	setGroup(dom.GroupHeaders, "done", 8)

	setGroup(dom.GroupTLS, "running", 0)
	add(checkT1(domainName, httpRes, httpsRes))
	setGroup(dom.GroupTLS, "running", 1)
	add(checkT2(pageURL, httpsRes))
	setGroup(dom.GroupTLS, "running", 2)
	add(checkT3(pageURL, httpsRes))
	setGroup(dom.GroupTLS, "running", 3)
	add(checkT4(pageURL, httpsRes))
	setGroup(dom.GroupTLS, "running", 4)
	add(checkT5(pageURL, body, strings.HasPrefix(pageURL, "https://")))
	setGroup(dom.GroupTLS, "running", 5)
	add(checkT6(pageURL, httpsRes))
	setGroup(dom.GroupTLS, "done", 6)

	setGroup(dom.GroupCookie, "running", 0)
	cookies := hdr.Values("Set-Cookie")
	add(checkC1(pageURL, cookies, strings.HasPrefix(pageURL, "https://")))
	setGroup(dom.GroupCookie, "running", 1)
	add(checkC2(pageURL, cookies))
	setGroup(dom.GroupCookie, "running", 2)
	add(checkC3(pageURL, cookies))
	setGroup(dom.GroupCookie, "running", 3)
	add(checkC4(pageURL, cookies))
	setGroup(dom.GroupCookie, "done", 4)

	setGroup(dom.GroupFiles, "running", 0)
	doneFiles := 0
	if level >= 2 {
		add(checkF1(ctx, r.Client, domainName))
		doneFiles++
		setGroup(dom.GroupFiles, "running", doneFiles)
		add(checkF2(ctx, r.Client, domainName))
		doneFiles++
		setGroup(dom.GroupFiles, "running", doneFiles)
		add(checkF3(ctx, r.Client, domainName))
		doneFiles++
		setGroup(dom.GroupFiles, "running", doneFiles)
		add(checkF4(ctx, r.Client, domainName))
		doneFiles++
		setGroup(dom.GroupFiles, "running", doneFiles)
		add(checkF5(ctx, r.Client, domainName))
		doneFiles++
		setGroup(dom.GroupFiles, "running", doneFiles)
		add(checkF6(ctx, r.Client, domainName))
		doneFiles++
		setGroup(dom.GroupFiles, "running", doneFiles)
	}
	add(checkF7(ctx, r.Client, domainName))
	doneFiles++
	setGroup(dom.GroupFiles, "done", doneFiles)

	setGroup(dom.GroupSoft, "running", 0)
	cms := detectCMS(body, hdr)
	add(checkS1(pageURL, cms))
	setGroup(dom.GroupSoft, "running", 1)
	add(checkS2(pageURL, cms))
	setGroup(dom.GroupSoft, "running", 2)
	add(checkS3(pageURL, body))
	setGroup(dom.GroupSoft, "running", 3)
	add(checkS4(pageURL, body))
	setGroup(dom.GroupSoft, "done", 4)

	setGroup(dom.GroupDNS, "running", 0)
	auth, authErr := newAuthDNS(domainName)
	add(checkD1(domainName, auth, authErr))
	setGroup(dom.GroupDNS, "running", 1)
	add(checkD2(domainName, auth))
	setGroup(dom.GroupDNS, "running", 2)
	add(checkD3(domainName, auth, authErr))
	setGroup(dom.GroupDNS, "running", 3)
	add(checkD4(domainName, auth))
	setGroup(dom.GroupDNS, "running", 4)
	add(checkD5(domainName, auth))
	setGroup(dom.GroupDNS, "running", 5)
	add(checkD6(domainName, auth))
	setGroup(dom.GroupDNS, "done", 6)

	return findings, groups, nil
}

func finding(id string, group dom.GroupID, status dom.Status, sev dom.Severity, ev dom.Evidence, source string) dom.Finding {
	return dom.Finding{
		ID: id, Group: group, Status: status, Severity: sev, Evidence: ev,
		TitleKey: "check." + id + ".title", DangerKey: "check." + id + ".danger", SourceURL: source,
	}
}

func headerVal(h map[string][]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

func checkH1(url string, h map[string][]string) dom.Finding {
	v := headerVal(h, "Strict-Transport-Security")
	ev := dom.Evidence{URL: url, Header: "Strict-Transport-Security", Value: ssrf.Truncate(v, 200)}
	if v == "" {
		return finding("H1", dom.GroupHeaders, dom.StatusFail, dom.SeverityHigh, ev, "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security")
	}
	if !strings.Contains(strings.ToLower(v), "max-age=") {
		return finding("H1", dom.GroupHeaders, dom.StatusFail, dom.SeverityHigh, ev, "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security")
	}
	var maxAge int
	fmt.Sscanf(strings.ToLower(v), "max-age=%d", &maxAge)
	re := regexp.MustCompile(`(?i)max-age\s*=\s*(\d+)`)
	if m := re.FindStringSubmatch(v); len(m) == 2 {
		fmt.Sscanf(m[1], "%d", &maxAge)
	}
	if maxAge < 15552000 {
		return finding("H1", dom.GroupHeaders, dom.StatusFail, dom.SeverityHigh, ev, "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security")
	}
	return finding("H1", dom.GroupHeaders, dom.StatusPass, dom.SeverityHigh, ev, "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security")
}

func checkH2(url string, h map[string][]string) dom.Finding {
	v := headerVal(h, "Content-Security-Policy")
	ev := dom.Evidence{URL: url, Header: "Content-Security-Policy", Value: ssrf.Truncate(v, 200)}
	if v == "" {
		return finding("H2", dom.GroupHeaders, dom.StatusFail, dom.SeverityHigh, ev, "https://developer.mozilla.org/docs/Web/HTTP/CSP")
	}
	low := strings.ToLower(v)
	if strings.Contains(low, "'unsafe-inline'") || strings.Contains(low, "'unsafe-eval'") || strings.Contains(low, " *") || strings.HasSuffix(low, "*") || strings.Contains(low, " *;") {
		return finding("H2", dom.GroupHeaders, dom.StatusFail, dom.SeverityHigh, ev, "https://developer.mozilla.org/docs/Web/HTTP/CSP")
	}
	return finding("H2", dom.GroupHeaders, dom.StatusPass, dom.SeverityHigh, ev, "https://developer.mozilla.org/docs/Web/HTTP/CSP")
}

func checkH3(url string, h map[string][]string) dom.Finding {
	xfo := headerVal(h, "X-Frame-Options")
	csp := headerVal(h, "Content-Security-Policy")
	ev := dom.Evidence{URL: url, Header: "X-Frame-Options", Value: ssrf.Truncate(xfo, 200)}
	if xfo == "" && !strings.Contains(strings.ToLower(csp), "frame-ancestors") {
		return finding("H3", dom.GroupHeaders, dom.StatusFail, dom.SeverityMedium, ev, "https://owasp.org/www-community/attacks/Clickjacking")
	}
	return finding("H3", dom.GroupHeaders, dom.StatusPass, dom.SeverityMedium, ev, "https://owasp.org/www-community/attacks/Clickjacking")
}

func checkH4(url string, h map[string][]string) dom.Finding {
	v := headerVal(h, "X-Content-Type-Options")
	ev := dom.Evidence{URL: url, Header: "X-Content-Type-Options", Value: ssrf.Truncate(v, 200)}
	if !strings.EqualFold(v, "nosniff") {
		return finding("H4", dom.GroupHeaders, dom.StatusFail, dom.SeverityMedium, ev, "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options")
	}
	return finding("H4", dom.GroupHeaders, dom.StatusPass, dom.SeverityMedium, ev, "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options")
}

func checkH5(url string, h map[string][]string) dom.Finding {
	v := headerVal(h, "Referrer-Policy")
	ev := dom.Evidence{URL: url, Header: "Referrer-Policy", Value: ssrf.Truncate(v, 200)}
	if v == "" {
		return finding("H5", dom.GroupHeaders, dom.StatusFail, dom.SeverityLow, ev, "https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy")
	}
	return finding("H5", dom.GroupHeaders, dom.StatusPass, dom.SeverityLow, ev, "https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy")
}

func checkH6(url string, h map[string][]string) dom.Finding {
	v := headerVal(h, "Permissions-Policy")
	if v == "" {
		v = headerVal(h, "Feature-Policy")
	}
	ev := dom.Evidence{URL: url, Header: "Permissions-Policy", Value: ssrf.Truncate(v, 200)}
	if v == "" {
		return finding("H6", dom.GroupHeaders, dom.StatusFail, dom.SeverityLow, ev, "https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy")
	}
	return finding("H6", dom.GroupHeaders, dom.StatusPass, dom.SeverityLow, ev, "https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy")
}

func checkH7(url string, h map[string][]string) dom.Finding {
	verRE := regexp.MustCompile(`\d+\.\d+`)
	var leaks []string
	for _, name := range []string{"Server", "X-Powered-By", "X-AspNet-Version"} {
		v := headerVal(h, name)
		if verRE.MatchString(v) {
			leaks = append(leaks, name+": "+v)
		}
	}
	ev := dom.Evidence{URL: url, Detail: ssrf.Truncate(strings.Join(leaks, "; "), 200)}
	if len(leaks) > 0 {
		return finding("H7", dom.GroupHeaders, dom.StatusFail, dom.SeverityLow, ev, "https://owasp.org/www-project-secure-headers/")
	}
	return finding("H7", dom.GroupHeaders, dom.StatusPass, dom.SeverityLow, ev, "https://owasp.org/www-project-secure-headers/")
}

func checkH8(url string, h map[string][]string) dom.Finding {
	acao := headerVal(h, "Access-Control-Allow-Origin")
	acac := headerVal(h, "Access-Control-Allow-Credentials")
	ev := dom.Evidence{URL: url, Header: "Access-Control-Allow-Origin", Value: ssrf.Truncate(acao, 200)}
	if acao == "*" && strings.EqualFold(acac, "true") {
		return finding("H8", dom.GroupHeaders, dom.StatusFail, dom.SeverityHigh, ev, "https://developer.mozilla.org/docs/Web/HTTP/CORS")
	}
	return finding("H8", dom.GroupHeaders, dom.StatusPass, dom.SeverityHigh, ev, "https://developer.mozilla.org/docs/Web/HTTP/CORS")
}

func checkT1(domain string, httpRes, httpsRes *ssrf.Response) dom.Finding {
	ev := dom.Evidence{URL: "http://" + domain + "/", Detail: "HTTP to HTTPS redirect"}
	if httpRes == nil {
		return finding("T1", dom.GroupTLS, dom.StatusError, dom.SeverityHigh, ev, "https://developer.mozilla.org/docs/Glossary/HTTPS")
	}
	if httpRes.StatusCode >= 300 && httpRes.StatusCode < 400 {
		loc := httpRes.Header.Get("Location")
		if strings.HasPrefix(strings.ToLower(loc), "https://") {
			return finding("T1", dom.GroupTLS, dom.StatusPass, dom.SeverityHigh, dom.Evidence{URL: ev.URL, Value: ssrf.Truncate(loc, 200)}, "https://developer.mozilla.org/docs/Glossary/HTTPS")
		}
	}
	if httpsRes != nil && strings.HasPrefix(httpsRes.URL, "https://") && httpRes.StatusCode == 200 {
		return finding("T1", dom.GroupTLS, dom.StatusFail, dom.SeverityHigh, ev, "https://developer.mozilla.org/docs/Glossary/HTTPS")
	}
	if httpRes.StatusCode == 200 {
		return finding("T1", dom.GroupTLS, dom.StatusFail, dom.SeverityHigh, ev, "https://developer.mozilla.org/docs/Glossary/HTTPS")
	}
	return finding("T1", dom.GroupTLS, dom.StatusWarn, dom.SeverityHigh, ev, "https://developer.mozilla.org/docs/Glossary/HTTPS")
}

func checkT2(url string, res *ssrf.Response) dom.Finding {
	ev := dom.Evidence{URL: url, Detail: "TLS certificate"}
	if res == nil || res.TLS == nil || len(res.TLS.PeerCertificates) == 0 {
		return finding("T2", dom.GroupTLS, dom.StatusFail, dom.SeverityCritical, ev, "https://developer.mozilla.org/docs/Web/Security/Transport_Layer_Security")
	}
	cert := res.TLS.PeerCertificates[0]
	remain := time.Until(cert.NotAfter)
	ev.Detail = ssrf.Truncate(fmt.Sprintf("notAfter=%s subject=%s", cert.NotAfter.Format(time.RFC3339), cert.Subject.CommonName), 200)
	if remain < 14*24*time.Hour {
		return finding("T2", dom.GroupTLS, dom.StatusFail, dom.SeverityCritical, ev, "https://developer.mozilla.org/docs/Web/Security/Transport_Layer_Security")
	}
	if len(res.TLS.VerifiedChains) == 0 && res.TLS.HandshakeComplete {
		// may be insecure skip; we don't skip verify by default
	}
	return finding("T2", dom.GroupTLS, dom.StatusPass, dom.SeverityCritical, ev, "https://developer.mozilla.org/docs/Web/Security/Transport_Layer_Security")
}

func checkT3(url string, res *ssrf.Response) dom.Finding {
	ev := dom.Evidence{URL: url, Detail: "TLS version"}
	if res == nil || res.TLS == nil {
		return finding("T3", dom.GroupTLS, dom.StatusError, dom.SeverityHigh, ev, "https://datatracker.ietf.org/doc/html/rfc8446")
	}
	ver := res.TLS.Version
	ev.Value = tlsVersionName(ver)
	if ver == tls.VersionTLS10 || ver == tls.VersionTLS11 {
		return finding("T3", dom.GroupTLS, dom.StatusFail, dom.SeverityHigh, ev, "https://datatracker.ietf.org/doc/html/rfc8446")
	}
	if ver < tls.VersionTLS12 {
		return finding("T3", dom.GroupTLS, dom.StatusFail, dom.SeverityHigh, ev, "https://datatracker.ietf.org/doc/html/rfc8446")
	}
	return finding("T3", dom.GroupTLS, dom.StatusPass, dom.SeverityHigh, ev, "https://datatracker.ietf.org/doc/html/rfc8446")
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}

func checkT4(url string, res *ssrf.Response) dom.Finding {
	ev := dom.Evidence{URL: url, Detail: "cipher suite"}
	if res == nil || res.TLS == nil {
		return finding("T4", dom.GroupTLS, dom.StatusError, dom.SeverityHigh, ev, "https://ssl-config.mozilla.org/")
	}
	name := tls.CipherSuiteName(res.TLS.CipherSuite)
	ev.Value = name
	low := strings.ToLower(name)
	bad := []string{"rc4", "3des", "export", "null", "anon"}
	for _, b := range bad {
		if strings.Contains(low, b) {
			return finding("T4", dom.GroupTLS, dom.StatusFail, dom.SeverityHigh, ev, "https://ssl-config.mozilla.org/")
		}
	}
	return finding("T4", dom.GroupTLS, dom.StatusPass, dom.SeverityHigh, ev, "https://ssl-config.mozilla.org/")
}

func checkT5(url, body string, isHTTPS bool) dom.Finding {
	ev := dom.Evidence{URL: url, Detail: "mixed content"}
	if !isHTTPS {
		return finding("T5", dom.GroupTLS, dom.StatusInfo, dom.SeverityMedium, ev, "https://developer.mozilla.org/docs/Web/Security/Mixed_content")
	}
	re := regexp.MustCompile(`(?i)(src|href)=["']http://[^"']+`)
	if re.MatchString(body) {
		m := re.FindString(body)
		ev.Value = ssrf.Truncate(m, 200)
		return finding("T5", dom.GroupTLS, dom.StatusFail, dom.SeverityMedium, ev, "https://developer.mozilla.org/docs/Web/Security/Mixed_content")
	}
	return finding("T5", dom.GroupTLS, dom.StatusPass, dom.SeverityMedium, ev, "https://developer.mozilla.org/docs/Web/Security/Mixed_content")
}

func checkT6(url string, res *ssrf.Response) dom.Finding {
	ev := dom.Evidence{URL: url, Detail: "HTTP/2 and HTTP/3 support (informational)"}
	if res == nil || res.TLS == nil {
		return finding("T6", dom.GroupTLS, dom.StatusInfo, dom.SeverityInfo, ev, "https://developer.mozilla.org/docs/Glossary/HTTP_2")
	}
	ev.Value = res.TLS.NegotiatedProtocol
	if res.TLS.NegotiatedProtocol == "h2" || res.TLS.NegotiatedProtocol == "h3" {
		return finding("T6", dom.GroupTLS, dom.StatusPass, dom.SeverityInfo, ev, "https://developer.mozilla.org/docs/Glossary/HTTP_2")
	}
	return finding("T6", dom.GroupTLS, dom.StatusInfo, dom.SeverityInfo, ev, "https://developer.mozilla.org/docs/Glossary/HTTP_2")
}

func checkC1(url string, cookies []string, https bool) dom.Finding {
	ev := dom.Evidence{URL: url, Header: "Set-Cookie"}
	if !https || len(cookies) == 0 {
		return finding("C1", dom.GroupCookie, dom.StatusPass, dom.SeverityHigh, ev, "https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie")
	}
	for _, c := range cookies {
		if !strings.Contains(strings.ToLower(c), "secure") {
			ev.Value = ssrf.Truncate(c, 200)
			return finding("C1", dom.GroupCookie, dom.StatusFail, dom.SeverityHigh, ev, "https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie")
		}
	}
	return finding("C1", dom.GroupCookie, dom.StatusPass, dom.SeverityHigh, ev, "https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie")
}

func isSessionCookie(c string) bool {
	low := strings.ToLower(c)
	return strings.Contains(low, "session") || strings.Contains(low, "sid") || strings.Contains(low, "auth") || strings.Contains(low, "token") || strings.Contains(low, "phpsessid") || strings.Contains(low, "wordpress_")
}

func checkC2(url string, cookies []string) dom.Finding {
	ev := dom.Evidence{URL: url, Header: "Set-Cookie"}
	for _, c := range cookies {
		if isSessionCookie(c) && !strings.Contains(strings.ToLower(c), "httponly") {
			ev.Value = ssrf.Truncate(c, 200)
			return finding("C2", dom.GroupCookie, dom.StatusFail, dom.SeverityHigh, ev, "https://owasp.org/www-community/HttpOnly")
		}
	}
	return finding("C2", dom.GroupCookie, dom.StatusPass, dom.SeverityHigh, ev, "https://owasp.org/www-community/HttpOnly")
}

func checkC3(url string, cookies []string) dom.Finding {
	ev := dom.Evidence{URL: url, Header: "Set-Cookie"}
	for _, c := range cookies {
		if !strings.Contains(strings.ToLower(c), "samesite") {
			ev.Value = ssrf.Truncate(c, 200)
			return finding("C3", dom.GroupCookie, dom.StatusFail, dom.SeverityMedium, ev, "https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie/SameSite")
		}
	}
	return finding("C3", dom.GroupCookie, dom.StatusPass, dom.SeverityMedium, ev, "https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie/SameSite")
}

func checkC4(url string, cookies []string) dom.Finding {
	ev := dom.Evidence{URL: url, Header: "Set-Cookie", Detail: "Recommend __Host- / __Secure- prefixes for session cookies"}
	hasSession := false
	hasPrefix := false
	for _, c := range cookies {
		if isSessionCookie(c) {
			hasSession = true
			name := strings.SplitN(c, "=", 2)[0]
			if strings.HasPrefix(name, "__Host-") || strings.HasPrefix(name, "__Secure-") {
				hasPrefix = true
			}
		}
	}
	if hasSession && !hasPrefix {
		return finding("C4", dom.GroupCookie, dom.StatusInfo, dom.SeverityInfo, ev, "https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie#cookie_prefixes")
	}
	return finding("C4", dom.GroupCookie, dom.StatusPass, dom.SeverityInfo, ev, "https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie#cookie_prefixes")
}

func probeURL(ctx context.Context, client *ssrf.Client, domain, path string) (*ssrf.Response, string) {
	for _, scheme := range []string{"https", "http"} {
		u := scheme + "://" + domain + path
		res, err := client.Fetch(ctx, u)
		if err != nil {
			continue
		}
		return res, u
	}
	return nil, "https://" + domain + path
}

func bodyLooksHTML(b []byte) bool {
	low := strings.ToLower(string(b))
	return strings.Contains(low, "<html") || strings.Contains(low, "<!doctype")
}

func exposedOK(res *ssrf.Response) bool {
	return res != nil && res.StatusCode == 200 && len(res.Body) > 0
}

func checkF1(ctx context.Context, client *ssrf.Client, domain string) dom.Finding {
	res, u := probeURL(ctx, client, domain, "/.git/HEAD")
	ev := dom.Evidence{URL: u, Detail: ".git/HEAD"}
	if exposedOK(res) {
		body := strings.TrimSpace(string(res.Body))
		ev.Value = ssrf.Truncate(body, 200)
		if strings.HasPrefix(body, "ref:") || body == "ref: refs/heads/master" || strings.HasPrefix(body, "ref: refs/") {
			return finding("F1", dom.GroupFiles, dom.StatusFail, dom.SeverityCritical, ev, "https://owasp.org/www-community/vulnerabilities/Source_code_disclosure")
		}
		if !bodyLooksHTML(res.Body) && len(body) < 200 {
			return finding("F1", dom.GroupFiles, dom.StatusFail, dom.SeverityCritical, ev, "https://owasp.org/www-community/vulnerabilities/Source_code_disclosure")
		}
	}
	return finding("F1", dom.GroupFiles, dom.StatusPass, dom.SeverityCritical, ev, "https://owasp.org/www-community/vulnerabilities/Source_code_disclosure")
}

func checkF2(ctx context.Context, client *ssrf.Client, domain string) dom.Finding {
	paths := []string{"/.env", "/wp-config.php.bak", "/config.php.old"}
	ev := dom.Evidence{Detail: "env/config backups"}
	for _, p := range paths {
		res, u := probeURL(ctx, client, domain, p)
		if !exposedOK(res) || bodyLooksHTML(res.Body) {
			continue
		}
		body := string(res.Body)
		low := strings.ToLower(body)
		if strings.Contains(body, "=") || strings.Contains(low, "db_") || strings.Contains(low, "password") || strings.Contains(low, "define(") {
			ev.URL = u
			ev.Value = ssrf.Truncate(strings.TrimSpace(body), 200)
			return finding("F2", dom.GroupFiles, dom.StatusFail, dom.SeverityCritical, ev, "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url")
		}
	}
	ev.URL = "https://" + domain + "/.env"
	return finding("F2", dom.GroupFiles, dom.StatusPass, dom.SeverityCritical, ev, "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url")
}

func checkF3(ctx context.Context, client *ssrf.Client, domain string) dom.Finding {
	paths := []string{"/backup.zip", "/dump.sql", "/db.sql"}
	ev := dom.Evidence{Detail: "backup dumps"}
	for _, p := range paths {
		res, u := probeURL(ctx, client, domain, p)
		if res == nil || res.StatusCode != 200 || len(res.Body) < 4 {
			continue
		}
		if bodyLooksHTML(res.Body) {
			continue
		}
		ct := strings.ToLower(headerVal(res.Header, "Content-Type"))
		body := res.Body
		isZip := len(body) >= 2 && body[0] == 'P' && body[1] == 'K'
		isSQL := strings.Contains(strings.ToLower(string(body[:min(200, len(body))])), "create table") ||
			strings.Contains(ct, "sql") || strings.HasSuffix(p, ".sql")
		isArchive := isZip || strings.Contains(ct, "zip") || strings.Contains(ct, "octet-stream")
		if isZip || (isSQL && !bodyLooksHTML(body)) || (isArchive && len(body) > 512) {
			ev.URL = u
			ev.Value = ssrf.Truncate(ct+" "+string(body[:min(40, len(body))]), 200)
			return finding("F3", dom.GroupFiles, dom.StatusFail, dom.SeverityCritical, ev, "https://owasp.org/www-project-web-security-testing-guide/")
		}
	}
	ev.URL = "https://" + domain + "/backup.zip"
	return finding("F3", dom.GroupFiles, dom.StatusPass, dom.SeverityCritical, ev, "https://owasp.org/www-project-web-security-testing-guide/")
}

func checkF4(ctx context.Context, client *ssrf.Client, domain string) dom.Finding {
	paths := []string{"/phpinfo.php", "/server-status", "/info.php"}
	ev := dom.Evidence{Detail: "diagnostic pages"}
	for _, p := range paths {
		res, u := probeURL(ctx, client, domain, p)
		if !exposedOK(res) {
			continue
		}
		low := strings.ToLower(string(res.Body))
		if strings.Contains(low, "phpinfo()") || strings.Contains(low, "php version") ||
			strings.Contains(low, "apache server status") || strings.Contains(low, "server-info") ||
			strings.Contains(low, "scoreboard") {
			ev.URL = u
			ev.Value = ssrf.Truncate(strings.TrimSpace(string(res.Body)), 200)
			return finding("F4", dom.GroupFiles, dom.StatusFail, dom.SeverityHigh, ev, "https://owasp.org/www-project-web-security-testing-guide/")
		}
	}
	ev.URL = "https://" + domain + "/phpinfo.php"
	return finding("F4", dom.GroupFiles, dom.StatusPass, dom.SeverityHigh, ev, "https://owasp.org/www-project-web-security-testing-guide/")
}

func checkF5(ctx context.Context, client *ssrf.Client, domain string) dom.Finding {
	paths := []string{"/uploads/", "/files/", "/backup/"}
	ev := dom.Evidence{Detail: "directory listing"}
	for _, p := range paths {
		res, u := probeURL(ctx, client, domain, p)
		if !exposedOK(res) {
			continue
		}
		low := strings.ToLower(string(res.Body))
		if strings.Contains(low, "index of /") || strings.Contains(low, "directory listing") ||
			strings.Contains(low, "<title>index of") {
			ev.URL = u
			ev.Value = ssrf.Truncate(strings.TrimSpace(string(res.Body)), 200)
			return finding("F5", dom.GroupFiles, dom.StatusFail, dom.SeverityMedium, ev, "https://owasp.org/www-community/vulnerabilities/Directory_listing")
		}
	}
	ev.URL = "https://" + domain + "/uploads/"
	return finding("F5", dom.GroupFiles, dom.StatusPass, dom.SeverityMedium, ev, "https://owasp.org/www-community/vulnerabilities/Directory_listing")
}

func checkF6(ctx context.Context, client *ssrf.Client, domain string) dom.Finding {
	paths := []string{"/phpmyadmin/", "/adminer.php"}
	ev := dom.Evidence{Detail: "admin panels"}
	for _, p := range paths {
		res, u := probeURL(ctx, client, domain, p)
		if res == nil || res.StatusCode >= 400 {
			continue
		}
		if res.StatusCode == 401 || res.StatusCode == 403 {
			continue
		}
		low := strings.ToLower(string(res.Body))
		if strings.Contains(low, "phpmyadmin") || strings.Contains(low, "adminer") ||
			(res.StatusCode == 200 && (strings.Contains(low, "mysql") && strings.Contains(low, "login"))) {
			ev.URL = u
			ev.Value = ssrf.Truncate(strings.TrimSpace(string(res.Body)), 200)
			return finding("F6", dom.GroupFiles, dom.StatusFail, dom.SeverityMedium, ev, "https://owasp.org/www-project-web-security-testing-guide/")
		}
	}
	ev.URL = "https://" + domain + "/phpmyadmin/"
	return finding("F6", dom.GroupFiles, dom.StatusPass, dom.SeverityMedium, ev, "https://owasp.org/www-project-web-security-testing-guide/")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func checkF7(ctx context.Context, client *ssrf.Client, domain string) dom.Finding {
	u := "https://" + domain + "/.well-known/security.txt"
	ev := dom.Evidence{URL: u}
	res, err := client.Fetch(ctx, u)
	if err != nil || res.StatusCode >= 400 {
		res2, err2 := client.Fetch(ctx, "http://"+domain+"/.well-known/security.txt")
		if err2 != nil || res2.StatusCode >= 400 {
			return finding("F7", dom.GroupFiles, dom.StatusInfo, dom.SeverityInfo, ev, "https://datatracker.ietf.org/doc/html/rfc9116")
		}
		res = res2
	}
	ev.Value = ssrf.Truncate(string(res.Body), 200)
	if res.StatusCode == 200 && strings.Contains(strings.ToLower(string(res.Body)), "contact:") {
		return finding("F7", dom.GroupFiles, dom.StatusPass, dom.SeverityInfo, ev, "https://datatracker.ietf.org/doc/html/rfc9116")
	}
	return finding("F7", dom.GroupFiles, dom.StatusInfo, dom.SeverityInfo, ev, "https://datatracker.ietf.org/doc/html/rfc9116")
}

type cmsInfo struct {
	Name    string
	Version string
}

func detectCMS(body string, h map[string][]string) cmsInfo {
	low := strings.ToLower(body)
	gen := strings.ToLower(headerVal(h, "X-Generator") + " " + headerVal(h, "X-Powered-By"))
	info := cmsInfo{}
	switch {
	case strings.Contains(low, "wp-content") || strings.Contains(low, "wordpress") || strings.Contains(gen, "wordpress"):
		info.Name = "WordPress"
		if m := regexp.MustCompile(`(?i)wordpress\s*([0-9]+\.[0-9.]+)`).FindStringSubmatch(body); len(m) == 2 {
			info.Version = m[1]
		}
	case strings.Contains(low, "/media/jui/") || strings.Contains(low, "joomla"):
		info.Name = "Joomla"
	case strings.Contains(low, "drupal") || strings.Contains(low, "sites/default/files"):
		info.Name = "Drupal"
	case strings.Contains(low, "bitrix") || strings.Contains(low, "/bitrix/"):
		info.Name = "Bitrix"
	case strings.Contains(low, "magento") || strings.Contains(low, "mage/cookies"):
		info.Name = "Magento"
	}
	return info
}

func checkS1(url string, cms cmsInfo) dom.Finding {
	ev := dom.Evidence{URL: url, Detail: "CMS fingerprint"}
	if cms.Name == "" {
		ev.Value = "unknown"
		return finding("S1", dom.GroupSoft, dom.StatusInfo, dom.SeverityInfo, ev, "")
	}
	ev.Value = ssrf.Truncate(cms.Name+" "+cms.Version, 200)
	return finding("S1", dom.GroupSoft, dom.StatusInfo, dom.SeverityInfo, ev, "")
}

func checkS2(url string, cms cmsInfo) dom.Finding {
	ev := dom.Evidence{URL: url, Detail: "Known vulnerable CMS version (local snapshot)"}
	// Minimal built-in snapshot; full NVD sync is a daily job.
	vuln := map[string][]string{
		"WordPress": {"4.", "5.0", "5.1", "5.2", "5.3", "5.4", "5.5", "5.6", "5.7", "5.8"},
	}
	if cms.Name != "" && cms.Version != "" {
		for _, p := range vuln[cms.Name] {
			if strings.HasPrefix(cms.Version, p) {
				ev.Value = cms.Name + " " + cms.Version
				return finding("S2", dom.GroupSoft, dom.StatusFail, dom.SeverityHigh, ev, "https://nvd.nist.gov/")
			}
		}
	}
	if cms.Name == "" || cms.Version == "" {
		return finding("S2", dom.GroupSoft, dom.StatusInfo, dom.SeverityHigh, ev, "https://nvd.nist.gov/")
	}
	return finding("S2", dom.GroupSoft, dom.StatusPass, dom.SeverityHigh, ev, "https://nvd.nist.gov/")
}

func checkS3(url, body string) dom.Finding {
	ev := dom.Evidence{URL: url, Detail: "outdated JS libraries"}
	patterns := []struct {
		re  *regexp.Regexp
		bad func(maj, min int) bool
		lab string
	}{
		{regexp.MustCompile(`(?i)jquery(?:[.-]|@)([0-9]+)\.([0-9]+)`), func(maj, min int) bool { return maj < 3 || (maj == 3 && min < 5) }, "jQuery"},
		{regexp.MustCompile(`(?i)bootstrap(?:[.-]|@)([0-9]+)\.([0-9]+)`), func(maj, min int) bool { return maj < 4 || (maj == 4 && min < 3) }, "Bootstrap"},
	}
	for _, p := range patterns {
		if m := p.re.FindStringSubmatch(body); len(m) >= 3 {
			var maj, min int
			fmt.Sscanf(m[1], "%d", &maj)
			fmt.Sscanf(m[2], "%d", &min)
			ev.Value = ssrf.Truncate(p.lab+" "+m[1]+"."+m[2], 200)
			if p.bad(maj, min) {
				return finding("S3", dom.GroupSoft, dom.StatusFail, dom.SeverityMedium, ev, "https://owasp.org/www-project-top-ten/")
			}
		}
	}
	return finding("S3", dom.GroupSoft, dom.StatusPass, dom.SeverityMedium, ev, "https://owasp.org/www-project-top-ten/")
}

func checkS4(url, body string) dom.Finding {
	ev := dom.Evidence{URL: url, Detail: "Subresource Integrity"}
	re := regexp.MustCompile(`(?i)<script[^>]+src=["']https?://[^"']+["'][^>]*>`)
	scripts := re.FindAllString(body, 20)
	for _, s := range scripts {
		if !strings.Contains(strings.ToLower(s), "integrity=") {
			ev.Value = ssrf.Truncate(s, 200)
			return finding("S4", dom.GroupSoft, dom.StatusFail, dom.SeverityLow, ev, "https://developer.mozilla.org/docs/Web/Security/Subresource_Integrity")
		}
	}
	return finding("S4", dom.GroupSoft, dom.StatusPass, dom.SeverityLow, ev, "https://developer.mozilla.org/docs/Web/Security/Subresource_Integrity")
}

func dnsDetail(kind, name string, auth *authDNS) string {
	detail := kind + " " + name
	if auth != nil {
		if label := auth.NSLabel(); label != "" {
			detail += " via NS " + label
		}
	}
	return detail
}

func checkD1(domain string, auth *authDNS, authErr error) dom.Finding {
	name := domain
	ev := dom.Evidence{Detail: dnsDetail("TXT", name, auth)}
	if auth == nil && authErr != nil {
		ev.Value = "NS lookup failed: " + ssrf.Truncate(authErr.Error(), 120)
		return finding("D1", dom.GroupDNS, dom.StatusError, dom.SeverityMedium, ev, "https://datatracker.ietf.org/doc/html/rfc7208")
	}
	txts, err := auth.LookupTXT(context.Background(), name)
	if err != nil {
		ev.Value = "lookup failed: " + ssrf.Truncate(err.Error(), 120)
		return finding("D1", dom.GroupDNS, dom.StatusError, dom.SeverityMedium, ev, "https://datatracker.ietf.org/doc/html/rfc7208")
	}
	var spf string
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
			spf = t
			break
		}
	}
	if spf == "" {
		ev.Value = "no v=spf1 record"
		return finding("D1", dom.GroupDNS, dom.StatusFail, dom.SeverityMedium, ev, "https://datatracker.ietf.org/doc/html/rfc7208")
	}
	ev.Value = ssrf.Truncate(spf, 200)
	if strings.Contains(strings.ToLower(spf), "+all") {
		ev.Detail = dnsDetail("TXT", name, auth) + " (+all allows any host)"
		return finding("D1", dom.GroupDNS, dom.StatusFail, dom.SeverityMedium, ev, "https://datatracker.ietf.org/doc/html/rfc7208")
	}
	return finding("D1", dom.GroupDNS, dom.StatusPass, dom.SeverityMedium, ev, "https://datatracker.ietf.org/doc/html/rfc7208")
}

func checkD2(domain string, auth *authDNS) dom.Finding {
	selectors := []string{"default", "google", "selector1", "selector2", "k1", "s1", "dkim"}
	ev := dom.Evidence{Detail: dnsDetail("TXT", "<selector>._domainkey."+domain, auth)}
	if auth == nil {
		ev.Value = "no DKIM among selectors: " + strings.Join(selectors, ", ")
		return finding("D2", dom.GroupDNS, dom.StatusInfo, dom.SeverityInfo, ev, "https://datatracker.ietf.org/doc/html/rfc6376")
	}
	found := ""
	for _, s := range selectors {
		host := s + "._domainkey." + domain
		txts, err := auth.LookupTXT(context.Background(), host)
		if err != nil {
			continue
		}
		for _, t := range txts {
			if strings.Contains(strings.ToLower(t), "v=dkim1") || strings.Contains(t, "p=") {
				found = s
				ev.Detail = dnsDetail("TXT", host, auth)
				ev.Value = ssrf.Truncate(t, 200)
				break
			}
		}
		if found != "" {
			break
		}
	}
	if found == "" {
		ev.Value = "no DKIM among selectors: " + strings.Join(selectors, ", ")
		return finding("D2", dom.GroupDNS, dom.StatusInfo, dom.SeverityInfo, ev, "https://datatracker.ietf.org/doc/html/rfc6376")
	}
	return finding("D2", dom.GroupDNS, dom.StatusPass, dom.SeverityInfo, ev, "https://datatracker.ietf.org/doc/html/rfc6376")
}

func checkD3(domain string, auth *authDNS, authErr error) dom.Finding {
	name := "_dmarc." + domain
	ev := dom.Evidence{Detail: dnsDetail("TXT", name, auth)}
	if auth == nil && authErr != nil {
		ev.Value = "NS lookup failed: " + ssrf.Truncate(authErr.Error(), 120)
		return finding("D3", dom.GroupDNS, dom.StatusError, dom.SeverityMedium, ev, "https://datatracker.ietf.org/doc/html/rfc7489")
	}
	txts, err := auth.LookupTXT(context.Background(), name)
	if err != nil {
		ev.Value = "lookup failed: " + ssrf.Truncate(err.Error(), 120)
		return finding("D3", dom.GroupDNS, dom.StatusError, dom.SeverityMedium, ev, "https://datatracker.ietf.org/doc/html/rfc7489")
	}
	var rec string
	for _, t := range txts {
		if strings.Contains(strings.ToLower(t), "v=dmarc1") {
			rec = t
			break
		}
	}
	if rec == "" {
		ev.Value = "no v=DMARC1 record"
		return finding("D3", dom.GroupDNS, dom.StatusFail, dom.SeverityMedium, ev, "https://datatracker.ietf.org/doc/html/rfc7489")
	}
	ev.Value = ssrf.Truncate(rec, 200)
	if strings.Contains(strings.ToLower(rec), "p=none") {
		ev.Detail = dnsDetail("TXT", name, auth) + " (p=none = monitor only)"
		return finding("D3", dom.GroupDNS, dom.StatusFail, dom.SeverityMedium, ev, "https://datatracker.ietf.org/doc/html/rfc7489")
	}
	return finding("D3", dom.GroupDNS, dom.StatusPass, dom.SeverityMedium, ev, "https://datatracker.ietf.org/doc/html/rfc7489")
}

func checkD4(domain string, auth *authDNS) dom.Finding {
	ev := dom.Evidence{Detail: dnsDetail("DNSSEC", domain, auth)}
	var err error
	if auth != nil {
		_, err = auth.LookupIP(context.Background(), domain)
	} else {
		_, err = net.LookupIP(domain)
	}
	if err != nil {
		return finding("D4", dom.GroupDNS, dom.StatusError, dom.SeverityInfo, ev, "https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en")
	}
	ev.Value = "not verified by validating resolver in MVP"
	return finding("D4", dom.GroupDNS, dom.StatusInfo, dom.SeverityInfo, ev, "https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en")
}

func checkD5(domain string, auth *authDNS) dom.Finding {
	ev := dom.Evidence{Detail: dnsDetail("CAA", domain, auth)}
	var err error
	if auth != nil {
		_, err = auth.LookupIP(context.Background(), domain)
	} else {
		_, err = net.LookupHost(domain)
	}
	if err != nil {
		return finding("D5", dom.GroupDNS, dom.StatusError, dom.SeverityInfo, ev, "https://datatracker.ietf.org/doc/html/rfc8659")
	}
	ev.Value = "CAA records not enumerated in MVP resolver"
	return finding("D5", dom.GroupDNS, dom.StatusInfo, dom.SeverityInfo, ev, "https://datatracker.ietf.org/doc/html/rfc8659")
}

func checkD6(domain string, auth *authDNS) dom.Finding {
	ev := dom.Evidence{Detail: dnsDetail("CNAME", "common subdomains", auth)}
	subs := []string{"www", "mail", "ftp", "dev", "staging", "cdn", "static"}
	for _, s := range subs {
		host := s + "." + domain
		var cname string
		var err error
		if auth != nil {
			cname, err = auth.LookupCNAME(context.Background(), host)
		} else {
			cname, err = net.LookupCNAME(host)
		}
		if err != nil || cname == "" || strings.EqualFold(cname, host+".") {
			continue
		}
		cname = strings.TrimSuffix(cname, ".")
		if looksExternalDangling(cname) {
			var ips []net.IP
			if auth != nil {
				ips, err = auth.LookupIP(context.Background(), host)
			} else {
				ips, err = net.LookupIP(host)
			}
			if err != nil || len(ips) == 0 {
				ev.Value = ssrf.Truncate(host+" -> "+cname, 200)
				return finding("D6", dom.GroupDNS, dom.StatusFail, dom.SeverityHigh, ev, "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery")
			}
		}
	}
	return finding("D6", dom.GroupDNS, dom.StatusPass, dom.SeverityHigh, ev, "")
}

func looksExternalDangling(cname string) bool {
	low := strings.ToLower(cname)
	needles := []string{"amazonaws.com", "cloudfront.net", "azurewebsites.net", "herokuapp.com", "github.io", "shopify.com", "zendesk.com", "ghost.io"}
	for _, n := range needles {
		if strings.Contains(low, n) {
			return true
		}
	}
	return false
}

func isOptOutTXT(value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	v = strings.Trim(v, `"'`)
	switch v {
	case "1", "true", "yes", "optout", "opt-out", "sitechecker-optout":
		return true
	}
	return strings.Contains(v, "sitechecker-optout")
}

func OptedOut(domain string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resolver := &net.Resolver{}
	txts, err := resolver.LookupTXT(ctx, "_sitechecker-optout."+domain)
	if err != nil {
		return false
	}
	for _, t := range txts {
		if isOptOutTXT(t) {
			return true
		}
	}
	return false
}

func CheckSecurityTxtOptOut(ctx context.Context, client *ssrf.Client, domain string) bool {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	res, err := client.Fetch(ctx, "https://"+domain+"/.well-known/security.txt")
	if err != nil || res.StatusCode >= 400 {
		return false
	}
	body := strings.ToLower(string(res.Body))
	// Ignore HTML login/landing pages that many sites return for missing security.txt.
	if strings.Contains(body, "<html") || strings.Contains(body, "<!doctype") {
		return false
	}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "x-sitechecker-optout:") || line == "sitechecker-optout" {
			return true
		}
		if strings.Contains(line, "sitechecker-optout") && !strings.HasPrefix(line, "#") {
			return true
		}
	}
	return false
}
