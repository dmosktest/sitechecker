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

func (r *Runner) Run(ctx context.Context, domainName string, onEvent EventFunc) ([]dom.Finding, []dom.GroupProgress, error) {
	groups := []dom.GroupProgress{
		{ID: dom.GroupHeaders, State: "pending", Total: 8},
		{ID: dom.GroupTLS, State: "pending", Total: 6},
		{ID: dom.GroupCookie, State: "pending", Total: 4},
		{ID: dom.GroupFiles, State: "pending", Total: 1},
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
		if f.Fixes.Nginx == "" && f.Fixes.Apache == "" && f.Fixes.Other == "" {
			f.Fixes = fixes.For(f.ID)
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
	httpRes, _ = r.Client.Fetch(ctx, httpURL)

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
	add(checkF7(ctx, r.Client, domainName))
	setGroup(dom.GroupFiles, "done", 1)

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
	add(checkD1(domainName))
	setGroup(dom.GroupDNS, "running", 1)
	add(checkD2(domainName))
	setGroup(dom.GroupDNS, "running", 2)
	add(checkD3(domainName))
	setGroup(dom.GroupDNS, "running", 3)
	add(checkD4(domainName))
	setGroup(dom.GroupDNS, "running", 4)
	add(checkD5(domainName))
	setGroup(dom.GroupDNS, "running", 5)
	add(checkD6(domainName))
	setGroup(dom.GroupDNS, "done", 6)

	return findings, groups, nil
}

func finding(id string, group dom.GroupID, status dom.Status, sev dom.Severity, ev dom.Evidence, source string) dom.Finding {
	return dom.Finding{
		ID: id, Group: group, Status: status, Severity: sev, Evidence: ev,
		TitleKey: "check." + id + ".title", DangerKey: "check." + id + ".danger", SourceURL: source,
		Fixes: fixes.For(id),
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

func lookupTXT(name string) ([]string, error) {
	return net.LookupTXT(name)
}

func checkD1(domain string) dom.Finding {
	ev := dom.Evidence{Detail: "SPF"}
	txts, err := lookupTXT(domain)
	if err != nil {
		return finding("D1", dom.GroupDNS, dom.StatusError, dom.SeverityMedium, ev, "https://datatracker.ietf.org/doc/html/rfc7208")
	}
	var spf string
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
			spf = t
			break
		}
	}
	ev.Value = ssrf.Truncate(spf, 200)
	if spf == "" {
		return finding("D1", dom.GroupDNS, dom.StatusFail, dom.SeverityMedium, ev, "https://datatracker.ietf.org/doc/html/rfc7208")
	}
	if strings.Contains(strings.ToLower(spf), "+all") {
		return finding("D1", dom.GroupDNS, dom.StatusFail, dom.SeverityMedium, ev, "https://datatracker.ietf.org/doc/html/rfc7208")
	}
	return finding("D1", dom.GroupDNS, dom.StatusPass, dom.SeverityMedium, ev, "https://datatracker.ietf.org/doc/html/rfc7208")
}

func checkD2(domain string) dom.Finding {
	ev := dom.Evidence{Detail: "DKIM selectors (informational probe)"}
	selectors := []string{"default", "google", "selector1", "selector2", "k1", "s1", "dkim"}
	found := ""
	for _, s := range selectors {
		txts, err := lookupTXT(s + "._domainkey." + domain)
		if err != nil {
			continue
		}
		for _, t := range txts {
			if strings.Contains(strings.ToLower(t), "v=dkim1") || strings.Contains(t, "p=") {
				found = s
				ev.Value = ssrf.Truncate(t, 200)
				break
			}
		}
		if found != "" {
			break
		}
	}
	if found == "" {
		return finding("D2", dom.GroupDNS, dom.StatusInfo, dom.SeverityInfo, ev, "https://datatracker.ietf.org/doc/html/rfc6376")
	}
	return finding("D2", dom.GroupDNS, dom.StatusPass, dom.SeverityInfo, ev, "https://datatracker.ietf.org/doc/html/rfc6376")
}

func checkD3(domain string) dom.Finding {
	ev := dom.Evidence{Detail: "DMARC"}
	txts, err := lookupTXT("_dmarc." + domain)
	if err != nil {
		return finding("D3", dom.GroupDNS, dom.StatusError, dom.SeverityMedium, ev, "https://datatracker.ietf.org/doc/html/rfc7489")
	}
	var rec string
	for _, t := range txts {
		if strings.Contains(strings.ToLower(t), "v=dmarc1") {
			rec = t
			break
		}
	}
	ev.Value = ssrf.Truncate(rec, 200)
	if rec == "" {
		return finding("D3", dom.GroupDNS, dom.StatusFail, dom.SeverityMedium, ev, "https://datatracker.ietf.org/doc/html/rfc7489")
	}
	if strings.Contains(strings.ToLower(rec), "p=none") {
		return finding("D3", dom.GroupDNS, dom.StatusFail, dom.SeverityMedium, ev, "https://datatracker.ietf.org/doc/html/rfc7489")
	}
	return finding("D3", dom.GroupDNS, dom.StatusPass, dom.SeverityMedium, ev, "https://datatracker.ietf.org/doc/html/rfc7489")
}

func checkD4(domain string) dom.Finding {
	ev := dom.Evidence{Detail: "DNSSEC (informational)"}
	_, err := net.LookupIP(domain)
	if err != nil {
		return finding("D4", dom.GroupDNS, dom.StatusError, dom.SeverityInfo, ev, "https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en")
	}
	// Without a validating resolver we only report informational unknown.
	ev.Value = "not verified by validating resolver in MVP"
	return finding("D4", dom.GroupDNS, dom.StatusInfo, dom.SeverityInfo, ev, "https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en")
}

func checkD5(domain string) dom.Finding {
	ev := dom.Evidence{Detail: "CAA (informational; full CAA RR parse deferred)"}
	if _, err := net.LookupHost(domain); err != nil {
		return finding("D5", dom.GroupDNS, dom.StatusError, dom.SeverityInfo, ev, "https://datatracker.ietf.org/doc/html/rfc8659")
	}
	ev.Value = "CAA records not enumerated in MVP resolver"
	return finding("D5", dom.GroupDNS, dom.StatusInfo, dom.SeverityInfo, ev, "https://datatracker.ietf.org/doc/html/rfc8659")
}

func checkD6(domain string) dom.Finding {
	ev := dom.Evidence{Detail: "Dangling CNAME via common subdomains (CT full crawl deferred)"}
	subs := []string{"www", "mail", "ftp", "dev", "staging", "cdn", "static"}
	for _, s := range subs {
		host := s + "." + domain
		cname, err := net.LookupCNAME(host)
		if err != nil || cname == "" || strings.EqualFold(cname, host+".") {
			continue
		}
		cname = strings.TrimSuffix(cname, ".")
		if looksExternalDangling(cname) {
			ips, err := net.LookupIP(host)
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
	txts, err := net.LookupTXT("_sitechecker-optout." + domain)
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
