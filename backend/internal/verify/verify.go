package verify

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"strings"
	"time"

	"sitechecker/internal/dnsauth"
	"sitechecker/internal/domain"
	"sitechecker/internal/ssrf"
)

const (
	TokenTTL     = 7 * 24 * time.Hour
	VerifiedTTL  = 30 * 24 * time.Hour
	DNSPrefix    = "_sitechecker-verify."
	FilePrefix   = "/.well-known/sitechecker-"
	MetaName     = "sitechecker-verify"
)

var l2DeniedSuffixes = []string{
	"gosuslugi.ru",
	"cbr.ru",
	"nalog.gov.ru",
	"sberbank.ru",
	"vtb.ru",
	"tinkoff.ru",
	"yandex.ru",
	"google.com",
	"googleapis.com",
	"cloudflare.com",
	"microsoft.com",
	"apple.com",
	"amazon.com",
	"aws.amazon.com",
}

func NewToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func Instruction(method domain.VerifyMethod, domainName, token string) string {
	switch method {
	case domain.VerifyDNS:
		return "Create TXT record " + DNSPrefix + domainName + " with value " + token
	case domain.VerifyFile:
		return "Publish https://" + domainName + FilePrefix + token + ".txt containing exactly " + token
	case domain.VerifyMeta:
		return "Add <meta name=\"" + MetaName + "\" content=\"" + token + "\"> to the homepage of https://" + domainName + "/"
	default:
		return ""
	}
}

func ScopeFor(method domain.VerifyMethod) string {
	if method == domain.VerifyDNS {
		return "domain"
	}
	return "host"
}

func L2Denied(domainName string) bool {
	d := strings.ToLower(strings.TrimSuffix(domainName, "."))
	for _, suf := range l2DeniedSuffixes {
		if d == suf || strings.HasSuffix(d, "."+suf) {
			return true
		}
	}
	return false
}

func Confirm(ctx context.Context, client *ssrf.Client, v *domain.Verification) bool {
	switch v.Method {
	case domain.VerifyDNS:
		return confirmDNS(ctx, v.Domain, v.Token)
	case domain.VerifyFile:
		return confirmFile(ctx, client, v.Domain, v.Token)
	case domain.VerifyMeta:
		return confirmMeta(ctx, client, v.Domain, v.Token)
	default:
		return false
	}
}

func confirmDNS(ctx context.Context, domainName, token string) bool {
	name := DNSPrefix + domainName
	txts, err := dnsauth.LookupTXT(ctx, domainName, name)
	if err != nil {
		return false
	}
	want := strings.TrimSpace(token)
	for _, t := range txts {
		if strings.TrimSpace(strings.Trim(t, `"'`)) == want {
			return true
		}
	}
	return false
}

func confirmFile(ctx context.Context, client *ssrf.Client, domainName, token string) bool {
	path := FilePrefix + token + ".txt"
	for _, scheme := range []string{"https", "http"} {
		res, err := client.Fetch(ctx, scheme+"://"+domainName+path)
		if err != nil || res.StatusCode != 200 {
			continue
		}
		body := strings.TrimSpace(string(res.Body))
		if looksLikeHTML(body) {
			continue
		}
		if body == token || strings.Contains(body, token) {
			return true
		}
	}
	return false
}

var metaRe = regexp.MustCompile(`(?i)<meta\s+[^>]*name=["']sitechecker-verify["'][^>]*content=["']([^"']+)["'][^>]*/?>`)
var metaReAlt = regexp.MustCompile(`(?i)<meta\s+[^>]*content=["']([^"']+)["'][^>]*name=["']sitechecker-verify["'][^>]*/?>`)

func confirmMeta(ctx context.Context, client *ssrf.Client, domainName, token string) bool {
	for _, scheme := range []string{"https", "http"} {
		res, err := client.Fetch(ctx, scheme+"://"+domainName+"/")
		if err != nil || res.StatusCode >= 400 {
			continue
		}
		body := string(res.Body)
		if m := metaRe.FindStringSubmatch(body); len(m) == 2 && m[1] == token {
			return true
		}
		if m := metaReAlt.FindStringSubmatch(body); len(m) == 2 && m[1] == token {
			return true
		}
	}
	return false
}

func looksLikeHTML(s string) bool {
	low := strings.ToLower(s)
	return strings.Contains(low, "<html") || strings.Contains(low, "<!doctype")
}
