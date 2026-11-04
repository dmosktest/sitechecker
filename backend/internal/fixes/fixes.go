package fixes

import (
	"strings"

	"sitechecker/internal/domain"
)

func ApplyHost(f domain.Fixes, host string) domain.Fixes {
	if host == "" {
		host = "example.com"
	}
	repl := func(s string) string {
		if s == "" {
			return s
		}
		return strings.ReplaceAll(s, "example.com", host)
	}
	return domain.Fixes{
		Nginx:      repl(f.Nginx),
		Apache:     repl(f.Apache),
		Htaccess:   repl(f.Htaccess),
		Traefik:    repl(f.Traefik),
		Caddy:      repl(f.Caddy),
		Cloudflare: repl(f.Cloudflare),
		WordPress:  repl(f.WordPress),
		Other:      repl(f.Other),
	}
}

func For(id, host string) domain.Fixes {
	return ApplyHost(forID(id), host)
}

func forID(id string) domain.Fixes {
	switch id {
	case "H1":
		return domain.Fixes{
			Nginx: "# Enables HSTS for 1 year. Ensure all subdomains work over HTTPS first.\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
			Apache: `# Apache vhost / server config (mod_headers)
# Enables HSTS for 1 year — only after HTTPS works everywhere.
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"`,
			Htaccess: `# .htaccess (mod_headers; AllowOverride FileInfo or All)
<IfModule mod_headers.c>
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</IfModule>`,
			Traefik: "# Dynamic config (file provider) or equivalent Docker labels.\nhttp:\n  middlewares:\n    hsts:\n      headers:\n        stsSeconds: 31536000\n        stsIncludeSubdomains: true\n        forceSTSHeader: true\n  # routers.myapp.middlewares: hsts@file",
			Caddy:      "# Caddyfile site block\nheader Strict-Transport-Security \"max-age=31536000; includeSubDomains\"",
			Cloudflare: "SSL/TLS → Edge Certificates → enable HTTP Strict Transport Security (HSTS). Set max-age ≥ 15552000; enable Include subdomains only after HTTPS works everywhere. Do not enable Preload without a plan.",
			WordPress:  "If a security plugin manages headers (e.g. Really Simple SSL, Wordfence): enable HSTS there. Or add via hosting panel / server config above — WordPress core does not set HSTS by itself.",
		}
	case "H2":
		return domain.Fixes{
			Nginx: "# Start in Report-Only; tighten after collecting reports.\nadd_header Content-Security-Policy-Report-Only \"default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'\" always;",
			Apache: `# Apache vhost / server config (mod_headers)
Header always set Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'"`,
			Htaccess: `# .htaccess (mod_headers)
<IfModule mod_headers.c>
  Header always set Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'"
</IfModule>`,
			Traefik: "http:\n  middlewares:\n    csp:\n      headers:\n        customResponseHeaders:\n          Content-Security-Policy-Report-Only: \"default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'\"",
			Caddy:      "header Content-Security-Policy-Report-Only \"default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'\"",
			Cloudflare: "Rules → Transform Rules → Modify response header: set Content-Security-Policy-Report-Only to a starter policy, collect reports, then switch to Content-Security-Policy.",
			WordPress:  "Prefer a security/CSP plugin in Report-Only first. Avoid themes that inject unsafe-inline scripts; move critical CSS/JS to hashed nonces when enforcing CSP.",
		}
	case "H3":
		return domain.Fixes{
			Nginx: "add_header X-Frame-Options \"SAMEORIGIN\" always;\n# or in CSP: frame-ancestors 'self';",
			Apache: `# Apache vhost / server config (mod_headers)
Header always set X-Frame-Options "SAMEORIGIN"
# or CSP: frame-ancestors 'self'`,
			Htaccess: `# .htaccess (mod_headers)
<IfModule mod_headers.c>
  Header always set X-Frame-Options "SAMEORIGIN"
</IfModule>`,
			Traefik: "http:\n  middlewares:\n    frame:\n      headers:\n        frameDeny: true\n        contentSecurityPolicy: \"frame-ancestors 'self'\"",
			Caddy:      "header X-Frame-Options SAMEORIGIN\n# or: header Content-Security-Policy \"frame-ancestors 'self'\"",
			Cloudflare: "Security → Settings → enable \"Browser Integrity Check\" as needed; better: Transform Rule adding X-Frame-Options: SAMEORIGIN or CSP frame-ancestors 'self'.",
			WordPress:  "Many security plugins can send X-Frame-Options. Or add the header in the host/CDN config so it applies to all responses.",
		}
	case "H4":
		return domain.Fixes{
			Nginx: "add_header X-Content-Type-Options \"nosniff\" always;",
			Apache: `# Apache vhost / server config (mod_headers)
Header always set X-Content-Type-Options "nosniff"`,
			Htaccess: `# .htaccess (mod_headers)
<IfModule mod_headers.c>
  Header always set X-Content-Type-Options "nosniff"
</IfModule>`,
			Traefik: "http:\n  middlewares:\n    nosniff:\n      headers:\n        contentTypeNosniff: true",
			Caddy:      "header X-Content-Type-Options nosniff",
			Cloudflare: "Transform Rules → Modify response header → set X-Content-Type-Options to nosniff.",
			WordPress:  "Enable \"X-Content-Type-Options: nosniff\" in your security plugin, or set it at the web server / Cloudflare layer.",
		}
	case "H5":
		return domain.Fixes{
			Nginx: "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
			Apache: `# Apache vhost / server config (mod_headers)
Header always set Referrer-Policy "strict-origin-when-cross-origin"`,
			Htaccess: `# .htaccess (mod_headers)
<IfModule mod_headers.c>
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>`,
			Traefik: "http:\n  middlewares:\n    referrer:\n      headers:\n        referrerPolicy: \"strict-origin-when-cross-origin\"",
			Caddy:      "header Referrer-Policy \"strict-origin-when-cross-origin\"",
			Cloudflare: "Transform Rules → set Referrer-Policy: strict-origin-when-cross-origin.",
			WordPress:  "Set Referrer-Policy via security plugin or server/CDN headers.",
		}
	case "H6":
		return domain.Fixes{
			Nginx: "add_header Permissions-Policy \"geolocation=(), microphone=(), camera=()\" always;",
			Apache: `# Apache vhost / server config (mod_headers)
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"`,
			Htaccess: `# .htaccess (mod_headers)
<IfModule mod_headers.c>
  Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
</IfModule>`,
			Traefik: "http:\n  middlewares:\n    permissions:\n      headers:\n        permissionsPolicy: \"geolocation=(), microphone=(), camera=()\"",
			Caddy:      "header Permissions-Policy \"geolocation=(), microphone=(), camera=()\"",
			Cloudflare: "Transform Rules → set Permissions-Policy to disable unused browser features.",
			WordPress:  "Send Permissions-Policy from a security plugin or the edge; tighten further if the site needs camera/mic.",
		}
	case "H7":
		return domain.Fixes{
			Nginx: "server_tokens off;\nproxy_hide_header X-Powered-By;",
			Apache: `# Apache vhost / server config
ServerTokens Prod
Header unset X-Powered-By`,
			Htaccess: `# .htaccess — can hide X-Powered-By only (ServerTokens is not allowed here)
<IfModule mod_headers.c>
  Header unset X-Powered-By
</IfModule>`,
			Traefik: "http:\n  middlewares:\n    hide-powered:\n      headers:\n        customResponseHeaders:\n          X-Powered-By: \"\"\n          Server: \"\"",
			Caddy:      "header {\n\t-Server\n\t-X-Powered-By\n}",
			Cloudflare: "Transform Rules can remove or overwrite Server / X-Powered-By response headers at the edge.",
			WordPress:  "Remove expose_php and version banners; security plugins can strip X-Powered-By. Prefer fixing at nginx/Apache/Cloudflare.",
		}
	case "H8":
		return domain.Fixes{
			Nginx: "# Do not combine Access-Control-Allow-Origin * with credentials.\n# Reflect only trusted origins explicitly.",
			Apache: `# Apache vhost — do NOT pair wildcard CORS with credentials.
# Avoid Access-Control-Allow-Origin "*" with Allow-Credentials true.`,
			Htaccess: `# .htaccess — do NOT enable wildcard CORS with credentials.
# Avoid Header set Access-Control-Allow-Origin "*" with credentials.`,
			Traefik:    "# Prefer an explicit origin list; never pair * with credentials.",
			Caddy:      "# Do not set Access-Control-Allow-Origin * together with credentials.",
			Cloudflare: "Review Transform/Worker CORS: never pair Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.",
			WordPress:  "Audit REST API / plugin CORS. Disable wildcard ACAO with credentials; allowlist trusted origins only.",
		}
	case "T1":
		return domain.Fixes{
			Nginx: "server {\n  listen 80;\n  server_name example.com;\n  return 301 https://$host$request_uri;\n}",
			Apache: `# Apache vhost — HTTP → HTTPS
<VirtualHost *:80>
  ServerName example.com
  Redirect permanent / https://example.com/
</VirtualHost>`,
			Htaccess: `# .htaccess (mod_rewrite) — HTTP → HTTPS
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteCond %{HTTPS} off
  RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
</IfModule>`,
			Traefik: "http:\n  middlewares:\n    redirect-https:\n      redirectScheme:\n        scheme: https\n        permanent: true",
			Caddy:      "http://example.com {\n\tredir https://{host}{uri} permanent\n}",
			Cloudflare: "SSL/TLS → Overview → Full (strict). Enable Always Use HTTPS under Edge Certificates.",
			WordPress:  "Settings → General: use https:// site URLs. Really Simple SSL or host force-HTTPS; still prefer CDN/server redirect.",
		}
	case "C1":
		return domain.Fixes{
			Nginx: "# Ensure Set-Cookie includes Secure on HTTPS sites.",
			Apache: `# Apache vhost (mod_headers) — append Secure; prefer app-level Secure
Header edit Set-Cookie ^(.*)$ $1;Secure`,
			Htaccess: `# .htaccess (mod_headers) — append Secure; prefer app-level Secure
<IfModule mod_headers.c>
  Header edit Set-Cookie ^(.*)$ $1;Secure
</IfModule>`,
			Traefik:    "# Prefer setting Secure in the application cookie API.",
			Caddy:      "# Set Secure on cookies in the application.",
			Cloudflare: "Prefer app-level Secure cookies. Workers can rewrite Set-Cookie only as a last resort.",
			WordPress:  "Ensure AUTH_KEY cookies and session plugins set Secure when the site is HTTPS (FORCE_SSL_ADMIN, secure login plugins).",
			Other:      "Mark session cookies Secure in the application cookie API when serving over HTTPS.",
		}
	case "C2":
		return domain.Fixes{
			Other:      "Mark session cookies HttpOnly in the application cookie API.",
			WordPress:  "Core auth cookies are HttpOnly; audit custom plugins that set JS-readable session cookies.",
			Cloudflare: "Fix cookie flags in the origin app; do not rely on the CDN alone.",
		}
	case "C3":
		return domain.Fixes{
			Other:      "Add SameSite=Lax (or Strict) to cookies that do not need cross-site POSTs.",
			WordPress:  "Update WordPress and plugins; modern versions set SameSite on auth cookies. Patch custom setcookie() calls.",
			Cloudflare: "Set SameSite in the application Set-Cookie; edge rewrites are fragile.",
		}
	case "F1":
		return domain.Fixes{
			Nginx: "location ~ /\\.git {\n  deny all;\n  return 404;\n}",
			Apache: `# Apache vhost
<DirectoryMatch "/\\.git">
  Require all denied
</DirectoryMatch>`,
			Htaccess: "# Place in web root or deny .git via server config\nRedirectMatch 404 /\\.git",
			Traefik:    "# Block path prefix /.git at the reverse proxy or WAF.",
			Caddy:      "@git path /.git*\nrespond @git 404",
			Cloudflare: "WAF custom rule: URI Path contains /.git → Block. Or Transform to serve 404.",
			WordPress:  "Never deploy .git inside the public web root. Delete it from the server or move the docroot to /public.",
			Other:      "Remove .git from the public document root; keep repositories outside the web tree.",
		}
	case "F2":
		return domain.Fixes{
			Nginx: "location ~* /(\\.env|wp-config\\.php\\.(bak|old|save)|config\\.php\\.(old|bak)) {\n  deny all;\n  return 404;\n}",
			Apache: "RedirectMatch 404 /(\\.env|wp-config\\.php\\.(bak|old)|config\\.php\\.(old|bak))",
			Htaccess: "<FilesMatch \"^(\\.env|.*\\.(bak|old|save|swp))$\">\n  Require all denied\n</FilesMatch>",
			Caddy:      "@secrets path /.env* */wp-config.php.bak */config.php.old\nrespond @secrets 404",
			Cloudflare: "WAF: block requests for /.env, *.bak, wp-config.php.bak and similar backup names.",
			WordPress:  "Delete wp-config.php.bak and editor leftovers from the web root. Keep wp-config.php unreadable via URL (outside docroot or denied).",
			Other:      "Delete backup copies of secrets from the public tree; rotate any credentials that were exposed.",
		}
	case "F3":
		return domain.Fixes{
			Nginx: "location ~* \\.(sql|zip|tar|gz|bak)$ {\n  deny all;\n  return 404;\n}",
			Apache: "RedirectMatch 404 \\.(sql|zip|tar|gz|bak)$",
			Htaccess: "<FilesMatch \"\\.(sql|zip|tar|gz|bak)$\">\n  Require all denied\n</FilesMatch>",
			Caddy:      "@dumps path *.sql *.zip *.tar *.gz\nrespond @dumps 404",
			Cloudflare: "WAF rule: block download of *.sql / backup.zip under the site hostname.",
			WordPress:  "Do not store backup.zip / dump.sql in wp-content or the web root. Use off-site backups.",
			Other:      "Remove database dumps and archives from publicly reachable directories.",
		}
	case "F4":
		return domain.Fixes{
			Nginx: "location ~* /(phpinfo\\.php|info\\.php|server-status|server-info) {\n  deny all;\n  return 404;\n}",
			Apache: `# Disable mod_status publicly; remove phpinfo scripts
<Location /server-status>
  Require all denied
</Location>`,
			Htaccess: "RedirectMatch 404 /(phpinfo|info)\\.php$",
			Caddy:      "@diag path /phpinfo.php /info.php /server-status /server-info\nrespond @diag 404",
			Cloudflare: "WAF: block URI paths phpinfo.php, server-status, server-info.",
			WordPress:  "Delete leftover phpinfo.php from the hosting account; do not leave debug drop-ins in public folders.",
			Other:      "Remove diagnostic scripts and restrict Apache/nginx status handlers to localhost.",
		}
	case "F5":
		return domain.Fixes{
			Nginx: "autoindex off;",
			Apache: "Options -Indexes",
			Htaccess: "Options -Indexes",
			Caddy:      "# Caddy does not enable listing by default; avoid file_server browse",
			Cloudflare: "If origin lists directories, fix origin Options/autoindex; optionally WAF-challenge odd directory URLs.",
			WordPress:  "Add empty index.php in upload folders; ensure host disables directory indexes.",
			Other:      "Turn off autoindex / Options Indexes on the web server.",
		}
	case "F6":
		return domain.Fixes{
			Nginx: "location ~* /(phpmyadmin|adminer|pma) {\n  deny all;\n  return 404;\n}",
			Apache: "RedirectMatch 404 /(phpmyadmin|adminer\\.php|pma)",
			Htaccess: "RedirectMatch 404 /(phpmyadmin|adminer|pma)",
			Caddy:      "@dba path /phpmyadmin* /adminer.php /adminer* /pma*\nrespond @dba 404",
			Cloudflare: "WAF: block /phpmyadmin and /adminer.php from the public Internet; allow only via VPN/IP allowlist if needed.",
			WordPress:  "Do not install phpMyAdmin under the site URL. Manage the DB via host panel or SSH tunnel.",
			Other:      "Remove public DB admin tools or put them behind VPN, basic auth, and IP allowlists.",
		}
	case "F7":
		return domain.Fixes{
			Other:      "Publish /.well-known/security.txt with Contact and Expires fields (RFC 9116).",
			Cloudflare: "Host security.txt on the origin or as a Cloudflare Worker/static asset at /.well-known/security.txt.",
			WordPress:  "Add /.well-known/security.txt via hosting file manager or a small plugin that serves RFC 9116 fields.",
		}
	case "D1":
		return domain.Fixes{Other: "Add a TXT SPF record on example.com, e.g. v=spf1 -all (avoid +all). If you send mail, use your provider include and end with -all."}
	case "D3":
		return domain.Fixes{Other: "Add a TXT record on _dmarc.example.com: v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"}
	default:
		return domain.Fixes{}
	}
}
