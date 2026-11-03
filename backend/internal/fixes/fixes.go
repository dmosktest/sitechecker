package fixes

import "sitechecker/internal/domain"

func For(id string) domain.Fixes {
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
			Caddy:   "# Caddyfile site block\nheader Strict-Transport-Security \"max-age=31536000; includeSubDomains\"",
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
			Caddy:   "header Content-Security-Policy-Report-Only \"default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'\"",
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
			Caddy:   "header X-Frame-Options SAMEORIGIN\n# or: header Content-Security-Policy \"frame-ancestors 'self'\"",
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
			Caddy:   "header X-Content-Type-Options nosniff",
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
			Caddy:   "header Referrer-Policy \"strict-origin-when-cross-origin\"",
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
			Caddy:   "header Permissions-Policy \"geolocation=(), microphone=(), camera=()\"",
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
			Caddy:   "header {\n\t-Server\n\t-X-Powered-By\n}",
		}
	case "H8":
		return domain.Fixes{
			Nginx: "# Do not combine Access-Control-Allow-Origin * with credentials.\n# Reflect only trusted origins explicitly.",
			Apache: `# Apache vhost — do NOT pair wildcard CORS with credentials.
# Avoid Access-Control-Allow-Origin "*" with Allow-Credentials true.`,
			Htaccess: `# .htaccess — do NOT enable wildcard CORS with credentials.
# Avoid Header set Access-Control-Allow-Origin "*" with credentials.`,
			Traefik: "# Prefer an explicit origin list; never pair * with credentials.",
			Caddy:   "# Do not set Access-Control-Allow-Origin * together with credentials.",
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
			Caddy:   "http://example.com {\n\tredir https://{host}{uri} permanent\n}",
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
			Traefik: "# Prefer setting Secure in the application cookie API.",
			Caddy:   "# Set Secure on cookies in the application.",
			Other:   "Mark session cookies Secure in the application cookie API when serving over HTTPS.",
		}
	case "C2":
		return domain.Fixes{Other: "Mark session cookies HttpOnly in the application cookie API."}
	case "C3":
		return domain.Fixes{Other: "Add SameSite=Lax (or Strict) to cookies that do not need cross-site POSTs."}
	case "F7":
		return domain.Fixes{Other: "Publish /.well-known/security.txt with Contact and Expires fields (RFC 9116)."}
	case "D1":
		return domain.Fixes{Other: "Add a TXT SPF record, e.g. v=spf1 include:_spf.example.com -all (avoid +all)."}
	case "D3":
		return domain.Fixes{Other: "Add _dmarc TXT with v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"}
	default:
		return domain.Fixes{}
	}
}
