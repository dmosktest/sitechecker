# sitechecker

Passive website security check: level 1 covers headers, TLS, cookies, CMS/JS hints, DNS and mail; after domain ownership proof, level 2 probes exposed `.git`, `.env`, backups, diagnostic pages, directory listings and DB admin panels. Grade A–F with live progress, plain-language findings, and copy-paste fixes for nginx, Apache (vhost + `.htaccess`), Traefik, Caddy, Cloudflare and WordPress, plus a downloadable AI remediation brief (Markdown). Shareable report URL `/{lang}/?r=<id>` stays fresh for 24 hours, then re-scans in place. Public docs: `/{lang}/sample/` (sample report) and `/{lang}/methodology/` (check list and scoring). No signup for a one-off scan.

**Live:** https://sitechecker.dmosk.net/

This repository mirrors application source only (no Docker/Compose or stand config). The full monorepo and deploy live in GitLab `mksrv`.

## Ownership (level 2)

One of:

- DNS TXT `_sitechecker-verify.<domain>` = token  
- File `/.well-known/sitechecker-<token>.txt` containing the token  
- Meta `<meta name="sitechecker-verify" content="<token}">` on the homepage  

## Stack

- Frontend: Vite + TypeScript  
- Backend: Go API + worker  
- Redis queue, PostgreSQL reports and verifications  

## License

MIT © dmosk
