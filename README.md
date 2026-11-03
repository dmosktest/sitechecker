# sitechecker

Passive website security baseline check: headers, TLS, cookies, CMS/JS hints, DNS and mail. Grade A–F with copy-paste fixes for nginx, Apache (vhost + `.htaccess`), Traefik and Caddy, plus a downloadable AI remediation brief.

**Live:** https://sitechecker.dmosk.net/

This repository mirrors application source only (no Docker/Compose or stand config). The full monorepo and deploy live in GitLab `mksrv`.

## Stack

- Frontend: Vite + TypeScript
- Backend: Go API + worker
- Redis queue, PostgreSQL reports

## License

MIT © dmosk
