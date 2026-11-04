import { checkDanger, checkTitle } from "./check-messages";
import { t } from "./i18n";
import { localeNames, localePath, localeUrl, type Locale } from "./site-config";

type CheckMeta = { id: string; level: 1 | 2; severity: string; group: string };

const CHECKS: CheckMeta[] = [
  { id: "H1", level: 1, severity: "high", group: "headers" },
  { id: "H2", level: 1, severity: "high", group: "headers" },
  { id: "H3", level: 1, severity: "medium", group: "headers" },
  { id: "H4", level: 1, severity: "medium", group: "headers" },
  { id: "H5", level: 1, severity: "low", group: "headers" },
  { id: "H6", level: 1, severity: "low", group: "headers" },
  { id: "H7", level: 1, severity: "low", group: "headers" },
  { id: "H8", level: 1, severity: "high", group: "headers" },
  { id: "T1", level: 1, severity: "high", group: "tls" },
  { id: "T2", level: 1, severity: "critical", group: "tls" },
  { id: "T3", level: 1, severity: "high", group: "tls" },
  { id: "T4", level: 1, severity: "high", group: "tls" },
  { id: "T5", level: 1, severity: "medium", group: "tls" },
  { id: "T6", level: 1, severity: "info", group: "tls" },
  { id: "C1", level: 1, severity: "high", group: "cookie" },
  { id: "C2", level: 1, severity: "high", group: "cookie" },
  { id: "C3", level: 1, severity: "medium", group: "cookie" },
  { id: "C4", level: 1, severity: "info", group: "cookie" },
  { id: "F1", level: 2, severity: "critical", group: "files" },
  { id: "F2", level: 2, severity: "critical", group: "files" },
  { id: "F3", level: 2, severity: "critical", group: "files" },
  { id: "F4", level: 2, severity: "high", group: "files" },
  { id: "F5", level: 2, severity: "medium", group: "files" },
  { id: "F6", level: 2, severity: "medium", group: "files" },
  { id: "F7", level: 1, severity: "info", group: "files" },
  { id: "S1", level: 1, severity: "info", group: "software" },
  { id: "S2", level: 1, severity: "high", group: "software" },
  { id: "S3", level: 1, severity: "medium", group: "software" },
  { id: "S4", level: 1, severity: "low", group: "software" },
  { id: "D1", level: 1, severity: "medium", group: "dns" },
  { id: "D2", level: 1, severity: "info", group: "dns" },
  { id: "D3", level: 1, severity: "medium", group: "dns" },
  { id: "D4", level: 1, severity: "info", group: "dns" },
  { id: "D5", level: 1, severity: "info", group: "dns" },
  { id: "D6", level: 1, severity: "high", group: "dns" },
];

const SCORE_DEDUCT = localeNames({
  en: "Score starts at 100. Fail deductions: critical −30, high −12, medium −5, low −2, info 0. Warn subtracts half. Any critical finding caps the grade at D. Grades: A ≥90, B 80–89, C 65–79, D 50–64, F below 50.",
  ru: "Счёт начинается со 100. За fail: critical −30, high −12, medium −5, low −2, info 0. Warn — половина. Любая критическая находка ограничивает оценку уровнем D. Границы: A ≥90, B 80–89, C 65–79, D 50–64, F ниже 50.",
});

const METHOD_LEAD = localeNames({
  en: "Passive GET/HEAD only. Level 1 is public hygiene; level 2 probes sensitive paths after ownership proof. This is a baseline, not a penetration test.",
  ru: "Только пассивные GET/HEAD. Уровень 1 — публичная гигиена; уровень 2 — чувствительные пути после подтверждения владения. Это baseline, не пентест.",
});

const SAMPLE_LEAD = localeNames({
  en: "Static demo of a level-1 report for example.com. No live scan is run on this page.",
  ru: "Статичный демо-отчёт уровня 1 для example.com. На этой странице живой скан не запускается.",
});

function esc(s: string): string {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function groupLabel(locale: Locale, group: string): string {
  const key = `group_${group}` as Parameters<typeof t>[1];
  try {
    return t(locale, key);
  } catch {
    return group;
  }
}

function sevLabel(locale: Locale, severity: string): string {
  const key = `sev_${severity}` as Parameters<typeof t>[1];
  try {
    return t(locale, key);
  } catch {
    return severity;
  }
}

export function trustNavHtml(locale: Locale): string {
  return `<nav id="trust-nav" class="trust-nav" aria-label="${esc(t(locale, "trustNavLabel"))}">
  <a href="${localePath(locale)}sample/">${esc(t(locale, "sampleLink"))}</a>
  <span class="trust-sep" aria-hidden="true">·</span>
  <a href="${localePath(locale)}methodology/">${esc(t(locale, "methodologyLink"))}</a>
</nav>`;
}

export function renderMethodologyBody(locale: Locale): string {
  const rows = CHECKS.map((c) => {
    const title = checkTitle(locale, c.id);
    return `<tr>
  <td><code>${esc(c.id)}</code></td>
  <td>${esc(title)}</td>
  <td>${esc(groupLabel(locale, c.group))}</td>
  <td>${esc(sevLabel(locale, c.severity))}</td>
  <td>L${c.level}</td>
</tr>`;
  }).join("\n");

  return `<p class="lead">${esc(METHOD_LEAD[locale])}</p>
<p class="muted">${esc(SCORE_DEDUCT[locale])}</p>
<div class="table-wrap">
<table class="check-table">
  <thead>
    <tr>
      <th>ID</th>
      <th>${esc(t(locale, "methodColTitle"))}</th>
      <th>${esc(t(locale, "methodColGroup"))}</th>
      <th>${esc(t(locale, "methodColSeverity"))}</th>
      <th>${esc(t(locale, "methodColLevel"))}</th>
    </tr>
  </thead>
  <tbody>
${rows}
  </tbody>
</table>
</div>`;
}

export function renderSampleBody(locale: Locale): string {
  const findings: { id: string; status: string; severity: string }[] = [
    { id: "H1", status: "fail", severity: "high" },
    { id: "H4", status: "fail", severity: "medium" },
    { id: "T1", status: "pass", severity: "high" },
    { id: "C1", status: "fail", severity: "high" },
    { id: "D3", status: "warn", severity: "medium" },
    { id: "F7", status: "info", severity: "info" },
  ];

  const cards = findings
    .map((f) => {
      const title = checkTitle(locale, f.id);
      const danger = checkDanger(locale, f.id);
      const status = t(locale, `status_${f.status}` as Parameters<typeof t>[1]);
      return `<article class="finding" data-status="${f.status}">
  <header class="finding-head">
    <strong class="finding-title">${esc(title)}</strong>
    <span class="pill code">${esc(f.id)}</span>
    <span class="pill sev-${f.severity}">${esc(sevLabel(locale, f.severity))}</span>
    <span class="pill status-${f.status}">${esc(status)}</span>
  </header>
  ${danger ? `<p class="finding-danger"><span class="label">${esc(t(locale, "whyItMatters"))}:</span> ${esc(danger)}</p>` : ""}
  <div class="fix-block">
    <p class="label">${esc(t(locale, "howFix"))}</p>
    <pre><code>${esc(
      f.id === "H1"
        ? 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'
        : f.id === "H4"
          ? 'add_header X-Content-Type-Options "nosniff" always;'
          : f.id === "C1"
            ? "Mark session cookies Secure in the application cookie API."
            : f.id === "D3"
              ? "Add _dmarc TXT with v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
              : "Publish /.well-known/security.txt with Contact and Expires (RFC 9116).",
    )}</code></pre>
  </div>
</article>`;
    })
    .join("\n");

  return `<p class="lead">${esc(SAMPLE_LEAD[locale])}</p>
<section class="panel sample-report">
  <h2>${esc(t(locale, "reportTitle"))}</h2>
  <p class="muted">example.com · 18420 ms · ${esc(t(locale, "level1Badge"))}</p>
  <div class="grade-row">
    <div class="grade-metric">
      <span class="muted">${esc(t(locale, "gradeLabel"))}</span>
      <p class="grade">C</p>
    </div>
    <div class="grade-metric">
      <span class="muted">${esc(t(locale, "scoreLabel"))}</span>
      <p class="score">71</p>
    </div>
  </div>
  <p class="grade-summary" data-tone="fair">${esc(t(locale, "gradeC"))}</p>
  <h3>${esc(t(locale, "topFixes"))}</h3>
  <ol>
    <li><strong>${esc(checkTitle(locale, "H1"))}</strong> — ${esc(sevLabel(locale, "high"))} <span class="muted">(H1)</span></li>
    <li><strong>${esc(checkTitle(locale, "C1"))}</strong> — ${esc(sevLabel(locale, "high"))} <span class="muted">(C1)</span></li>
    <li><strong>${esc(checkTitle(locale, "H4"))}</strong> — ${esc(sevLabel(locale, "medium"))} <span class="muted">(H4)</span></li>
  </ol>
  <div class="findings">${cards}</div>
  <p class="disclaimer">${esc(t(locale, "disclaimer"))}</p>
</section>`;
}

const PAGE_CSS = `
:root {
  --bg: #17110c; --bg-elevated: #241a12; --surface: #2e2117; --border: #4a3424;
  --text: #f6eee6; --muted: #b7a394; --accent: #f0852a; --accent-text: #2a1404;
  --danger: #e07070; --ok: #7cbc7c; --radius: 6px;
  --sev-critical: #e07070; --sev-high: #e08a4a; --sev-medium: #e0b35a; --sev-low: #6aa8e0; --sev-info: #7cbc7c;
  --font: "IBM Plex Sans", "Segoe UI", sans-serif; --mono: "IBM Plex Mono", Consolas, monospace;
}
* { box-sizing: border-box; }
body {
  margin: 0; min-height: 100%; font-family: var(--font); color: var(--text); line-height: 1.45;
  background:
    radial-gradient(1200px 600px at 10% -10%, #3a2414 0%, transparent 55%),
    radial-gradient(900px 500px at 100% 0%, #2c1c10 0%, transparent 50%),
    var(--bg);
}
a { color: var(--accent); }
.wrap { width: min(1100px, calc(100% - 2rem)); margin: 0 auto; padding: 2.5rem 0 4rem; }
.brand { font-size: 0.85rem; letter-spacing: 0.12em; text-transform: uppercase; color: var(--accent); margin: 0 0 1.25rem; }
.brand a { color: inherit; text-decoration: none; }
.brand a:hover { text-decoration: underline; }
.lead { color: var(--text); max-width: 52rem; }
.muted { color: var(--muted); }
.back { margin: 0 0 1.5rem; }
.table-wrap { overflow-x: auto; margin: 1.25rem 0; }
.check-table { width: 100%; border-collapse: collapse; font-size: 0.92rem; }
.check-table th, .check-table td { border-bottom: 1px solid var(--border); padding: 0.55rem 0.45rem; text-align: left; vertical-align: top; }
.check-table th { color: var(--muted); font-weight: 600; }
.check-table code { font-family: var(--mono); color: var(--accent); }
.panel { margin-top: 1rem; padding-top: 0.5rem; border-top: 1px solid var(--border); }
.grade-row { display: flex; flex-wrap: wrap; gap: 1.25rem; align-items: flex-end; margin: 0.75rem 0 1rem; }
.grade { font-size: 2.4rem; margin: 0; font-weight: 700; }
.score { font-size: 1.6rem; margin: 0; }
.grade-summary[data-tone="fair"] { color: #e0b35a; }
.finding { border: 1px solid var(--border); border-radius: var(--radius); background: var(--bg-elevated); padding: 0.85rem 1rem; margin: 0.75rem 0; }
.finding-head { display: flex; flex-wrap: wrap; gap: 0.4rem; align-items: center; margin-bottom: 0.4rem; }
.pill { border: 1px solid var(--border); border-radius: 999px; padding: 0.1rem 0.55rem; font-size: 0.78rem; color: var(--muted); }
.pill.code { font-family: var(--mono); color: var(--accent); }
.sev-critical { color: var(--sev-critical); border-color: var(--sev-critical); }
.sev-high { color: var(--sev-high); border-color: var(--sev-high); }
.sev-medium { color: var(--sev-medium); border-color: var(--sev-medium); }
.sev-low { color: var(--sev-low); border-color: var(--sev-low); }
.sev-info { color: var(--sev-info); border-color: var(--sev-info); }
.label { color: var(--muted); font-size: 0.85rem; }
pre { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 0.75rem; overflow-x: auto; font-family: var(--mono); font-size: 0.85rem; }
.disclaimer { color: var(--muted); font-size: 0.9rem; margin-top: 1.25rem; }
`;

function docsShell(locale: Locale, title: string, pathSuffix: string, body: string): string {
  const home = localePath(locale);
  const dir = locale === "ar" || locale === "fa" ? "rtl" : "ltr";
  return `<!doctype html>
<html lang="${locale}" dir="${dir}">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="robots" content="index, follow" />
    <title>${esc(title)}</title>
    <meta name="description" content="${esc(title)}" />
    <link rel="canonical" href="${localeUrl(locale)}${pathSuffix}" />
    <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
    <style>${PAGE_CSS}</style>
  </head>
  <body>
    <main class="wrap">
      <p class="brand"><a href="https://dmosk.net/">dmosk</a> / sitechecker</p>
      <p class="back"><a href="${home}">← ${esc(t(locale, "docsBack"))}</a></p>
      <h1>${esc(title)}</h1>
      ${body}
    </main>
  </body>
</html>
`;
}

export function renderMethodologyPage(locale: Locale): string {
  return docsShell(locale, t(locale, "methodologyTitle"), "methodology/", renderMethodologyBody(locale));
}

export function renderSamplePage(locale: Locale): string {
  return docsShell(locale, t(locale, "sampleTitle"), "sample/", renderSampleBody(locale));
}
