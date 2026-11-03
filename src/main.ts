import "./style.css";
import { downloadAiPrompt } from "./ai-prompt";
import { createCheck, getCheck, getReport, openEvents, type CheckRecord, type Finding } from "./api";
import { checkDanger, checkTitle } from "./check-messages";
import { detectLocale, t } from "./i18n";
import { registerServiceWorker } from "./register-sw";
import { LOCALES, localePath, type Locale } from "./site-config";

let lastReport: CheckRecord | null = null;

type ProgressGroup = CheckRecord["progress"][number];

const INITIAL_PROGRESS: ProgressGroup[] = [
  { id: "headers", state: "pending", done: 0, total: 8 },
  { id: "tls", state: "pending", done: 0, total: 6 },
  { id: "cookie", state: "pending", done: 0, total: 4 },
  { id: "files", state: "pending", done: 0, total: 1 },
  { id: "software", state: "pending", done: 0, total: 4 },
  { id: "dns", state: "pending", done: 0, total: 6 },
];

const locale = detectLocale();
document.documentElement.lang = locale;

function $(id: string): HTMLElement {
  const el = document.getElementById(id);
  if (!el) throw new Error(`#${id}`);
  return el;
}

function applyChrome(): void {
  const setText = (id: string, key: Parameters<typeof t>[1]) => {
    const el = document.getElementById(id);
    if (el) el.textContent = t(locale, key);
  };
  setText("domain-label", "domainLabel");
  setText("check-btn", "checkBtn");
  setText("progress-title", "progressTitle");
  setText("report-title", "reportTitle");
  setText("top-fixes-title", "topFixes");
  setText("disclaimer", "disclaimer");
  setText("retry-btn", "retry");
  setText("grade-label", "gradeLabel");
  setText("score-label", "scoreLabel");
  setText("ai-prompt-btn-text", "downloadAiPrompt");
  const input = document.getElementById("domain-input") as HTMLInputElement | null;
  if (input) input.placeholder = t(locale, "domainPlaceholder");
  document.querySelectorAll<HTMLElement>("[data-filter]").forEach((btn) => {
    const f = btn.dataset.filter;
    if (f === "all") btn.textContent = t(locale, "filterAll");
    if (f === "fail") btn.textContent = t(locale, "filterFail");
    if (f === "pass") btn.textContent = t(locale, "filterPass");
  });
}

function formatWait(sec: number): string {
  const total = Math.max(1, Math.ceil(sec));
  const hours = Math.floor(total / 3600);
  const mins = Math.floor((total % 3600) / 60);
  const secs = total % 60;
  const parts: string[] = [];
  if (hours > 0) parts.push(t(locale, "waitHour").replace("{n}", String(hours)));
  if (mins > 0) parts.push(t(locale, "waitMin").replace("{n}", String(mins)));
  if (secs > 0 || parts.length === 0) parts.push(t(locale, "waitSec").replace("{n}", String(secs)));
  return parts.join(" ");
}

function mapError(code?: string, retryAfter?: number): string {
  switch (code) {
    case "invalid_domain":
      return t(locale, "errorInvalid");
    case "rate_limited": {
      const wait = retryAfter && retryAfter > 0 ? formatWait(retryAfter) : formatWait(60);
      return t(locale, "errorRate").replace("{wait}", wait);
    }
    case "opted_out":
      return t(locale, "errorOptOut");
    case "pow_required":
      return t(locale, "errorPow");
    default:
      return t(locale, "errorGeneric");
  }
}

function groupLabel(id: string): string {
  const key = `group_${id}` as Parameters<typeof t>[1];
  try {
    return t(locale, key);
  } catch {
    return id;
  }
}

function statusLabel(status: string): string {
  const key = `status_${status}` as Parameters<typeof t>[1];
  try {
    return t(locale, key);
  } catch {
    return status;
  }
}

function severityLabel(severity: string): string {
  const key = `sev_${severity}` as Parameters<typeof t>[1];
  try {
    return t(locale, key);
  } catch {
    return severity;
  }
}

function progressStateLabel(state: string): string {
  switch (state) {
    case "running":
      return t(locale, "progressRunning");
    case "done":
      return t(locale, "progressDone");
    case "queued":
      return t(locale, "progressQueued");
    default:
      return t(locale, "progressPending");
  }
}

function renderProgress(groups: ProgressGroup[]): void {
  const box = $("progress-list");
  const list = groups?.length ? groups : INITIAL_PROGRESS;
  box.innerHTML = list
    .map((g) => {
      const pct = g.total > 0 ? Math.min(100, Math.round((g.done / g.total) * 100)) : 0;
      return `<li class="progress-item" data-state="${escapeHtml(g.state)}">
        <div class="progress-item-main">
          <span class="progress-item-name">${escapeHtml(groupLabel(g.id))}</span>
          <span class="muted progress-item-meta">${g.done}/${g.total} · ${escapeHtml(progressStateLabel(g.state))}</span>
        </div>
        <div class="progress-track" aria-hidden="true"><span class="progress-fill" style="width:${pct}%"></span></div>
      </li>`;
    })
    .join("");
}

function showProgressPanel(): void {
  $("report-panel").hidden = true;
  const panel = $("progress-panel");
  panel.hidden = false;
  renderProgress(INITIAL_PROGRESS);
  panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function copyText(text: string, btn: HTMLButtonElement): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    btn.textContent = t(locale, "copied");
    setTimeout(() => {
      btn.textContent = t(locale, "copyFix");
    }, 1500);
  } catch {
    btn.textContent = t(locale, "copyError");
  }
}

function findingCard(f: Finding): string {
  const fixes = f.fixes || {};
  const tabs: { id: string; label: string; body: string }[] = [];
  if (fixes.nginx) tabs.push({ id: "nginx", label: t(locale, "nginx"), body: fixes.nginx });
  if (fixes.apache) tabs.push({ id: "apache", label: t(locale, "apache"), body: fixes.apache });
  if (fixes.htaccess) tabs.push({ id: "htaccess", label: t(locale, "htaccess"), body: fixes.htaccess });
  if (fixes.traefik) tabs.push({ id: "traefik", label: t(locale, "traefik"), body: fixes.traefik });
  if (fixes.caddy) tabs.push({ id: "caddy", label: t(locale, "caddy"), body: fixes.caddy });
  if (fixes.other) tabs.push({ id: "other", label: t(locale, "other"), body: fixes.other });
  const evidence = [f.evidence.header, f.evidence.value, f.evidence.detail, f.evidence.url]
    .filter(Boolean)
    .join(" · ");
  const title = checkTitle(locale, f.id);
  const danger = checkDanger(locale, f.id);
  const fixHtml = tabs.length
    ? `<div class="fix-block">
        <p class="label">${t(locale, "howFix")}</p>
        <div class="fix-tabs">${tabs
          .map(
            (tab, i) =>
              `<button type="button" class="fix-tab${i === 0 ? " active" : ""}" data-tab="${f.id}-${tab.id}">${tab.label}</button>`,
          )
          .join("")}</div>
        ${tabs
          .map(
            (tab, i) => `<div class="fix-pane${i === 0 ? " active" : ""}" data-pane="${f.id}-${tab.id}">
            <pre><code>${escapeHtml(tab.body)}</code></pre>
            <button type="button" class="copy-btn" data-copy="${encodeURIComponent(tab.body)}">${t(locale, "copyFix")}</button>
          </div>`,
          )
          .join("")}
      </div>`
    : "";
  return `<article class="finding" data-status="${f.status}" data-id="${f.id}">
    <header class="finding-head">
      <strong class="finding-title">${escapeHtml(title)}</strong>
      <span class="pill code">${escapeHtml(f.id)}</span>
      <span class="pill sev-${f.severity}">${escapeHtml(severityLabel(f.severity))}</span>
      <span class="pill status-${f.status}">${statusLabel(f.status)}</span>
    </header>
    ${danger ? `<p class="finding-danger"><span class="label">${t(locale, "whyItMatters")}:</span> ${escapeHtml(danger)}</p>` : ""}
    ${evidence ? `<p class="muted"><span class="label">${t(locale, "evidence")}:</span> ${escapeHtml(evidence)}</p>` : ""}
    ${f.source_url ? `<p class="muted"><a href="${escapeHtml(f.source_url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(t(locale, "sourceLink"))}</a></p>` : ""}
    ${fixHtml}
  </article>`;
}

function escapeHtml(s: string): string {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function gradeSummary(grade?: string): { text: string; tone: string } {
  switch ((grade || "").toUpperCase()) {
    case "A":
      return { text: t(locale, "gradeA"), tone: "good" };
    case "B":
      return { text: t(locale, "gradeB"), tone: "good" };
    case "C":
      return { text: t(locale, "gradeC"), tone: "fair" };
    case "D":
      return { text: t(locale, "gradeD"), tone: "poor" };
    case "F":
      return { text: t(locale, "gradeF"), tone: "bad" };
    default:
      return { text: "", tone: "" };
  }
}

function renderReport(rec: CheckRecord): void {
  lastReport = rec;
  $("report-panel").hidden = false;
  $("grade-value").textContent = rec.grade || "—";
  $("score-value").textContent = String(rec.score ?? "—");
  $("report-meta").textContent = `${rec.domain} · ${rec.duration_ms ?? 0} ms · L${rec.level}`;
  const summary = $("grade-summary");
  const verdict = gradeSummary(rec.grade);
  if (verdict.text) {
    summary.hidden = false;
    summary.textContent = verdict.text;
    summary.dataset.tone = verdict.tone;
  } else {
    summary.hidden = true;
    summary.textContent = "";
    delete summary.dataset.tone;
  }

  const top = $("top-fixes-list");
  const byId = new Map((rec.findings || []).map((f) => [f.id, f]));
  top.innerHTML = (rec.top_fixes || [])
    .map((id) => {
      const f = byId.get(id);
      const title = checkTitle(locale, id);
      const sev = f ? severityLabel(f.severity) : "";
      return `<li><strong>${escapeHtml(title)}</strong>${sev ? ` — ${escapeHtml(sev)}` : ""} <span class="muted">(${escapeHtml(id)})</span></li>`;
    })
    .join("");

  const list = $("findings-list");
  list.innerHTML = (rec.findings || []).map(findingCard).join("");

  list.querySelectorAll<HTMLButtonElement>(".fix-tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      const key = btn.dataset.tab!;
      const root = btn.closest(".finding")!;
      root.querySelectorAll(".fix-tab").forEach((b) => b.classList.remove("active"));
      root.querySelectorAll(".fix-pane").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      root.querySelector(`[data-pane="${key}"]`)?.classList.add("active");
    });
  });
  list.querySelectorAll<HTMLButtonElement>("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", () => {
      void copyText(decodeURIComponent(btn.dataset.copy || ""), btn);
    });
  });
  applyFilter("fail");
}

function applyFilter(mode: string): void {
  document.querySelectorAll<HTMLElement>("[data-filter]").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.filter === mode);
  });
  document.querySelectorAll<HTMLElement>(".finding").forEach((el) => {
    const st = el.dataset.status || "";
    let show = true;
    if (mode === "fail") show = st === "fail" || st === "warn" || st === "error";
    if (mode === "pass") show = st === "pass" || st === "info";
    el.hidden = !show;
  });
}

async function waitForDone(id: string): Promise<CheckRecord> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = async (ok: boolean) => {
      if (settled) return;
      settled = true;
      window.clearInterval(poll);
      es.close();
      try {
        resolve(await getReport(id));
      } catch (e) {
        if (ok) reject(e);
        else reject(e);
      }
    };
    const es = openEvents(id, (raw) => {
      const data = raw as { type?: string; progress?: ProgressGroup[]; state?: string };
      if (data.progress) renderProgress(data.progress);
      if (data.type === "done" || data.state === "done" || data.state === "failed") {
        void finish(true);
      }
    });
    es.onerror = () => {
      /* keep polling */
    };
    const poll = window.setInterval(async () => {
      try {
        const rec = await getCheck(id);
        if (rec.progress?.length) renderProgress(rec.progress);
        if (rec.state === "done" || rec.state === "failed") {
          void finish(true);
        }
      } catch {
        /* ignore */
      }
    }, 400);
  });
}

function wireLangMenu(): void {
  const details = document.querySelector("details.lang");
  if (!details) return;
  document.addEventListener("click", (e) => {
    if (!details.contains(e.target as Node)) details.removeAttribute("open");
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") details.removeAttribute("open");
  });
}

async function onCheck(): Promise<void> {
  const input = $("domain-input") as HTMLInputElement;
  const err = $("form-error");
  err.textContent = "";
  const btn = $("check-btn") as HTMLButtonElement;
  btn.disabled = true;
  btn.textContent = t(locale, "checking");
  showProgressPanel();
  try {
    const id = await createCheck(input.value.trim(), locale);
    const rec = await waitForDone(id);
    if (rec.progress?.length) renderProgress(rec.progress);
    if (rec.state === "failed") {
      err.textContent = rec.error || t(locale, "errorGeneric");
    } else {
      renderReport(rec);
    }
  } catch (e) {
    const ex = e as { code?: string; retryAfter?: number };
    err.textContent = mapError(ex.code, ex.retryAfter);
    $("progress-panel").hidden = true;
  } finally {
    btn.disabled = false;
    btn.textContent = t(locale, "checkBtn");
  }
}

function boot(): void {
  applyChrome();
  wireLangMenu();
  $("check-form").addEventListener("submit", (e) => {
    e.preventDefault();
    void onCheck();
  });
  $("retry-btn").addEventListener("click", () => {
    void onCheck();
  });
  $("ai-prompt-btn").addEventListener("click", () => {
    if (!lastReport) return;
    downloadAiPrompt(lastReport, locale);
  });
  document.querySelectorAll<HTMLElement>("[data-filter]").forEach((btn) => {
    btn.addEventListener("click", () => applyFilter(btn.dataset.filter || "all"));
  });
  void registerServiceWorker();
  // ensure locale links exist
  void LOCALES;
  void localePath;
}

boot();

export type { Locale };
