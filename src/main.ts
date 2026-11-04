import "./style.css";
import { downloadAiPrompt } from "./ai-prompt";
import {
  confirmVerification,
  createCheck,
  getCheck,
  getReport,
  getVerifyStatus,
  openEvents,
  rescanCheck,
  startVerification,
  type CheckRecord,
  type Finding,
} from "./api";
import { checkDanger, checkFix, checkTitle, isDnsFix } from "./check-messages";
import { trustNavHtml } from "./docs-content";
import { detectLocale, t } from "./i18n";
import { registerServiceWorker } from "./register-sw";
import { LOCALES, SITE_ORIGIN, localePath, type Locale } from "./site-config";

let lastReport: CheckRecord | null = null;
let lastShareUrl = "";
let pendingVerifyId: string | null = null;
let domainVerified = false;
let scanningDomain = "";

type ProgressGroup = CheckRecord["progress"][number];

function initialProgress(level: number): ProgressGroup[] {
  return [
    { id: "headers", state: "pending", done: 0, total: 8 },
    { id: "tls", state: "pending", done: 0, total: 6 },
    { id: "cookie", state: "pending", done: 0, total: 4 },
    { id: "files", state: "pending", done: 0, total: level >= 2 ? 7 : 1 },
    { id: "software", state: "pending", done: 0, total: 4 },
    { id: "dns", state: "pending", done: 0, total: 6 },
  ];
}

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
  setText("share-label", "shareLabel");
  setText("share-copy-btn", "shareCopy");
  setText("share-hint", "shareHint");
  setText("report-title", "reportTitle");
  setText("top-fixes-title", "topFixes");
  setText("disclaimer", "disclaimer");
  setText("retry-btn", "retry");
  setText("grade-label", "gradeLabel");
  setText("score-label", "scoreLabel");
  setText("ai-prompt-btn-text", "downloadAiPrompt");
  const level2Label = document.getElementById("level2-label");
  if (level2Label) level2Label.innerHTML = level2LabelHtml();
  setText("verify-summary", "verifySummary");
  setText("verify-lead", "verifyLead");
  setText("verify-method-label", "verifyMethod");
  setText("verify-start-btn", "verifyStart");
  setText("verify-confirm-btn", "verifyConfirm");
  setText("verify-dns-hint", "verifyDnsWait");
  const input = document.getElementById("domain-input") as HTMLInputElement | null;
  if (input) input.placeholder = t(locale, "domainPlaceholder");
  const method = document.getElementById("verify-method") as HTMLSelectElement | null;
  if (method) {
    method.options[0].textContent = t(locale, "verifyDns");
    method.options[1].textContent = t(locale, "verifyFile");
    method.options[2].textContent = t(locale, "verifyMeta");
  }
  syncVerifyDnsHint();
  document.querySelectorAll<HTMLElement>("[data-filter]").forEach((btn) => {
    const f = btn.dataset.filter;
    if (f === "all") btn.textContent = t(locale, "filterAll");
    if (f === "fail") btn.textContent = t(locale, "filterFail");
    if (f === "pass") btn.textContent = t(locale, "filterPass");
  });
  const trust = document.getElementById("trust-nav");
  if (trust) trust.outerHTML = trustNavHtml(locale);
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
    case "verification_required":
      return t(locale, "errorVerify");
    case "blocked_target":
      return t(locale, "errorBlocked");
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

function overallProgress(groups: ProgressGroup[]): { pct: number; current?: ProgressGroup; allDone: boolean } {
  const list = groups?.length ? groups : [];
  let done = 0;
  let total = 0;
  let current: ProgressGroup | undefined;
  let allDone = list.length > 0;
  for (const g of list) {
    done += Math.min(g.done, g.total);
    total += g.total;
    if (g.state === "running") current = g;
    if (g.state !== "done") allDone = false;
  }
  if (!current) current = list.find((g) => g.state === "queued" || g.state === "pending");
  const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0;
  return { pct, current, allDone };
}

function setProgressLive(active: boolean): void {
  const panel = $("progress-panel");
  panel.dataset.scanning = active ? "true" : "false";
  panel.setAttribute("aria-busy", active ? "true" : "false");
}

function renderProgress(groups: ProgressGroup[], opts?: { complete?: boolean }): void {
  const box = $("progress-list");
  const list = groups?.length ? groups : initialProgress(1);
  const { pct, current, allDone } = overallProgress(list);
  const complete = Boolean(opts?.complete || allDone);
  setProgressLive(!complete);

  const statusText = $("progress-status-text");
  const stepText = $("progress-step-text");
  const pctEl = $("progress-pct");
  const fill = $("progress-overall-fill");

  if (complete) {
    statusText.textContent = t(locale, "progressComplete");
    stepText.textContent = "";
    pctEl.textContent = "100%";
    fill.style.width = "100%";
  } else {
    statusText.textContent = scanningDomain
      ? t(locale, "progressScanning").replace("{domain}", scanningDomain)
      : t(locale, "progressWorking");
    stepText.textContent = current
      ? t(locale, "progressStep").replace("{group}", groupLabel(current.id))
      : "";
    pctEl.textContent = `${pct}%`;
    fill.style.width = `${Math.max(pct, pct > 0 ? pct : 4)}%`;
  }

  box.innerHTML = list
    .map((g) => {
      const itemPct = g.total > 0 ? Math.min(100, Math.round((g.done / g.total) * 100)) : 0;
      return `<li class="progress-item" data-state="${escapeHtml(g.state)}">
        <div class="progress-item-main">
          <span class="progress-item-name">${escapeHtml(groupLabel(g.id))}</span>
          <span class="muted progress-item-meta">${g.done}/${g.total} · ${escapeHtml(progressStateLabel(g.state))}</span>
        </div>
        <div class="progress-track" aria-hidden="true"><span class="progress-fill" style="width:${itemPct}%"></span></div>
      </li>`;
    })
    .join("");
}

function reportShareUrl(id: string): string {
  return `${SITE_ORIGIN}${localePath(locale)}?r=${encodeURIComponent(id)}`;
}

function setShareUrl(id: string): void {
  lastShareUrl = reportShareUrl(id);
  const input = $("share-url") as HTMLInputElement;
  input.value = lastShareUrl;
  $("share-panel").hidden = false;
  const url = new URL(window.location.href);
  url.searchParams.set("r", id);
  window.history.replaceState({}, "", `${url.pathname}${url.search}${url.hash}`);
  document.querySelectorAll<HTMLAnchorElement>("a.lang-option[data-locale]").forEach((a) => {
    const loc = a.dataset.locale;
    if (!loc) return;
    a.href = `${localePath(loc as Locale)}?r=${encodeURIComponent(id)}`;
  });
}

function showProgressPanel(level: number, domain?: string): void {
  $("report-panel").hidden = true;
  const panel = $("progress-panel");
  if (domain) scanningDomain = domain;
  else if (!scanningDomain) {
    scanningDomain = (($("domain-input") as HTMLInputElement).value || "").trim();
  }
  panel.hidden = false;
  renderProgress(initialProgress(level));
  panel.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function copyShareLink(btn: HTMLButtonElement): Promise<void> {
  if (!lastShareUrl) return;
  const label = t(locale, "shareCopy");
  try {
    await navigator.clipboard.writeText(lastShareUrl);
    btn.textContent = t(locale, "copied");
    setTimeout(() => {
      btn.textContent = label;
    }, 1500);
  } catch {
    btn.textContent = t(locale, "copyError");
    setTimeout(() => {
      btn.textContent = label;
    }, 1500);
  }
}

function setVerifiedUI(ok: boolean, until?: string, denied?: boolean): void {
  domainVerified = ok && !denied;
  const toggle = $("level2-toggle") as HTMLInputElement;
  const status = $("verify-status");
  toggle.disabled = !domainVerified;
  if (!domainVerified) toggle.checked = false;
  if (denied) {
    status.hidden = false;
    status.textContent = t(locale, "verifyDenied");
    status.dataset.tone = "bad";
    return;
  }
  if (ok) {
    status.hidden = false;
    status.textContent = until
      ? t(locale, "verifyOkUntil").replace("{until}", new Date(until).toLocaleString(locale))
      : t(locale, "verifyOk");
    status.dataset.tone = "good";
  } else {
    status.hidden = true;
    status.textContent = "";
    delete status.dataset.tone;
  }
}

async function refreshVerifyStatus(): Promise<void> {
  const domain = ($("domain-input") as HTMLInputElement).value.trim();
  if (!domain) {
    setVerifiedUI(false);
    return;
  }
  try {
    const st = await getVerifyStatus(domain);
    setVerifiedUI(st.verified, st.verified_until, st.l2_denied);
  } catch {
    setVerifiedUI(false);
  }
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

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function level2LabelHtml(): string {
  const link = `<a href="#verify-panel" class="verify-jump">${escapeHtml(t(locale, "level2VerifyLink"))}</a>`;
  return t(locale, "level2Label").split("{link}").join(link);
}

function openVerifyPanel(): void {
  const panel = $("verify-panel") as HTMLDetailsElement;
  panel.open = true;
  panel.scrollIntoView({ behavior: "smooth", block: "start" });
}

function reportDomain(): string {
  return (scanningDomain || lastReport?.domain || ($("domain-input") as HTMLInputElement).value || "").trim();
}

function withScanDomain(text: string, domain: string): string {
  if (!text) return text;
  const host = domain || "example.com";
  return text.split("example.com").join(host);
}

function findingCard(f: Finding): string {
  const domain = reportDomain();
  const fixes = f.fixes || {};
  const tabs: { id: string; label: string; body: string }[] = [];
  const push = (id: string, labelKey: Parameters<typeof t>[1], body?: string) => {
    if (!body) return;
    tabs.push({ id, label: t(locale, labelKey), body: withScanDomain(body, domain) });
  };
  push("nginx", "nginx", fixes.nginx);
  push("apache", "apache", fixes.apache);
  push("htaccess", "htaccess", fixes.htaccess);
  push("traefik", "traefik", fixes.traefik);
  push("caddy", "caddy", fixes.caddy);
  push("cloudflare", "cloudflare", fixes.cloudflare);
  push("wordpress", "wordpress", fixes.wordpress);
  const localizedOther = checkFix(locale, f.id, domain);
  push("other", "other", localizedOther || fixes.other);
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
  const dnsHintHtml = isDnsFix(f.id)
    ? `<p class="muted dns-prop-hint">* ${escapeHtml(t(locale, "dnsPropHint"))}</p>`
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
    ${dnsHintHtml}
  </article>`;
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
  if (rec.domain) scanningDomain = rec.domain;
  if (rec.progress?.length) renderProgress(rec.progress, { complete: true });
  else setProgressLive(false);
  $("report-panel").hidden = false;
  $("grade-value").textContent = rec.grade || "—";
  $("score-value").textContent = String(rec.score ?? "—");
  const levelLabel = rec.level >= 2 ? t(locale, "level2Badge") : t(locale, "level1Badge");
  $("report-meta").textContent = `${rec.domain} · ${rec.duration_ms ?? 0} ms · ${levelLabel}`;
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

  const topTitle = $("top-fixes-title");
  const top = $("top-fixes-list");
  const topFixes = rec.top_fixes || [];
  const byId = new Map((rec.findings || []).map((f) => [f.id, f]));
  top.innerHTML = topFixes
    .map((id) => {
      const f = byId.get(id);
      const title = checkTitle(locale, id);
      const sev = f ? severityLabel(f.severity) : "";
      return `<li><strong>${escapeHtml(title)}</strong>${sev ? ` — ${escapeHtml(sev)}` : ""} <span class="muted">(${escapeHtml(id)})</span></li>`;
    })
    .join("");
  const showTopFixes = topFixes.length > 0;
  topTitle.hidden = !showTopFixes;
  top.hidden = !showTopFixes;

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
    const finish = async () => {
      if (settled) return;
      settled = true;
      window.clearInterval(poll);
      window.clearTimeout(watchdog);
      es.close();
      try {
        resolve(await getReport(id));
      } catch (e) {
        reject(e);
      }
    };
    const pollOnce = async () => {
      try {
        const rec = await getCheck(id);
        if (rec.progress?.length) renderProgress(rec.progress);
        if (rec.state === "done" || rec.state === "failed") {
          void finish();
        }
      } catch {
        /* ignore transient poll errors */
      }
    };
    const es = openEvents(id, (raw) => {
      const data = raw as { type?: string; progress?: ProgressGroup[]; state?: string };
      if (data.progress) renderProgress(data.progress);
      if (data.type === "done" || data.state === "done" || data.state === "failed") {
        void finish();
      }
    });
    es.onerror = () => {
      /* keep polling */
    };
    const poll = window.setInterval(() => {
      void pollOnce();
    }, 400);
    void pollOnce();
    const watchdog = window.setTimeout(() => {
      void finish();
    }, 90_000);
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

async function runCheckFlow(id: string, level: number, domain?: string): Promise<void> {
  setShareUrl(id);
  showProgressPanel(level, domain);
  const rec = await waitForDone(id);
  if (rec.progress?.length) renderProgress(rec.progress, { complete: rec.state !== "failed" });
  if (rec.state === "failed") {
    setProgressLive(false);
    $("form-error").textContent = rec.error || t(locale, "errorGeneric");
  } else {
    renderReport(rec);
  }
}

async function onCheck(): Promise<void> {
  const input = $("domain-input") as HTMLInputElement;
  const err = $("form-error");
  err.textContent = "";
  const btn = $("check-btn") as HTMLButtonElement;
  const level2 = $("level2-toggle") as HTMLInputElement;
  const level = level2.checked && domainVerified ? 2 : 1;
  btn.disabled = true;
  btn.textContent = t(locale, "checking");
  const domain = input.value.trim();
  showProgressPanel(level, domain);
  try {
    const id = await createCheck(domain, locale, level);
    await runCheckFlow(id, level, domain);
  } catch (e) {
    const ex = e as { code?: string; retryAfter?: number };
    err.textContent = mapError(ex.code, ex.retryAfter);
    $("progress-panel").hidden = true;
    setProgressLive(false);
    $("share-panel").hidden = true;
  } finally {
    btn.disabled = false;
    btn.textContent = t(locale, "checkBtn");
  }
}

async function openSharedReport(id: string): Promise<void> {
  const err = $("form-error");
  err.textContent = "";
  const btn = $("check-btn") as HTMLButtonElement;
  btn.disabled = true;
  btn.textContent = t(locale, "checking");
  setShareUrl(id);
  try {
    let rec = await getCheck(id);
    ($("domain-input") as HTMLInputElement).value = rec.domain || "";
    scanningDomain = rec.domain || "";
    void refreshVerifyStatus();
    if (rec.state === "done" || rec.state === "failed") {
      if (rec.fresh === false) {
        showProgressPanel(rec.level || 1, rec.domain);
        const refreshed = await rescanCheck(id);
        if (refreshed.progress?.length) renderProgress(refreshed.progress);
        rec = await waitForDone(id);
      } else {
        rec = await getReport(id);
      }
    } else {
      showProgressPanel(rec.level || 1, rec.domain);
      if (rec.progress?.length) renderProgress(rec.progress);
      rec = await waitForDone(id);
    }
    if (rec.progress?.length) renderProgress(rec.progress, { complete: rec.state !== "failed" });
    if (rec.state === "failed") {
      setProgressLive(false);
      err.textContent = rec.error || t(locale, "errorGeneric");
    } else {
      renderReport(rec);
      $("report-panel").scrollIntoView({ behavior: "smooth", block: "start" });
    }
  } catch (e) {
    const ex = e as { code?: string; retryAfter?: number };
    err.textContent = mapError(ex.code, ex.retryAfter);
    $("progress-panel").hidden = true;
    setProgressLive(false);
    $("share-panel").hidden = true;
  } finally {
    btn.disabled = false;
    btn.textContent = t(locale, "checkBtn");
  }
}

function syncVerifyDnsHint(): void {
  const hint = document.getElementById("verify-dns-hint");
  const method = document.getElementById("verify-method") as HTMLSelectElement | null;
  if (!hint || !method) return;
  hint.hidden = method.value !== "dns";
}

function verifyInstructionText(method: string, domain: string, token: string): string {
  const host = domain.trim();
  let body = "";
  if (method === "dns") {
    body = t(locale, "verifyInstrDns")
      .split("{host}")
      .join(`_sitechecker-verify.${host}`)
      .split("{token}")
      .join(token);
  } else if (method === "file") {
    body = t(locale, "verifyInstrFile")
      .split("{url}")
      .join(`https://${host}/.well-known/sitechecker-${token}.txt`)
      .split("{token}")
      .join(token);
  } else if (method === "meta") {
    body = t(locale, "verifyInstrMeta")
      .split("{meta}")
      .join(`<meta name="sitechecker-verify" content="${token}">`)
      .split("{url}")
      .join(`https://${host}/`);
  }
  const tokenLine = t(locale, "verifyTokenLabel").split("{token}").join(token);
  let text = body ? `${body}\n\n${tokenLine}` : tokenLine;
  if (method === "dns") {
    text = `${text}\n\n${t(locale, "verifyDnsWait")}`;
  }
  return text;
}

async function onVerifyStart(): Promise<void> {
  const err = $("verify-error");
  const box = $("verify-instruction");
  const confirmBtn = $("verify-confirm-btn") as HTMLButtonElement;
  err.textContent = "";
  const domain = ($("domain-input") as HTMLInputElement).value.trim();
  if (!domain) {
    err.textContent = t(locale, "errorInvalid");
    return;
  }
  const method = ($("verify-method") as HTMLSelectElement).value;
  const startBtn = $("verify-start-btn") as HTMLButtonElement;
  startBtn.disabled = true;
  try {
    const v = await startVerification(domain, method);
    pendingVerifyId = v.id;
    box.hidden = false;
    box.textContent = verifyInstructionText(method, v.domain || domain, v.token);
    confirmBtn.hidden = false;
  } catch (e) {
    const ex = e as { code?: string; retryAfter?: number };
    err.textContent = mapError(ex.code, ex.retryAfter);
  } finally {
    startBtn.disabled = false;
  }
}

async function onVerifyConfirm(): Promise<void> {
  const err = $("verify-error");
  err.textContent = "";
  if (!pendingVerifyId) {
    err.textContent = t(locale, "errorVerify");
    return;
  }
  const method = ($("verify-method") as HTMLSelectElement).value;
  const btn = $("verify-confirm-btn") as HTMLButtonElement;
  btn.disabled = true;
  try {
    const res = await confirmVerification(pendingVerifyId);
    setVerifiedUI(res.status === "verified", res.verified_until);
    ($("level2-toggle") as HTMLInputElement).checked = true;
  } catch (e) {
    const ex = e as { code?: string };
    const base = mapError(ex.code);
    err.textContent = method === "dns" ? `${base} ${t(locale, "verifyDnsWait")}` : base;
  } finally {
    btn.disabled = false;
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
  $("share-copy-btn").addEventListener("click", () => {
    void copyShareLink($("share-copy-btn") as HTMLButtonElement);
  });
  $("ai-prompt-btn").addEventListener("click", () => {
    if (!lastReport) return;
    downloadAiPrompt(lastReport, locale, lastShareUrl || reportShareUrl(lastReport.id));
  });
  document.querySelectorAll<HTMLElement>("[data-filter]").forEach((btn) => {
    btn.addEventListener("click", () => applyFilter(btn.dataset.filter || "all"));
  });
  const domainInput = $("domain-input") as HTMLInputElement;
  domainInput.addEventListener("change", () => {
    void refreshVerifyStatus();
  });
  domainInput.addEventListener("blur", () => {
    void refreshVerifyStatus();
  });
  $("verify-method").addEventListener("change", () => {
    syncVerifyDnsHint();
  });
  $("verify-start-btn").addEventListener("click", () => {
    void onVerifyStart();
  });
  $("verify-confirm-btn").addEventListener("click", () => {
    void onVerifyConfirm();
  });
  document.addEventListener("click", (e) => {
    const target = e.target as HTMLElement | null;
    const jump = target?.closest?.("a.verify-jump");
    if (!jump) return;
    e.preventDefault();
    e.stopPropagation();
    openVerifyPanel();
  });
  void registerServiceWorker();
  void LOCALES;
  void localePath;
  void refreshVerifyStatus();
  const sharedId = new URLSearchParams(window.location.search).get("r")?.trim();
  if (sharedId) {
    void openSharedReport(sharedId);
  }
}

boot();

export type { Locale };
