import type { CheckRecord, Finding } from "./api";
import { checkDanger, checkFix, checkTitle, isDnsFix } from "./check-messages";
import { t, type Locale } from "./i18n";

function isProblem(f: Finding): boolean {
  return f.status === "fail" || f.status === "warn" || f.status === "error";
}

function evidenceLine(f: Finding): string {
  return [f.evidence.header, f.evidence.value, f.evidence.detail, f.evidence.url].filter(Boolean).join(" · ");
}

function withScanDomain(text: string, domain: string): string {
  if (!text) return text;
  const host = domain.trim() || "example.com";
  return text.split("example.com").join(host);
}

function fixBlocks(f: Finding, locale: Locale, domain: string): string {
  const fixes = f.fixes || {};
  const parts: string[] = [];
  const add = (title: string, lang: string, body?: string) => {
    if (!body) return;
    parts.push(`### ${title}\n\`\`\`${lang}\n${withScanDomain(body, domain)}\n\`\`\``);
  };
  add("nginx", "nginx", fixes.nginx);
  add("Apache (vhost / server config)", "apache", fixes.apache);
  add(".htaccess", "apache", fixes.htaccess);
  add("Traefik", "yaml", fixes.traefik);
  add("Caddy", "caddy", fixes.caddy);
  if (fixes.cloudflare) parts.push(`### Cloudflare\n\`\`\`\n${withScanDomain(fixes.cloudflare, domain)}\n\`\`\``);
  if (fixes.wordpress) parts.push(`### WordPress\n\`\`\`\n${withScanDomain(fixes.wordpress, domain)}\n\`\`\``);
  const other = checkFix(locale, f.id, domain) || fixes.other;
  if (other) parts.push(`### Other\n\`\`\`\n${withScanDomain(other, domain)}\n\`\`\``);
  if (isDnsFix(f.id)) {
    parts.push(`* ${t(locale, "dnsPropHint")}`);
  }
  return parts.join("\n\n");
}

export function buildAiPrompt(rec: CheckRecord, locale: Locale, reportUrl?: string): string {
  const problems = (rec.findings || []).filter(isProblem);
  const byId = new Map((rec.findings || []).map((f) => [f.id, f]));
  const top = (rec.top_fixes || [])
    .map((id) => {
      const f = byId.get(id);
      return `- ${checkTitle(locale, id)} (${id})${f ? `, ${f.severity}/${f.status}` : ""}`;
    })
    .join("\n");

  const problemBlocks = problems
    .map((f, i) => {
      const title = checkTitle(locale, f.id);
      const danger = checkDanger(locale, f.id);
      const ev = evidenceLine(f);
      const fixes = fixBlocks(f, locale, rec.domain || "");
      return [
        `## ${i + 1}. ${title} [\`${f.id}\`]`,
        `- Status: ${f.status}`,
        `- Severity: ${f.severity}`,
        `- Group: ${f.group}`,
        danger ? `- Why it matters: ${danger}` : "",
        ev ? `- Evidence: ${ev}` : "",
        f.source_url ? `- Reference: ${f.source_url}` : "",
        fixes ? `\nSuggested starting points:\n\n${fixes}` : "",
      ]
        .filter(Boolean)
        .join("\n");
    })
    .join("\n\n");

  const readyReport = reportUrl || `https://sitechecker.dmosk.net/`;

  if (locale === "ru") {
    return [
      `# ТЗ для ИИ: подготовить правки по отчёту sitechecker`,
      ``,
      `Ты — опытный DevOps / security-инженер. Ниже уже готовый отчёт sitechecker. Твоя задача — только текст: план и конфиги для человека, который будет править сервер сам.`,
      ``,
      `## Жёсткие ограничения`,
      `- Не сканируй сайт, не открывай URL домена, не делай HTTP/HTTPS-запросы, curl, dig, nmap и любые сетевые проверки.`,
      `- Не запускай и не предлагай «сейчас прогнать» sitechecker, SSL Labs, securityheaders и подобные сканеры — отчёт уже есть.`,
      `- Не пиши скрипты/команды «для проверки прямо сейчас» от своего имени. Допустимы только короткие шаги проверки, которые выполнит человек после выката.`,
      `- Не обещай «полную безопасность», не предлагай атаки и эксплойты.`,
      ``,
      `## Контекст`,
      `- Домен: \`${rec.domain}\``,
      `- Оценка: ${rec.grade || "—"} (${rec.score ?? "—"} баллов), уровень L${rec.level}`,
      `- Итог: ${gradeHintRu(rec.grade)}`,
      `- Готовый отчёт: ${readyReport}`,
      ``,
      `## Приоритет (сначала это)`,
      top || "- (нет выделенных top-fix)",
      ``,
      `## Задача`,
      `1. Разбери каждую проблему ниже и предложи конкретный план правок в конфиге/коде.`,
      `2. Дай готовые фрагменты под стек проекта (nginx / Apache / Traefik / Caddy / приложение). Не копируй все варианты сразу — выбери релевантные.`,
      `3. Укажи порядок внедрения и риски (например HSTS на неполном HTTPS).`,
      `4. Если данных мало — задай короткие уточняющие вопросы, затем всё равно предложи безопасный дефолт.`,
      ``,
      `## Проблемы (${problems.length})`,
      problemBlocks || "_Проблем со статусом fail/warn/error нет._",
      ``,
      `## Формат ответа`,
      `- Краткий план работ (только правки, без запуска сканов)`,
      `- По каждой проблеме: что изменить, готовый фрагмент конфига`,
      `- В конце — короткий чеклист для человека после выката (без команд, которые ты должен выполнить сам)`,
      ``,
    ].join("\n");
  }

  return [
    `# AI brief: draft config fixes from a sitechecker report`,
    ``,
    `You are an experienced DevOps / security engineer. The sitechecker report below is already complete. Your job is text only: a remediation plan and configs for a human who will edit the server themselves.`,
    ``,
    `## Hard constraints`,
    `- Do not scan the site. Do not open the domain URL. Do not make HTTP/HTTPS requests, curl, dig, nmap, or any network checks.`,
    `- Do not run or offer to re-run sitechecker, SSL Labs, securityheaders, or similar scanners — the report is already here.`,
    `- Do not write scripts/commands that you would execute yourself “to verify now”. Short post-deploy checks the human can run later are fine.`,
    `- Do not claim full security. Do not suggest attacks or exploits.`,
    ``,
    `## Context`,
    `- Domain: \`${rec.domain}\``,
    `- Grade: ${rec.grade || "—"} (${rec.score ?? "—"} points), level L${rec.level}`,
    `- Ready report: ${readyReport}`,
    ``,
    `## Priority (do these first)`,
    top || "- (no top fixes listed)",
    ``,
    `## Task`,
    `1. For each issue below, propose a concrete config/code change plan.`,
    `2. Provide ready snippets for the relevant stack (nginx / Apache / Traefik / Caddy / app) — pick what fits; do not dump every option.`,
    `3. Include rollout order and risks (e.g. HSTS before full HTTPS).`,
    `4. If context is missing, ask short clarifying questions, then still propose a safe default.`,
    ``,
    `## Issues (${problems.length})`,
    problemBlocks || "_No fail/warn/error findings._",
    ``,
    `## Response format`,
    `- Short work plan (edits only, no scans)`,
    `- Per issue: what to change, ready config snippet`,
    `- End with a short post-deploy checklist for the human (nothing you must execute yourself)`,
    ``,
  ].join("\n");
}

function gradeHintRu(grade?: string): string {
  switch ((grade || "").toUpperCase()) {
    case "A":
      return "отлично";
    case "B":
      return "хорошо";
    case "C":
      return "средне";
    case "D":
      return "нехорошо";
    case "F":
      return "плохо";
    default:
      return "—";
  }
}

export function downloadAiPrompt(rec: CheckRecord, locale: Locale, reportUrl?: string): void {
  const text = buildAiPrompt(rec, locale, reportUrl);
  const safeDomain = (rec.domain || "site").replace(/[^\w.-]+/g, "_");
  const name = `sitechecker-${safeDomain}-ai-prompt.md`;
  const blob = new Blob([text], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
