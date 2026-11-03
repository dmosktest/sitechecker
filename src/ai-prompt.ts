import type { CheckRecord, Finding } from "./api";
import { checkDanger, checkTitle } from "./check-messages";
import type { Locale } from "./i18n";

function isProblem(f: Finding): boolean {
  return f.status === "fail" || f.status === "warn" || f.status === "error";
}

function evidenceLine(f: Finding): string {
  return [f.evidence.header, f.evidence.value, f.evidence.detail, f.evidence.url].filter(Boolean).join(" · ");
}

function fixBlocks(f: Finding): string {
  const fixes = f.fixes || {};
  const parts: string[] = [];
  if (fixes.nginx) parts.push(`### nginx\n\`\`\`nginx\n${fixes.nginx}\n\`\`\``);
  if (fixes.apache) parts.push(`### Apache (vhost / server config)\n\`\`\`apache\n${fixes.apache}\n\`\`\``);
  if (fixes.htaccess) parts.push(`### .htaccess\n\`\`\`apache\n${fixes.htaccess}\n\`\`\``);
  if (fixes.traefik) parts.push(`### Traefik\n\`\`\`yaml\n${fixes.traefik}\n\`\`\``);
  if (fixes.caddy) parts.push(`### Caddy\n\`\`\`caddy\n${fixes.caddy}\n\`\`\``);
  if (fixes.other) parts.push(`### Other\n\`\`\`\n${fixes.other}\n\`\`\``);
  return parts.join("\n\n");
}

export function buildAiPrompt(rec: CheckRecord, locale: Locale): string {
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
      const fixes = fixBlocks(f);
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

  if (locale === "ru") {
    return [
      `# ТЗ для ИИ: исправить проблемы безопасности сайта`,
      ``,
      `Ты — опытный DevOps / security-инженер. Нужно закрыть проблемы базовой гигиены сайта по отчёту sitechecker.`,
      ``,
      `## Контекст`,
      `- Домен: \`${rec.domain}\``,
      `- Оценка: ${rec.grade || "—"} (${rec.score ?? "—"} баллов), уровень L${rec.level}`,
      `- Итог: ${gradeHintRu(rec.grade)}`,
      `- Источник: https://sitechecker.dmosk.net/`,
      `- Важно: только пассивные проверки. Не обещай «полную безопасность», не предлагай атаки и эксплойты.`,
      ``,
      `## Приоритет (сначала это)`,
      top || "- (нет выделенных top-fix)",
      ``,
      `## Задача`,
      `1. Разбери каждую проблему ниже и предложи конкретный план правок.`,
      `2. Дай готовые конфиги под стек проекта (nginx / Apache / Traefik / Caddy / приложение), не копируй слепо все варианты сразу — выбери релевантные.`,
      `3. Укажи порядок внедрения, риски (например HSTS на неполном HTTPS) и как проверить результат.`,
      `4. Если данных мало — задай короткие уточняющие вопросы, затем всё равно предложи безопасный дефолт.`,
      ``,
      `## Проблемы (${problems.length})`,
      problemBlocks || "_Проблем со статусом fail/warn/error нет._",
      ``,
      `## Формат ответа`,
      `- Краткий план работ`,
      `- Затем по каждой проблеме: что сделать, конфиг, проверка`,
      `- В конце — чеклист «готово / проверить снова на sitechecker»`,
      ``,
    ].join("\n");
  }

  return [
    `# AI brief: fix website security baseline issues`,
    ``,
    `You are an experienced DevOps / security engineer. Fix the baseline hygiene issues from a sitechecker report.`,
    ``,
    `## Context`,
    `- Domain: \`${rec.domain}\``,
    `- Grade: ${rec.grade || "—"} (${rec.score ?? "—"} points), level L${rec.level}`,
    `- Source: https://sitechecker.dmosk.net/`,
    `- Constraints: passive checks only. Do not claim full security. Do not suggest attacks or exploits.`,
    ``,
    `## Priority (do these first)`,
    top || "- (no top fixes listed)",
    ``,
    `## Task`,
    `1. For each issue below, propose a concrete remediation plan.`,
    `2. Provide ready configs for the relevant stack (nginx / Apache / Traefik / Caddy / app) — pick what fits, do not dump every option blindly.`,
    `3. Include rollout order, risks (e.g. HSTS before full HTTPS), and how to verify.`,
    `4. If context is missing, ask short clarifying questions, then still propose a safe default.`,
    ``,
    `## Issues (${problems.length})`,
    problemBlocks || "_No fail/warn/error findings._",
    ``,
    `## Response format`,
    `- Short work plan`,
    `- Per issue: action, config, verification`,
    `- Finish with a checklist: done / re-check on sitechecker`,
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

export function downloadAiPrompt(rec: CheckRecord, locale: Locale): void {
  const text = buildAiPrompt(rec, locale);
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
