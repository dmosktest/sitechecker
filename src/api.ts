import { solvePow, type PowChallenge } from "./pow";

export type Finding = {
  id: string;
  group: string;
  status: string;
  severity: string;
  evidence: { url?: string; header?: string; value?: string; detail?: string };
  fixes?: {
    nginx?: string;
    apache?: string;
    htaccess?: string;
    traefik?: string;
    caddy?: string;
    other?: string;
  };
  title_key?: string;
  danger_key?: string;
  source_url?: string;
};

export type CheckRecord = {
  id: string;
  domain: string;
  lang: string;
  state: string;
  level: number;
  score: number;
  grade: string;
  duration_ms?: number;
  progress: { id: string; state: string; done: number; total: number }[];
  findings?: Finding[];
  top_fixes?: string[];
  error?: string;
  disclaimer?: string;
};

async function fetchPow(): Promise<string> {
  const res = await fetch("/api/v1/pow", { cache: "no-store" });
  if (!res.ok) throw new Error("pow");
  const ch = (await res.json()) as PowChallenge;
  const sol = await solvePow(ch);
  return JSON.stringify(sol);
}

export async function createCheck(domain: string, lang: string): Promise<string> {
  const pow = await fetchPow();
  const res = await fetch("/api/v1/checks", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain, lang, pow }),
  });
  const data = (await res.json()) as { id?: string; error?: string; retry_after?: number };
  if (!res.ok) {
    const err = new Error(data.error || "error") as Error & { code?: string; retryAfter?: number };
    err.code = data.error;
    if (typeof data.retry_after === "number" && data.retry_after > 0) {
      err.retryAfter = data.retry_after;
    }
    throw err;
  }
  return data.id!;
}

export async function getCheck(id: string): Promise<CheckRecord> {
  const res = await fetch(`/api/v1/checks/${id}`);
  if (!res.ok) throw new Error("not_found");
  return (await res.json()) as CheckRecord;
}

export async function getReport(id: string): Promise<CheckRecord> {
  const res = await fetch(`/api/v1/checks/${id}/report`);
  if (!res.ok && res.status !== 202) throw new Error("not_found");
  return (await res.json()) as CheckRecord;
}

export function openEvents(id: string, onMessage: (data: unknown) => void): EventSource {
  const es = new EventSource(`/api/v1/checks/${id}/events`);
  es.onmessage = (ev) => {
    try {
      onMessage(JSON.parse(ev.data));
    } catch {
      /* ignore */
    }
  };
  return es;
}
