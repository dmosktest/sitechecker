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
    cloudflare?: string;
    wordpress?: string;
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
  fresh?: boolean;
  fresh_until?: string;
  created_at?: string;
  finished_at?: string;
};

async function fetchPow(): Promise<string> {
  const res = await fetch("/api/v1/pow", { cache: "no-store" });
  if (!res.ok) throw new Error("pow");
  const ch = (await res.json()) as PowChallenge;
  const sol = await solvePow(ch);
  return JSON.stringify(sol);
}

export async function createCheck(domain: string, lang: string, level = 1): Promise<string> {
  const pow = await fetchPow();
  const res = await fetch("/api/v1/checks", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain, lang, pow, level }),
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

export type Verification = {
  id: string;
  domain: string;
  method: string;
  token: string;
  scope: string;
  status: string;
  instruction?: string;
  token_expires: string;
  verified_until?: string;
};

export type VerifyStatus = {
  domain: string;
  verified: boolean;
  verified_until?: string;
  l2_denied?: boolean;
};

export async function getVerifyStatus(domain: string): Promise<VerifyStatus> {
  const res = await fetch(`/api/v1/verifications?domain=${encodeURIComponent(domain)}`, { cache: "no-store" });
  if (!res.ok) {
    const data = (await res.json()) as { error?: string };
    throw Object.assign(new Error(data.error || "error"), { code: data.error });
  }
  return (await res.json()) as VerifyStatus;
}

export async function startVerification(domain: string, method: string): Promise<Verification> {
  const res = await fetch("/api/v1/verifications", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain, method }),
  });
  const data = (await res.json()) as Verification & { error?: string; retry_after?: number };
  if (!res.ok) {
    const err = new Error(data.error || "error") as Error & { code?: string; retryAfter?: number };
    err.code = data.error;
    if (typeof data.retry_after === "number" && data.retry_after > 0) err.retryAfter = data.retry_after;
    throw err;
  }
  return data;
}

export async function confirmVerification(id: string): Promise<{ status: string; verified_until?: string }> {
  const res = await fetch(`/api/v1/verifications/${id}/confirm`, { method: "POST" });
  const data = (await res.json()) as { status?: string; verified_until?: string; error?: string };
  if (!res.ok) {
    throw Object.assign(new Error(data.error || "error"), { code: data.error });
  }
  return data as { status: string; verified_until?: string };
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

export async function rescanCheck(id: string): Promise<{ id: string; state: string; rescanned: boolean; progress?: CheckRecord["progress"] }> {
  const res = await fetch(`/api/v1/checks/${id}/rescan`, { method: "POST" });
  const data = (await res.json()) as {
    id?: string;
    state?: string;
    rescanned?: boolean;
    progress?: CheckRecord["progress"];
    error?: string;
    retry_after?: number;
  };
  if (!res.ok) {
    const err = new Error(data.error || "error") as Error & { code?: string; retryAfter?: number };
    err.code = data.error;
    if (typeof data.retry_after === "number" && data.retry_after > 0) err.retryAfter = data.retry_after;
    throw err;
  }
  return {
    id: data.id || id,
    state: data.state || "queued",
    rescanned: Boolean(data.rescanned),
    progress: data.progress,
  };
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
