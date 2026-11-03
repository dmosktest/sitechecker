export type PowChallenge = {
  token: string;
  expires_at: number;
};

export type PowSolution = {
  token: string;
  expires_at: number;
};

export async function solvePow(ch: PowChallenge): Promise<PowSolution> {
  if (!ch?.token || !ch.expires_at) {
    throw new Error("pow_failed");
  }
  return { token: ch.token, expires_at: ch.expires_at };
}
