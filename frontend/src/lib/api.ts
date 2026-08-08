/** How much to trust a finding. See backend/patterns.py for the rules. */
export type Confidence = "high" | "medium" | "low";

type BaseFinding = {
  type: string;
  match: string;
  confidence: Confidence;
  /** Bits per character. Present only on entropy-pass findings. */
  entropy?: number;
};

export type FileFinding = BaseFinding & {
  file: string;
  line: number;
};

export type HistoryFinding = BaseFinding & {
  commit: string;
};

export type ScanResult = {
  repo: string;
  exposed: FileFinding[];
  history: HistoryFinding[];
  counts: { exposed: number; history: number };
  confidence_counts: Record<Confidence, number>;
  history_depth: number;
};

/** Thrown for any non-2xx response, carrying the backend's message. */
export class ScanError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export async function scanRepository(repoUrl: string): Promise<ScanResult> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repo_url: repoUrl }),
    });
  } catch {
    throw new ScanError(
      "Could not reach the scanner service. Make sure the backend is running.",
      0,
    );
  }

  if (!response.ok) {
    let detail = `Scan failed (${response.status}).`;
    try {
      const body = await response.json();
      if (typeof body?.detail === "string") {
        detail = body.detail;
      } else if (Array.isArray(body?.detail)) {
        // FastAPI validation error shape
        detail = "That doesn't look like a valid repository URL.";
      }
    } catch {
      /* keep the fallback message */
    }
    throw new ScanError(detail, response.status);
  }

  return response.json();
}
