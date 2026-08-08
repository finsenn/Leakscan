import type { Confidence, FileFinding, HistoryFinding } from "./api";

/**
 * Visual weight per confidence tier. The backend decides the tier; the UI only
 * decides how loudly to say it.
 *
 * high   — a provider-specific key shape. Full emphasis.
 * medium — generic keyword matches and card numbers. Slightly receded.
 * low    — entropy-only hits. Quietest: a broad net that needs human review.
 */
const RANK: Record<Confidence, number> = { high: 3, medium: 2, low: 1 };

export function rankOf(confidence: Confidence): number {
  return RANK[confidence] ?? 0;
}

/** Loudest findings first, then by file path, then line. */
export function sortFileFindings(findings: FileFinding[]): FileFinding[] {
  return [...findings].sort((a, b) => {
    const byConfidence = rankOf(b.confidence) - rankOf(a.confidence);
    if (byConfidence !== 0) return byConfidence;
    if (a.file !== b.file) return a.file.localeCompare(b.file);
    return a.line - b.line;
  });
}

export type GroupedHistoryFinding = HistoryFinding & { occurrences: number };

/**
 * A single commit often re-adds the same masked value on many lines (vendored
 * files, reformats). Collapse exact duplicates into one row with a count so the
 * list stays readable without dropping information.
 */
export function groupHistoryFindings(
  findings: HistoryFinding[],
): GroupedHistoryFinding[] {
  const groups = new Map<string, GroupedHistoryFinding>();
  for (const finding of findings) {
    const key = `${finding.commit}|${finding.type}|${finding.match}`;
    const existing = groups.get(key);
    if (existing) {
      existing.occurrences += 1;
    } else {
      groups.set(key, { ...finding, occurrences: 1 });
    }
  }
  return [...groups.values()].sort(
    (a, b) => rankOf(b.confidence) - rankOf(a.confidence),
  );
}

/** Split "src/config/settings.py" into its directory and filename halves. */
export function splitPath(path: string): { dir: string; name: string } {
  const index = path.lastIndexOf("/");
  if (index === -1) return { dir: "", name: path };
  return { dir: path.slice(0, index + 1), name: path.slice(index + 1) };
}
