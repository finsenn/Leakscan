import type { FileFinding, HistoryFinding } from "./api";

/**
 * The engine's "Generic *" patterns (Generic API Key / Password / Secret-Token)
 * match on keyword proximity rather than a provider-specific key shape, so they
 * carry most of the false positives. They stay in the list, but rendered quieter.
 */
export function isHighConfidence(type: string): boolean {
  return !type.startsWith("Generic ");
}

/** High-confidence findings first, then by file path, then line. */
export function sortFileFindings(findings: FileFinding[]): FileFinding[] {
  return [...findings].sort((a, b) => {
    const confidence = Number(isHighConfidence(b.type)) - Number(isHighConfidence(a.type));
    if (confidence !== 0) return confidence;
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
    (a, b) => Number(isHighConfidence(b.type)) - Number(isHighConfidence(a.type)),
  );
}

/** Split "src/config/settings.py" into its directory and filename halves. */
export function splitPath(path: string): { dir: string; name: string } {
  const index = path.lastIndexOf("/");
  if (index === -1) return { dir: "", name: path };
  return { dir: path.slice(0, index + 1), name: path.slice(index + 1) };
}
