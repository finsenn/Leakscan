"use client";

import type { FileFinding, ScanResult } from "@/lib/api";
import {
  groupHistoryFindings,
  isHighConfidence,
  sortFileFindings,
  splitPath,
  type GroupedHistoryFinding,
} from "@/lib/findings";

type Tone = "danger" | "history";

const TONE = {
  danger: {
    dot: "bg-danger",
    text: "text-danger",
    badge: "border-danger-border bg-danger-soft text-danger",
    rail: "bg-danger",
  },
  history: {
    dot: "bg-history",
    text: "text-history",
    badge: "border-history-border bg-history-soft text-history",
    rail: "bg-history",
  },
} as const;

export function ResultsView({ result }: { result: ScanResult }) {
  const { counts } = result;
  const total = counts.exposed + counts.history;
  const exposed = sortFileFindings(result.exposed);
  const history = groupHistoryFindings(result.history);

  return (
    <div className="space-y-5">
      <SummaryBar result={result} total={total} />

      {total === 0 ? (
        <CleanState repo={result.repo} />
      ) : (
        <div className="space-y-4">
          <Section
            tone="danger"
            title="Exposed"
            description="Committed to the repository and readable by anyone."
            count={counts.exposed}
            index={0}
          >
            {exposed.map((finding, i) => (
              <FileFindingRow key={rowKey(finding, i)} finding={finding} tone="danger" />
            ))}
          </Section>

          <Section
            tone="history"
            title="In git history"
            description={`Removed from the working tree but still recoverable from past commits (last ${result.history_depth} commits scanned).`}
            count={counts.history}
            index={1}
          >
            {history.map((finding, i) => (
              <HistoryFindingRow
                key={`${finding.commit}-${finding.type}-${finding.match}-${i}`}
                finding={finding}
              />
            ))}
          </Section>
        </div>
      )}
    </div>
  );
}

function rowKey(finding: FileFinding, index: number) {
  return `${finding.file}-${finding.line}-${finding.type}-${index}`;
}

function SummaryBar({ result, total }: { result: ScanResult; total: number }) {
  return (
    <div className="animate-rise flex flex-wrap items-center justify-between gap-4 rounded-xl border border-line bg-elevated px-5 py-4 shadow-soft">
      <div className="min-w-0">
        <p className="text-xs font-medium uppercase tracking-wider text-fg-muted">
          Scanned
        </p>
        <p className="mt-1 truncate font-mono text-sm text-fg">{result.repo}</p>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <CountBadge tone="danger" label="exposed" value={result.counts.exposed} />
        <CountBadge tone="history" label="in history" value={result.counts.history} />
        <span className="ml-1 text-xs text-fg-muted">{total} total</span>
      </div>
    </div>
  );
}

function CountBadge({
  tone,
  label,
  value,
}: {
  tone: Tone;
  label: string;
  value: number;
}) {
  const active = value > 0;
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium transition-colors ${
        active ? TONE[tone].badge : "border-line bg-surface text-fg-muted"
      }`}
    >
      <span
        className={`h-1.5 w-1.5 rounded-full ${active ? TONE[tone].dot : "bg-line-strong"}`}
      />
      <span className="tabular-nums">{value}</span>
      <span className="font-normal opacity-80">{label}</span>
    </span>
  );
}

function Section({
  tone,
  title,
  description,
  count,
  index,
  children,
}: {
  tone: Tone;
  title: string;
  description: string;
  count: number;
  index: number;
  children: React.ReactNode;
}) {
  const empty = count === 0;

  return (
    <section
      className="animate-rise overflow-hidden rounded-xl border border-line bg-elevated shadow-soft"
      style={{ animationDelay: `${60 + index * 70}ms` }}
    >
      <header className="flex items-start gap-3 border-b border-line px-5 py-3.5">
        <span
          className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${
            empty ? "bg-line-strong" : TONE[tone].dot
          }`}
        />
        <div className="min-w-0 flex-1">
          <h2
            className={`text-sm font-semibold tracking-tight ${
              empty ? "text-fg-secondary" : "text-fg"
            }`}
          >
            {title}
            <span className="ml-2 font-mono text-xs font-normal tabular-nums text-fg-muted">
              {count}
            </span>
          </h2>
          <p className="mt-0.5 text-[13px] leading-relaxed text-fg-muted">
            {description}
          </p>
        </div>
      </header>

      {empty ? (
        <p className="px-5 py-5 text-[13px] text-fg-muted">Nothing found.</p>
      ) : (
        <ul className="divide-y divide-line">{children}</ul>
      )}
    </section>
  );
}

function TypeBadge({ type }: { type: string }) {
  const strong = isHighConfidence(type);
  return (
    <span
      className={
        strong
          ? "inline-flex shrink-0 items-center rounded-md border border-line-strong bg-surface px-2 py-0.5 text-[11px] font-medium text-fg"
          : "inline-flex shrink-0 items-center rounded-md border border-line px-1.5 py-0.5 text-[10px] font-normal text-fg-muted"
      }
    >
      {type}
    </span>
  );
}

function MaskedValue({ value, strong }: { value: string; strong: boolean }) {
  return (
    <code
      className={`shrink-0 font-mono text-xs ${
        strong ? "text-fg-secondary" : "text-fg-muted opacity-70"
      }`}
    >
      {value}
    </code>
  );
}

function FileFindingRow({ finding, tone }: { finding: FileFinding; tone: Tone }) {
  const strong = isHighConfidence(finding.type);
  const { dir, name } = splitPath(finding.file);

  return (
    <li
      className={`group relative flex flex-wrap items-center gap-x-3 gap-y-1.5 py-2.5 pl-5 pr-5 transition-colors hover:bg-surface ${
        strong ? "" : "opacity-65 hover:opacity-100"
      }`}
    >
      {/* Left rail appears on hover — locates the row without adding permanent chrome. */}
      <span
        className={`absolute inset-y-0 left-0 w-0.5 origin-center scale-y-0 opacity-0 transition-all duration-200 group-hover:scale-y-100 group-hover:opacity-100 ${TONE[tone].rail}`}
      />

      <span className="min-w-0 flex-1 truncate font-mono text-[13px]">
        <span className="text-fg-muted">{dir}</span>
        <span className={strong ? "text-fg" : "text-fg-secondary"}>{name}</span>
        <span className="text-fg-muted">:{finding.line}</span>
      </span>

      <TypeBadge type={finding.type} />
      <MaskedValue value={finding.match} strong={strong} />
    </li>
  );
}

function HistoryFindingRow({ finding }: { finding: GroupedHistoryFinding }) {
  const strong = isHighConfidence(finding.type);

  return (
    <li
      className={`group relative flex flex-wrap items-center gap-x-3 gap-y-1.5 py-2.5 pl-5 pr-5 transition-colors hover:bg-surface ${
        strong ? "" : "opacity-65 hover:opacity-100"
      }`}
    >
      <span
        className={`absolute inset-y-0 left-0 w-0.5 origin-center scale-y-0 opacity-0 transition-all duration-200 group-hover:scale-y-100 group-hover:opacity-100 ${TONE.history.rail}`}
      />

      <span className="flex min-w-0 flex-1 items-center gap-2">
        <span className="text-fg-muted" aria-hidden="true">
          <svg width="13" height="13" viewBox="0 0 16 16" fill="none">
            <circle cx="8" cy="8" r="2.6" stroke="currentColor" strokeWidth="1.5" />
            <path
              d="M8 1.4v4M8 10.6v4"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
            />
          </svg>
        </span>
        <code className={`font-mono text-[13px] ${strong ? "text-fg" : "text-fg-secondary"}`}>
          {finding.commit}
        </code>
        {finding.occurrences > 1 && (
          <span className="rounded border border-line px-1 font-mono text-[10px] text-fg-muted">
            ×{finding.occurrences}
          </span>
        )}
      </span>

      <TypeBadge type={finding.type} />
      <MaskedValue value={finding.match} strong={strong} />
    </li>
  );
}

function CleanState({ repo }: { repo: string }) {
  return (
    <div className="animate-rise rounded-xl border border-safe-border bg-safe-soft px-6 py-12 text-center">
      <div className="mx-auto flex h-11 w-11 items-center justify-center rounded-full border border-safe-border bg-elevated text-safe shadow-soft">
        <svg width="20" height="20" viewBox="0 0 20 20" fill="none" aria-hidden="true">
          <path
            d="m5 10.5 3.4 3.4L15 7"
            stroke="currentColor"
            strokeWidth="1.8"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      </div>
      <p className="mt-4 text-[15px] font-medium text-fg">No secrets found</p>
      <p className="mx-auto mt-1.5 max-w-md text-sm leading-relaxed text-fg-secondary">
        <span className="font-mono text-[13px]">{repo}</span> came back clean across
        its committed files and scanned commit history.
      </p>
    </div>
  );
}
