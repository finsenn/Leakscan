"use client";

import { useEffect, useState } from "react";

export function EmptyState() {
  return (
    <div className="animate-rise rounded-xl border border-dashed border-line bg-surface/60 px-6 py-16 text-center">
      <div className="mx-auto flex h-11 w-11 items-center justify-center rounded-lg border border-line bg-elevated text-fg-muted shadow-soft">
        <svg width="20" height="20" viewBox="0 0 20 20" fill="none" aria-hidden="true">
          <circle cx="9" cy="9" r="5.4" stroke="currentColor" strokeWidth="1.5" />
          <path
            d="m13.2 13.2 3.3 3.3"
            stroke="currentColor"
            strokeWidth="1.5"
            strokeLinecap="round"
          />
        </svg>
      </div>
      <p className="mt-4 text-[15px] font-medium text-fg">No scan yet</p>
      <p className="mx-auto mt-1.5 max-w-sm text-sm leading-relaxed text-fg-secondary">
        Paste a public GitHub repository URL above to check it for exposed
        credentials.
      </p>
    </div>
  );
}

const STAGES = [
  "Validating repository",
  "Cloning repository",
  "Scanning files for secrets",
  "Reading commit history",
];

export function ScanningState({ repoUrl }: { repoUrl: string }) {
  const [stage, setStage] = useState(0);

  // The backend runs these steps in this order but doesn't stream progress,
  // so advance the label on a timer and hold on the last one until it returns.
  // The caller remounts this per scan (via key), so stage starts at 0 already.
  useEffect(() => {
    const timers = [
      window.setTimeout(() => setStage(1), 700),
      window.setTimeout(() => setStage(2), 2600),
      window.setTimeout(() => setStage(3), 5200),
    ];
    return () => timers.forEach(window.clearTimeout);
  }, [repoUrl]);

  return (
    <div
      className="animate-rise overflow-hidden rounded-xl border border-line bg-elevated shadow-soft"
      aria-live="polite"
      aria-busy="true"
    >
      {/* Indeterminate sweep — a single accent bar travelling the header edge. */}
      <div className="relative h-0.5 w-full overflow-hidden bg-line">
        <div className="animate-sweep absolute inset-y-0 w-1/3 rounded-full bg-accent" />
      </div>

      <div className="px-6 py-10 text-center">
        <p className="font-mono text-[13px] text-fg-secondary">{repoUrl}</p>

        <div className="mt-5 flex flex-col items-center gap-2.5">
          {STAGES.map((label, index) => (
            <div
              key={label}
              className="flex items-center gap-2.5 text-sm transition-all duration-300"
              style={{
                opacity: index === stage ? 1 : index < stage ? 0.45 : 0.25,
              }}
            >
              <span className="flex h-4 w-4 items-center justify-center">
                {index < stage ? (
                  <svg width="13" height="13" viewBox="0 0 16 16" fill="none" className="text-safe">
                    <path
                      d="m3.5 8.5 3 3 6-7"
                      stroke="currentColor"
                      strokeWidth="1.8"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                ) : index === stage ? (
                  <span className="animate-pulse-soft h-1.5 w-1.5 rounded-full bg-accent" />
                ) : (
                  <span className="h-1.5 w-1.5 rounded-full bg-line-strong" />
                )}
              </span>
              <span className={index === stage ? "text-fg" : "text-fg-secondary"}>
                {label}
              </span>
            </div>
          ))}
        </div>

        <p className="mt-6 text-xs text-fg-muted">
          Large repositories can take up to a minute.
        </p>
      </div>
    </div>
  );
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div
      role="alert"
      className="animate-rise flex items-start gap-3 rounded-xl border border-danger-border bg-danger-soft px-5 py-4"
    >
      <span className="mt-0.5 shrink-0 text-danger">
        <svg width="17" height="17" viewBox="0 0 16 16" fill="none" aria-hidden="true">
          <circle cx="8" cy="8" r="6.4" stroke="currentColor" strokeWidth="1.5" />
          <path
            d="M8 4.9v3.6"
            stroke="currentColor"
            strokeWidth="1.6"
            strokeLinecap="round"
          />
          <circle cx="8" cy="11" r="0.85" fill="currentColor" />
        </svg>
      </span>
      <div className="min-w-0">
        <p className="text-sm font-medium text-fg">Scan failed</p>
        <p className="mt-0.5 text-sm leading-relaxed text-fg-secondary">{message}</p>
      </div>
    </div>
  );
}
