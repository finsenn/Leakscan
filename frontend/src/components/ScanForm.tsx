"use client";

import { useState } from "react";

const EXAMPLES = [
  { label: "digininja/DVWA", url: "https://github.com/digininja/DVWA" },
  { label: "octocat/Spoon-Knife", url: "https://github.com/octocat/Spoon-Knife" },
];

export function ScanForm({
  onScan,
  isScanning,
}: {
  onScan: (url: string) => void;
  isScanning: boolean;
}) {
  const [value, setValue] = useState("");

  function submit(event: React.FormEvent) {
    event.preventDefault();
    const trimmed = value.trim();
    if (trimmed && !isScanning) onScan(trimmed);
  }

  return (
    <div className="w-full">
      <form onSubmit={submit}>
        <div className="group relative flex items-center rounded-xl border border-line bg-elevated shadow-soft transition-all duration-200 focus-within:border-accent focus-within:shadow-lift hover:border-line-strong">
          <span className="pointer-events-none pl-4 text-fg-muted" aria-hidden="true">
            <svg width="17" height="17" viewBox="0 0 16 16" fill="currentColor">
              <path d="M8 .2a8 8 0 0 0-2.53 15.59c.4.07.55-.17.55-.38l-.01-1.34c-2.23.48-2.7-1.07-2.7-1.07-.36-.93-.89-1.18-.89-1.18-.73-.5.05-.49.05-.49.8.06 1.23.83 1.23.83.72 1.23 1.88.87 2.34.67.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.6 7.6 0 0 1 4 0c1.53-1.03 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.28.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48l-.01 2.2c0 .21.15.46.55.38A8 8 0 0 0 8 .2Z" />
            </svg>
          </span>

          <input
            type="text"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="https://github.com/owner/repository"
            spellCheck={false}
            autoComplete="off"
            aria-label="Public GitHub repository URL"
            disabled={isScanning}
            className="min-w-0 flex-1 bg-transparent px-3 py-4 text-[15px] text-fg outline-none placeholder:text-fg-muted disabled:opacity-60 sm:text-base"
          />

          <button
            type="submit"
            disabled={isScanning || !value.trim()}
            className="focus-ring m-1.5 flex shrink-0 items-center gap-2 rounded-lg bg-accent px-4 py-2.5 text-sm font-medium text-accent-fg shadow-soft transition-all duration-150 hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-40 sm:px-5"
          >
            {isScanning ? (
              <>
                <Spinner />
                <span className="hidden sm:inline">Scanning</span>
              </>
            ) : (
              <>
                <span>Scan</span>
                <svg
                  width="14"
                  height="14"
                  viewBox="0 0 16 16"
                  fill="none"
                  aria-hidden="true"
                  className="transition-transform duration-200 group-focus-within:translate-x-0.5"
                >
                  <path
                    d="M3 8h9.5M9 4.5 12.5 8 9 11.5"
                    stroke="currentColor"
                    strokeWidth="1.7"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </>
            )}
          </button>
        </div>
      </form>

      <div className="mt-3 flex flex-wrap items-center gap-x-2 gap-y-1.5 px-1 text-[13px] text-fg-muted">
        <span>Try:</span>
        {EXAMPLES.map((example) => (
          <button
            key={example.url}
            type="button"
            disabled={isScanning}
            onClick={() => {
              setValue(example.url);
              onScan(example.url);
            }}
            className="focus-ring rounded-md border border-line px-2 py-0.5 font-mono text-[12px] text-fg-secondary transition-colors hover:border-line-strong hover:text-fg disabled:opacity-50"
          >
            {example.label}
          </button>
        ))}
      </div>
    </div>
  );
}

function Spinner() {
  return (
    <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <circle cx="8" cy="8" r="6.2" stroke="currentColor" strokeWidth="2" opacity="0.25" />
      <path
        d="M14.2 8A6.2 6.2 0 0 0 8 1.8"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        className="origin-center motion-safe:animate-spin"
        style={{ transformOrigin: "center" }}
      />
    </svg>
  );
}
