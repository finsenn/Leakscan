"use client";

import { useState } from "react";
import { Logo } from "@/components/Logo";
import { ResultsView } from "@/components/ResultsView";
import { ScanForm } from "@/components/ScanForm";
import { EmptyState, ErrorState, ScanningState } from "@/components/States";
import { ThemeToggle } from "@/components/ThemeToggle";
import { scanRepository, ScanError, type ScanResult } from "@/lib/api";

type Status = "idle" | "scanning" | "done" | "error";

export default function Home() {
  const [status, setStatus] = useState<Status>("idle");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState("");
  const [activeUrl, setActiveUrl] = useState("");

  async function handleScan(url: string) {
    setStatus("scanning");
    setActiveUrl(url);
    setError("");
    setResult(null);

    try {
      const data = await scanRepository(url);
      setResult(data);
      setStatus("done");
    } catch (err) {
      setError(
        err instanceof ScanError
          ? err.message
          : "Something went wrong while scanning.",
      );
      setStatus("error");
    }
  }

  return (
    <div className="min-h-screen bg-bg">
      <header className="sticky top-0 z-10 border-b border-line bg-bg/80 backdrop-blur-md">
        <div className="mx-auto flex h-14 max-w-3xl items-center justify-between px-6">
          <Logo />
          <div className="flex items-center gap-3">
            <a
              href="https://github.com"
              target="_blank"
              rel="noreferrer noopener"
              className="focus-ring hidden rounded-md px-2 py-1 text-[13px] text-fg-secondary transition-colors hover:text-fg sm:block"
            >
              How it works
            </a>
            <ThemeToggle />
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-3xl px-6 pb-28">
        <section className="pt-16 pb-10 sm:pt-24">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-line bg-surface px-2.5 py-1 text-[11px] font-medium text-fg-secondary">
            <span className="h-1.5 w-1.5 rounded-full bg-accent" />
            Public repositories only
          </span>

          <h1 className="mt-5 text-[2rem] font-semibold leading-[1.15] tracking-tight text-fg sm:text-[2.6rem]">
            Find leaked secrets
            <br />
            before they ship.
          </h1>

          <p className="mt-4 max-w-xl text-[15px] leading-relaxed text-fg-secondary sm:text-base">
            Scan any public GitHub repository for exposed API keys, tokens, and
            private keys — including credentials still buried in commit history.
            Findings are masked, and the clone is deleted the moment the scan
            finishes.
          </p>

          <div className="mt-8">
            <ScanForm onScan={handleScan} isScanning={status === "scanning"} />
          </div>
        </section>

        <section aria-live="polite" className="min-h-[16rem]">
          {status === "idle" && <EmptyState />}
          {status === "scanning" && (
            <ScanningState key={activeUrl} repoUrl={activeUrl} />
          )}
          {status === "error" && <ErrorState message={error} />}
          {status === "done" && result && <ResultsView result={result} />}
        </section>
      </main>

      <footer className="border-t border-line">
        <div className="mx-auto flex max-w-3xl flex-wrap items-center justify-between gap-2 px-6 py-5 text-xs text-fg-muted">
          <span>Secrets are masked in transit and never stored.</span>
          <span className="font-mono">Leakscan</span>
        </div>
      </footer>
    </div>
  );
}
