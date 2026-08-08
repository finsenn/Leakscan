"use client";

const STORAGE_KEY = "leakscan-theme";

/**
 * Holds no React state: the icons swap off the `.dark` class via CSS, which
 * keeps SSR markup and the pre-paint theme script from ever disagreeing.
 */
export function ThemeToggle() {
  function toggle() {
    const root = document.documentElement;
    const next = !root.classList.contains("dark");

    // Only animate colors during the switch, then drop the class so hover
    // transitions elsewhere stay snappy.
    root.classList.add("theme-transition");
    root.classList.toggle("dark", next);
    try {
      localStorage.setItem(STORAGE_KEY, next ? "dark" : "light");
    } catch {
      /* private mode — the toggle still works for this session */
    }
    window.setTimeout(() => root.classList.remove("theme-transition"), 260);
  }

  return (
    <button
      type="button"
      onClick={toggle}
      aria-label="Toggle dark mode"
      className="focus-ring flex h-8 w-8 items-center justify-center rounded-md border border-line bg-elevated text-fg-secondary transition-colors hover:border-line-strong hover:text-fg"
    >
      {/* Sun — shown in light mode */}
      <svg
        width="15"
        height="15"
        viewBox="0 0 16 16"
        fill="none"
        aria-hidden="true"
        className="dark:hidden"
      >
        <circle cx="8" cy="8" r="3.1" stroke="currentColor" strokeWidth="1.4" />
        <path
          d="M8 1.4v1.3M8 13.3v1.3M14.6 8h-1.3M2.7 8H1.4M12.66 3.34l-.92.92M4.26 11.74l-.92.92M12.66 12.66l-.92-.92M4.26 4.26l-.92-.92"
          stroke="currentColor"
          strokeWidth="1.4"
          strokeLinecap="round"
        />
      </svg>

      {/* Moon — shown in dark mode */}
      <svg
        width="15"
        height="15"
        viewBox="0 0 16 16"
        fill="none"
        aria-hidden="true"
        className="hidden -rotate-12 dark:block"
      >
        <path
          d="M13.5 9.7A5.8 5.8 0 0 1 6.3 2.5a5.8 5.8 0 1 0 7.2 7.2Z"
          stroke="currentColor"
          strokeWidth="1.4"
          strokeLinejoin="round"
        />
      </svg>
    </button>
  );
}
