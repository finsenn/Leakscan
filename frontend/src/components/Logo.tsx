export function Logo({ className = "" }: { className?: string }) {
  return (
    <span className={`flex items-center gap-2.5 ${className}`}>
      <span className="flex h-7 w-7 items-center justify-center rounded-md bg-accent shadow-soft">
        <svg
          width="16"
          height="16"
          viewBox="0 0 16 16"
          fill="none"
          aria-hidden="true"
          className="text-accent-fg"
        >
          {/* Aperture / scan frame with a centered scan line */}
          <path
            d="M2 5.5V3.5A1.5 1.5 0 0 1 3.5 2h2M14 5.5V3.5A1.5 1.5 0 0 0 12.5 2h-2M2 10.5v2A1.5 1.5 0 0 0 3.5 14h2M14 10.5v2a1.5 1.5 0 0 1-1.5 1.5h-2"
            stroke="currentColor"
            strokeWidth="1.6"
            strokeLinecap="round"
          />
          <path d="M3.5 8h9" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
        </svg>
      </span>
      <span className="text-[15px] font-semibold tracking-tight text-fg">
        Leakscan
      </span>
    </span>
  );
}
