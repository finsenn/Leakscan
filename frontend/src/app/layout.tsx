import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import Script from "next/script";
import "./globals.css";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-jetbrains",
  subsets: ["latin"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "Leakscan — Find leaked secrets before they ship",
  description:
    "Scan any public GitHub repository for exposed API keys, tokens, and private keys.",
};

/**
 * Applies the stored theme before first paint so a dark-mode user never sees
 * a white flash. Defaults to light when nothing is stored.
 */
const themeScript = `
(function () {
  try {
    var stored = localStorage.getItem("leakscan-theme");
    if (stored === "dark") document.documentElement.classList.add("dark");
  } catch (e) {}
})();
`;

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${inter.variable} ${jetbrainsMono.variable} antialiased`}>
        {/* Runs before hydration so a dark-mode visitor never sees a light flash. */}
        <Script
          id="theme-init"
          strategy="beforeInteractive"
          dangerouslySetInnerHTML={{ __html: themeScript }}
        />
        {children}
      </body>
    </html>
  );
}
