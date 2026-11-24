import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "Bastion — Pre-Ship Security & Anti-REA Release Gate",
  description:
    "Local-first 3-stage DevSecOps release gate orchestrating TruffleHog, Cloudflare Security Audit, and BLA Anti-REA build hardening.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning className={`${inter.variable} ${jetbrainsMono.variable}`}>
      <body className="min-h-screen antialiased selection:bg-neutral-200 dark:selection:bg-neutral-800">
        {children}
      </body>
    </html>
  );
}
