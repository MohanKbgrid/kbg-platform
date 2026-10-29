import type { Metadata } from "next";
import "./globals.css";
import Header from "@/components/Header";
import Footer from "@/components/Footer";
import { site } from "@/content/site";

export const metadata: Metadata = {
  title: { default: `${site.name} — ${site.tagline}`, template: `%s — ${site.name}` },
  description:
    "KB Grid builds a trusted AI foundation — platform canon, core primitives, Ask AI and Sentinel — and the domain products built on it.",
};

// Applies a stored theme before first paint to avoid a flash.
const themeInit = `try{var t=localStorage.getItem("kbg-theme");if(t)document.documentElement.setAttribute("data-theme",t)}catch(e){}`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeInit }} />
      </head>
      <body>
        <Header />
        <main>{children}</main>
        <Footer />
      </body>
    </html>
  );
}
