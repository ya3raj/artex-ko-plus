// Build-time locales work with Next.js and the embedded static UI.
export const LOCALES = ["en", "ko", "zh"] as const;
export type Locale = (typeof LOCALES)[number];
export const DEFAULT_LOCALE: Locale = "en";

export function resolveLocale(): Locale {
  const raw = process.env.NEXT_PUBLIC_LOCALE;
  return LOCALES.includes(raw as Locale) ? (raw as Locale) : DEFAULT_LOCALE;
}
