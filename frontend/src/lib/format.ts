export const percent = (value: number | null | undefined, digits = 2) =>
  value == null ? "—" : `${(value * 100).toFixed(digits)}%`;

export const count = (value: number | null | undefined) =>
  value == null ? "—" : value.toLocaleString("en-US");

export const perSecond = (value: number) => `${Math.round(value).toLocaleString("en-US")}/s`;

export const clock = (unixSeconds: number) =>
  new Date(unixSeconds * 1000).toLocaleTimeString("en-GB", { hour12: false });

export const RESOLUTION_LABELS: Record<string, string> = {
  unanimous: "Unanimous",
  advice: "Counselor advice",
  cross_check: "Cross-check",
  fallback: "Fallback",
};

/** Detectors keep their colour slot by name, never by position in a filtered list.
 *  Four validated slots; any further detector folds into muted "other" ink rather
 *  than reusing a hue. */
export function seriesColor(name: string, all: string[]): string {
  const slot = [...all].sort().indexOf(name);
  return slot >= 0 && slot < 4 ? `var(--series-${slot + 1})` : "var(--ink-muted)";
}
