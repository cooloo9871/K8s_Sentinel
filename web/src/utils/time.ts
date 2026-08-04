const TZ = 'Asia/Taipei'
const LOCALE = 'zh-TW'

/**
 * Formats an ISO timestamp string to Taiwan timezone (UTC+8).
 * Returns '—' for empty/invalid input.
 */
export function formatTWTime(iso: string | undefined | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (isNaN(d.getTime())) return iso
  return d.toLocaleString(LOCALE, {
    timeZone: TZ,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}
