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

// The topology buffers flows for 24h, so an edge can describe something that
// stopped happening hours ago. Live traffic refreshes an edge continuously and
// the graph polls every 30s, so anything seen within a few minutes is current —
// saying so about it would only cast doubt on a correct reading.
const STALE_AFTER_MS = 5 * 60_000

/** Whether an observation is old enough that it may no longer be happening. */
export function isStaleObservation(iso: string | undefined | null, now = Date.now()): boolean {
  if (!iso) return false
  const t = new Date(iso).getTime()
  if (isNaN(t)) return false
  return now - t > STALE_AFTER_MS
}
