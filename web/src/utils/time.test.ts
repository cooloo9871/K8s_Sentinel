import { describe, it, expect } from 'vitest'
import { isStaleObservation } from './time'

describe('isStaleObservation', () => {
  const now = new Date('2026-08-04T12:00:00Z').getTime()
  const ago = (ms: number) => new Date(now - ms).toISOString()

  // The graph polls every 30s, so a live edge is always a little behind. Calling
  // that stale would cast doubt on a reading that is correct.
  it('treats a recent observation as current', () => {
    expect(isStaleObservation(ago(0), now)).toBe(false)
    expect(isStaleObservation(ago(30_000), now)).toBe(false)
    expect(isStaleObservation(ago(4 * 60_000), now)).toBe(false)
  })

  it('treats an old observation as stale', () => {
    expect(isStaleObservation(ago(6 * 60_000), now)).toBe(true)
    expect(isStaleObservation(ago(3 * 3600_000), now)).toBe(true)
  })

  it('says nothing about a missing or unparseable timestamp', () => {
    expect(isStaleObservation(undefined, now)).toBe(false)
    expect(isStaleObservation('', now)).toBe(false)
    expect(isStaleObservation('not a date', now)).toBe(false)
  })
})
