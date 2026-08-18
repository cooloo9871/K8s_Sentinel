import { describe, it, expect } from 'vitest'
import { completePairs } from './labelPairs'

describe('completePairs', () => {
  // The mismatch this pins: the preview dropped a half row while the save
  // wrote {app: ""} — the preview said "every pod", the policy matched none.
  it('drops half-filled rows entirely', () => {
    expect(completePairs([
      { key: 'app', value: '' },
      { key: '', value: 'web' },
      { key: 'run', value: 'test' },
    ])).toEqual({ run: 'test' })
  })

  it('trims both halves', () => {
    expect(completePairs([{ key: ' app ', value: ' web ' }])).toEqual({ app: 'web' })
  })
})
