import { describe, it, expect } from 'vitest'
import { gateLimitError, gateRule } from './vulnGate'

const base = { enabled: true, mode: 'deny' as const, criticalLimit: 0, highLimit: -1, excludeNamespaces: [] }

describe('gateLimitError', () => {
  it('accepts one counted severity', () => {
    expect(gateLimitError(base)).toBe('')
  })
  it('refuses an enabled gate that counts nothing', () => {
    expect(gateLimitError({ ...base, criticalLimit: -1 })).not.toBe('')
  })
  it('does not complain while the gate is off', () => {
    expect(gateLimitError({ ...base, enabled: false, criticalLimit: -1 })).toBe('')
  })
})

describe('gateRule', () => {
  it('names the limits that count and what happens', () => {
    expect(gateRule(base, 3)).toBe('3 images refused: more than 0 critical')
    expect(gateRule({ ...base, mode: 'warn', highLimit: 10 }, 1))
      .toBe('1 image warned about: more than 0 critical or more than 10 high')
  })
})
