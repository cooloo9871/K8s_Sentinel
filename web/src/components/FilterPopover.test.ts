import { describe, it, expect } from 'vitest'
import { matchesFilter } from './FilterPopover'

describe('matchesFilter', () => {
  // Nothing ticked is the absence of a filter, not a value to match — the same
  // rule the namespace filter uses, so the two panels behave alike.
  it('lets everything through when nothing is selected', () => {
    expect(matchesFilter([], 'warning')).toBe(true)
    expect(matchesFilter([], null)).toBe(true)
  })

  it('narrows to one value', () => {
    expect(matchesFilter(['critical'], 'critical')).toBe(true)
    expect(matchesFilter(['critical'], 'warning')).toBe(false)
  })

  // The point of the control: seeing file and network rules together without
  // switching back and forth.
  it('narrows to several values at once', () => {
    const selected = ['File', 'Network']
    expect(matchesFilter(selected, 'File')).toBe(true)
    expect(matchesFilter(selected, 'Network')).toBe(true)
    expect(matchesFilter(selected, 'Process')).toBe(false)
  })

  // An event whose function matches no known rule type has no type at all.
  // Asking for network rules should not hand back the unclassifiable ones.
  it('excludes a value that could not be classified', () => {
    expect(matchesFilter(['Network'], null)).toBe(false)
  })
})
