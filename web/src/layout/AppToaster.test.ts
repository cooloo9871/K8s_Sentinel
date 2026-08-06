import { describe, it, expect } from 'vitest'
import { renderHook } from '@testing-library/react'
import { useToast } from './AppToaster'

describe('useToast', () => {
  // Callers put this in dependency arrays. Handing back a fresh object each
  // render made every such array change on every render, so a useCallback built
  // on it was never stable — and an effect depending on that callback re-ran
  // forever, refetching on each render it had just caused.
  it('keeps the same identity across renders', () => {
    const { result, rerender } = renderHook(() => useToast())
    const first = result.current

    rerender()
    rerender()

    expect(result.current).toBe(first)
  })

  it('still exposes success and error', () => {
    const { result } = renderHook(() => useToast())
    expect(typeof result.current.success).toBe('function')
    expect(typeof result.current.error).toBe('function')
  })
})
