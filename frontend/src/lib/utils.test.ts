// frontend/src/lib/utils.test.ts
import { describe, expect, it } from 'vitest'
import { clamp, cn, formatTimestamp } from './utils'

describe('cn', () => {
  it('merges conflicting Tailwind classes, last wins', () => {
    expect(cn('p-2', 'p-4')).toBe('p-4')
  })

  it('keeps non-conflicting classes and drops falsy values', () => {
    expect(cn('text-sm', null, undefined, 'font-mono')).toBe(
      'text-sm font-mono',
    )
  })
})

describe('clamp', () => {
  it('clamps into range', () => {
    expect(clamp(140, 0, 100)).toBe(100)
    expect(clamp(-3, 0, 100)).toBe(0)
    expect(clamp(42.6, 0, 100)).toBe(42.6)
  })

  it('falls back to the minimum for non-finite input', () => {
    expect(clamp(Number.NaN, 5, 10)).toBe(5)
    expect(clamp(Number.POSITIVE_INFINITY, 5, 10)).toBe(10)
  })
})

describe('formatTimestamp', () => {
  it('formats a valid ISO timestamp', () => {
    expect(formatTimestamp('2026-10-20T10:00:00Z', 'en-GB')).toMatch(/2026/)
  })

  it('returns a dash for missing values and the raw string when invalid', () => {
    expect(formatTimestamp(undefined)).toBe('—')
    expect(formatTimestamp('not-a-date')).toBe('not-a-date')
  })
})
