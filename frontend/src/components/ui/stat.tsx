// frontend/src/components/ui/stat.tsx
//
// The metric block used by overview, scan results, reliability and CBOM.
// Numerals are tabular and set in the data face (IBM Plex Mono): the number is
// the object, and important values take the pale gold value colour. Tone is
// only ever used when it carries real meaning.

import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

export type StatTone = 'default' | 'primary' | 'success' | 'warning' | 'danger' | 'info'

const TONE_CLASS: Record<StatTone, string> = {
  default: 'text-[var(--value)]',
  primary: 'text-[var(--primary)]',
  success: 'text-[var(--success)]',
  warning: 'text-[var(--warning)]',
  danger: 'text-[var(--danger)]',
  info: 'text-[var(--info)]',
}

export interface StatProps {
  label: ReactNode
  value: ReactNode
  /** Small unit set after the value, e.g. "/100" or "%". */
  suffix?: ReactNode
  /** One line of explanation under the value. */
  note?: ReactNode
  tone?: StatTone
  size?: 'md' | 'lg'
  className?: string
}

export function Stat({
  label,
  value,
  suffix,
  note,
  tone = 'default',
  size = 'md',
  className,
}: StatProps) {
  return (
    <div className={cn('min-w-0', className)}>
      <p className="eyebrow mb-2">{label}</p>
      <p
        className={cn(
          'tnum font-mono leading-none tracking-[-0.02em]',
          size === 'lg' ? 'text-[2.75rem]' : 'text-[1.9rem]',
          TONE_CLASS[tone],
        )}
      >
        {value}
        {suffix && (
          <span className="ml-1 font-sans text-[13px] font-normal tracking-normal text-[var(--muted-foreground)]">
            {suffix}
          </span>
        )}
      </p>
      {note && (
        <p className="mt-2 text-[11px] leading-snug text-[var(--muted-foreground)]">
          {note}
        </p>
      )}
    </div>
  )
}

export default Stat
