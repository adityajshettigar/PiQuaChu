// frontend/src/components/ui/bento-grid-showcase.tsx
//
// Typed replacement for the supplied `bento-product-features` demo. The demo's
// fixed marketing slots ("Zapier", "Focusing", avatars, shortcuts) are gone;
// callers pass real sections with explicit spans, and the grid only lays them
// out. DOM order is the reading order — spans never reorder content for
// assistive tech. All slots collapse to one column on small screens.
import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

export type BentoColSpan = 3 | 4 | 5 | 6 | 7 | 8 | 9 | 12
export type BentoRowSpan = 1 | 2

const COL_CLASS: Record<BentoColSpan, string> = {
  3: 'lg:col-span-3',
  4: 'lg:col-span-4',
  5: 'lg:col-span-5',
  6: 'lg:col-span-6',
  7: 'lg:col-span-7',
  8: 'lg:col-span-8',
  9: 'lg:col-span-9',
  12: 'lg:col-span-12',
}

const ROW_CLASS: Record<BentoRowSpan, string> = {
  1: 'lg:row-span-1',
  2: 'lg:row-span-2',
}

export interface BentoItem {
  id: string
  /** 12-column span on desktop; ignored on mobile/tablet. */
  colSpan?: BentoColSpan
  rowSpan?: BentoRowSpan
  /** Semantic label used for the region landmark. */
  label?: string
  content: ReactNode
}

export interface BentoGridProps {
  items: BentoItem[]
  className?: string
  /** Extra classes per item id, for surface styling owned by the page. */
  itemClassName?: (item: BentoItem) => string | undefined
}

export function BentoGrid({ items, className, itemClassName }: BentoGridProps) {
  const visible = items.filter((item) => item && item.content != null)
  if (visible.length === 0) return null

  return (
    <div
      className={cn(
        'grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-12',
        className,
      )}
    >
      {visible.map((item) => {
        const wide = (item.colSpan ?? 12) >= 6
        return (
          <div
            key={item.id}
            role={item.label ? 'region' : undefined}
            aria-label={item.label}
            className={cn(
              'min-w-0',
              wide ? 'sm:col-span-2' : 'sm:col-span-1',
              COL_CLASS[item.colSpan ?? 12],
              ROW_CLASS[item.rowSpan ?? 1],
              itemClassName?.(item),
            )}
          >
            {item.content}
          </div>
        )
      })}
    </div>
  )
}

// Prompt-specified name for the same primitive.
export const BentoGridShowcase = BentoGrid

export default BentoGrid
