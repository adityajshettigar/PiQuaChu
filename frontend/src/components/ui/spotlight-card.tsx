// frontend/src/components/ui/spotlight-card.tsx
//
// Adapted from the supplied `spotlight-card`. Deliberate changes:
//  * one component-local pointer handler per card; no global
//    `document.pointermove` listener (the supplied version registered one per
//    instance) and no per-render <style dangerouslySetInnerHTML> block — the
//    gradient lives in the `.spotlight-card` rule in index.css;
//  * pointer position is written straight to CSS custom properties, so moving
//    the pointer does not re-render React;
//  * `touch-action` is left to the browser, text selection and scrolling keep
//    working, and the effect is skipped for touch/pen input;
//  * the visual layer is pointer-events:none (CSS) and never focusable;
//  * colour comes from tokens, so it follows light/dark and the
//    prefers-reduced-motion rule in index.css.
import { useCallback, useRef, type HTMLAttributes, type PointerEvent as ReactPointerEvent } from 'react'
import { cn } from '@/lib/utils'

export interface SpotlightCardProps extends HTMLAttributes<HTMLDivElement> {
  /** Turn the effect off for surfaces where motion would distract. */
  disabled?: boolean
}

export function SpotlightCard({
  className,
  disabled = false,
  onPointerMove,
  onPointerLeave,
  children,
  ...props
}: SpotlightCardProps) {
  const ref = useRef<HTMLDivElement | null>(null)

  const handlePointerMove = useCallback(
    (event: ReactPointerEvent<HTMLDivElement>) => {
      onPointerMove?.(event)
      if (disabled || event.pointerType === 'touch') return
      const node = ref.current
      if (!node) return
      const rect = node.getBoundingClientRect()
      node.style.setProperty('--spot-x', `${event.clientX - rect.left}px`)
      node.style.setProperty('--spot-y', `${event.clientY - rect.top}px`)
      // Attribute flip only — no React state, no re-render on pointer move.
      if (node.dataset.spotlight !== 'on') node.dataset.spotlight = 'on'
    },
    [disabled, onPointerMove],
  )

  const handlePointerLeave = useCallback(
    (event: ReactPointerEvent<HTMLDivElement>) => {
      onPointerLeave?.(event)
      const node = ref.current
      if (node) node.dataset.spotlight = 'off'
    },
    [onPointerLeave],
  )

  return (
    <div
      ref={ref}
      data-spotlight="off"
      onPointerMove={handlePointerMove}
      onPointerLeave={handlePointerLeave}
      className={cn('spotlight-card', className)}
      {...props}
    >
      <div className="relative z-[1]">{children}</div>
    </div>
  )
}

export default SpotlightCard
