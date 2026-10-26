// frontend/src/components/ui/spotlight-card.test.tsx
import { describe, expect, it } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { SpotlightCard } from './spotlight-card'

function card(props: Partial<React.ComponentProps<typeof SpotlightCard>> = {}) {
  return render(
    <SpotlightCard data-testid="card" {...props}>
      <p>evidence</p>
    </SpotlightCard>,
  )
}

describe('SpotlightCard', () => {
  it('renders children and starts with the effect off', () => {
    card()
    expect(screen.getByText('evidence')).toBeInTheDocument()
    expect(screen.getByTestId('card')).toHaveAttribute('data-spotlight', 'off')
  })

  it('publishes the pointer position as CSS custom properties', () => {
    card()
    const node = screen.getByTestId('card')

    fireEvent.pointerMove(node, { clientX: 24, clientY: 12, pointerType: 'mouse' })

    expect(node).toHaveAttribute('data-spotlight', 'on')
    // jsdom reports a zero rect, so client coordinates map 1:1 here.
    expect(node.style.getPropertyValue('--spot-x')).toBe('24px')
    expect(node.style.getPropertyValue('--spot-y')).toBe('12px')
  })

  it('turns the effect off when the pointer leaves', () => {
    card()
    const node = screen.getByTestId('card')
    fireEvent.pointerMove(node, { clientX: 5, clientY: 5, pointerType: 'mouse' })
    fireEvent.pointerLeave(node)
    expect(node).toHaveAttribute('data-spotlight', 'off')
  })

  it('does not activate for touch input', () => {
    card()
    const node = screen.getByTestId('card')
    fireEvent.pointerMove(node, { clientX: 5, clientY: 5, pointerType: 'touch' })
    expect(node).toHaveAttribute('data-spotlight', 'off')
    expect(node.style.getPropertyValue('--spot-x')).toBe('')
  })

  it('can be disabled without breaking interaction', () => {
    card({ disabled: true })
    const node = screen.getByTestId('card')
    fireEvent.pointerMove(node, { clientX: 5, clientY: 5, pointerType: 'mouse' })
    expect(node).toHaveAttribute('data-spotlight', 'off')
  })

  it('keeps text selection possible (no touch-action override)', () => {
    card()
    expect(screen.getByTestId('card').style.touchAction).toBe('')
  })

  it('merges custom classes', () => {
    card({ className: 'p-4' })
    expect(screen.getByTestId('card').className).toContain('p-4')
  })
})
