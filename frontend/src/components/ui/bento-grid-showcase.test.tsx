// frontend/src/components/ui/bento-grid-showcase.test.tsx
import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { BentoGrid, type BentoItem } from './bento-grid-showcase'

const items: BentoItem[] = [
  {
    id: 'primary',
    colSpan: 8,
    label: 'Primary work area',
    content: <p>primary content</p>,
  },
  {
    id: 'secondary',
    colSpan: 4,
    label: 'Supporting area',
    content: <p>secondary content</p>,
  },
]

describe('BentoGrid', () => {
  it('renders items in DOM order with labelled regions', () => {
    render(<BentoGrid items={items} />)

    const regions = screen.getAllByRole('region')
    expect(regions).toHaveLength(2)
    expect(regions[0]).toHaveAccessibleName('Primary work area')
    expect(regions[1]).toHaveAccessibleName('Supporting area')
    expect(screen.getByText('primary content')).toBeInTheDocument()
    expect(screen.getByText('secondary content')).toBeInTheDocument()
  })

  it('applies desktop span classes and collapses wide items on tablet', () => {
    render(<BentoGrid items={items} />)
    const primary = screen.getByRole('region', { name: 'Primary work area' })

    expect(primary.className).toContain('lg:col-span-8')
    expect(primary.className).toContain('sm:col-span-2')

    const secondary = screen.getByRole('region', { name: 'Supporting area' })
    expect(secondary.className).toContain('lg:col-span-4')
    expect(secondary.className).toContain('sm:col-span-1')
  })

  it('renders nothing when there are no items', () => {
    const { container } = render(<BentoGrid items={[]} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('skips slots without content instead of drawing empty cards', () => {
    render(
      <BentoGrid
        items={[
          { id: 'a', colSpan: 6, content: <p>kept</p> },
          { id: 'b', colSpan: 6, content: null },
        ]}
      />,
    )
    expect(screen.getByText('kept')).toBeInTheDocument()
    expect(screen.queryByText(/empty/i)).not.toBeInTheDocument()
    expect(screen.getAllByText(/kept/i)).toHaveLength(1)
  })

  it('accepts per-item surface classes', () => {
    render(
      <BentoGrid
        items={items}
        itemClassName={(item) => (item.id === 'primary' ? 'bg-surface' : undefined)}
      />,
    )
    expect(
      screen.getByRole('region', { name: 'Primary work area' }).className,
    ).toContain('bg-surface')
  })
})
