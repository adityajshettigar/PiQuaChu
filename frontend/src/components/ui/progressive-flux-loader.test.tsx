// frontend/src/components/ui/progressive-flux-loader.test.tsx
import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ProgressiveFluxLoader } from './progressive-flux-loader'

const PHASES = [
  { id: 'queued', label: 'Queued' },
  { id: 'analysing', label: 'Analysing' },
]

describe('ProgressiveFluxLoader', () => {
  it('is indeterminate by default and never invents a percentage', () => {
    render(<ProgressiveFluxLoader label="Scan progress" />)

    expect(screen.getByRole('status')).toBeInTheDocument()
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument()
    expect(screen.getByText(/has not reported a percentage/i)).toBeInTheDocument()
    expect(screen.queryByText(/%/)).not.toBeInTheDocument()
  })

  it('exposes a real value in determinate mode', () => {
    render(<ProgressiveFluxLoader mode="determinate" value={42} />)

    const bar = screen.getByRole('progressbar', { name: /scan progress/i })
    expect(bar).toHaveAttribute('aria-valuenow', '42')
    expect(bar).toHaveAttribute('aria-valuetext', '42% complete')
    expect(screen.getByText('42%')).toBeInTheDocument()
  })

  it('clamps out-of-range and rejects non-finite values', () => {
    const { rerender } = render(
      <ProgressiveFluxLoader mode="determinate" value={140} />,
    )
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '100')

    rerender(<ProgressiveFluxLoader mode="determinate" value={Number.NaN} />)
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument()
    expect(screen.getByRole('status')).toBeInTheDocument()
  })

  it('fires onComplete once per completion transition', () => {
    const onComplete = vi.fn()
    const { rerender } = render(
      <ProgressiveFluxLoader mode="determinate" value={99} onComplete={onComplete} />,
    )
    expect(onComplete).not.toHaveBeenCalled()

    rerender(
      <ProgressiveFluxLoader mode="determinate" value={100} onComplete={onComplete} />,
    )
    rerender(
      <ProgressiveFluxLoader mode="determinate" value={100} onComplete={onComplete} />,
    )
    expect(onComplete).toHaveBeenCalledTimes(1)

    // A new run (value drops) may complete again.
    rerender(
      <ProgressiveFluxLoader mode="determinate" value={10} onComplete={onComplete} />,
    )
    rerender(
      <ProgressiveFluxLoader mode="determinate" value={100} onComplete={onComplete} />,
    )
    expect(onComplete).toHaveBeenCalledTimes(2)
  })

  it('marks the server-reported phase as current', () => {
    render(
      <ProgressiveFluxLoader
        mode="indeterminate"
        phases={PHASES}
        activePhaseId="analysing"
      />,
    )
    expect(screen.getByText('Analysing').closest('li')).toHaveAttribute(
      'aria-current',
      'step',
    )
    expect(screen.getByText('Queued').closest('li')).not.toHaveAttribute('aria-current')
  })

  it('ignores duplicate and malformed phases', () => {
    render(
      <ProgressiveFluxLoader
        mode="indeterminate"
        phases={[
          { id: 'queued', label: 'Queued' },
          { id: 'queued', label: 'Queued again' },
          { id: '', label: 'Broken' },
        ]}
      />,
    )
    expect(screen.getByText('Queued')).toBeInTheDocument()
    expect(screen.queryByText('Queued again')).not.toBeInTheDocument()
    expect(screen.queryByText('Broken')).not.toBeInTheDocument()
  })

  it('uses the supplied truthful status text', () => {
    render(
      <ProgressiveFluxLoader
        mode="indeterminate"
        statusText="Queued — server has not started yet."
      />,
    )
    expect(screen.getByText(/server has not started yet/i)).toBeInTheDocument()
  })
})
