// frontend/src/pages/results.test.tsx
import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { ScanResultsPage } from './scan-results'
import { jsonResponse, stubScanApi } from '@/test/fixtures'

afterEach(() => {
  vi.unstubAllGlobals()
})

function renderResults(scanId = 12) {
  return render(
    <MemoryRouter initialEntries={[`/results/${scanId}`]}>
      <ScanResultsPage scanId={scanId} />
    </MemoryRouter>,
  )
}

describe('ScanResultsPage', () => {
  it('shows readiness and weighted risk as separate, labelled measures', async () => {
    stubScanApi()
    renderResults()

    expect(await screen.findByRole('heading', { name: 'checkout-service.zip' })).toBeInTheDocument()
    expect(screen.getByText('41')).toBeInTheDocument()
    expect(screen.getByText('72')).toBeInTheDocument()
    expect(screen.getByText(/band: high/i)).toBeInTheDocument()
    expect(screen.getAllByText(/findings/i).length).toBeGreaterThan(0)
  })

  it('opens the assessment methodology panel with the reported formula version', async () => {
    stubScanApi()
    const user = userEvent.setup()
    renderResults()

    const button = await screen.findByRole('button', {
      name: /how readiness and risk are calculated/i,
    })
    await user.click(button)

    const dialog = await screen.findByRole('dialog', { name: /what the assessment means/i })
    expect(within(dialog).getByText(/starts at 100/i)).toBeInTheDocument()
    expect(within(dialog).getByText(/readiness-v1/)).toBeInTheDocument()
    expect(within(dialog).getByText(/risk-v1/)).toBeInTheDocument()
    expect(within(dialog).getByText(/not a compliance certificate/i)).toBeInTheDocument()
  })

  it('explains a standard from the matrix, including detection counts', async () => {
    stubScanApi()
    const user = userEvent.setup()
    renderResults()

    const row = await screen.findByRole('button', { name: /FIPS 203/i })
    await user.click(row)

    const dialog = await screen.findByRole('dialog', { name: /FIPS 203/i })
    expect(within(dialog).getByText(/2 ML-KEM evidence/i)).toBeInTheDocument()
    expect(within(dialog).getByText(/not an approved implementation/i)).toBeInTheDocument()
  })

  it('labels FIPS 206 evidence as in development rather than compliant', async () => {
    stubScanApi()
    renderResults()

    expect(await screen.findByText('in development')).toBeInTheDocument()
    expect(screen.queryByText('PQC evidence')).not.toBeInTheDocument()
  })

  it('links each priority finding to the workbench with its fingerprint', async () => {
    stubScanApi()
    renderResults()

    const link = await screen.findByRole('link', { name: /rsa-keypair/i })
    expect(link).toHaveAttribute('href', '/results/12/findings?finding=fp-rsa')
  })

  it('distinguishes a missing scan from a scan with no findings', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => jsonResponse({ error: 'Unknown scan_id' }, 404)),
    )
    renderResults(99)

    expect(await screen.findByText(/no stored scan with this id/i)).toBeInTheDocument()
  })

  it('renders a valid empty scan without inventing a finding', async () => {
    stubScanApi({
      scan_id: 13,
      timestamp: '2026-10-21T08:30:00Z',
      filename: 'clean.zip',
      pqc_score: 100,
      verdict: 'compliant',
      compliance: { risk_score: 0, risk_level: 'low', findings_count: 0 },
      findings: [],
      remediation_plans: [],
      baseline: null,
      counts: { findings: 0, remediation_plans: 0 },
    })
    render(
      <MemoryRouter>
        <ScanResultsPage scanId={13} />
      </MemoryRouter>,
    )

    expect(await screen.findByRole('heading', { name: 'clean.zip' })).toBeInTheDocument()
    expect(screen.getByText(/no legacy findings were reported/i)).toBeInTheDocument()
    expect(screen.getByText(/not proof that no cryptography exists/i)).toBeInTheDocument()
  })
})
