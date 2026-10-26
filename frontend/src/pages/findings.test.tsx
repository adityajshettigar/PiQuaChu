// frontend/src/pages/findings.test.tsx
import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { FindingsPage } from './findings'
import { stubScanApi } from '@/test/fixtures'

afterEach(() => {
  vi.unstubAllGlobals()
})

function renderFindings() {
  return render(
    <MemoryRouter initialEntries={['/results/12/findings']}>
      <FindingsPage scanId={12} />
    </MemoryRouter>,
  )
}

describe('FindingsPage', () => {
  it('lists the stored findings with their rule, location and standard', async () => {
    stubScanApi()
    renderFindings()

    expect((await screen.findAllByText('rsa-keypair')).length).toBeGreaterThan(0)
    expect(screen.getAllByText('weak-crypto-md5').length).toBeGreaterThan(0)
    expect(screen.getAllByText(/src\/auth\/Keys.java/i).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/FIPS 203/).length).toBeGreaterThan(0)
  })

  it('filters by search and says when nothing matches, without hiding the total', async () => {
    stubScanApi()
    const user = userEvent.setup()
    renderFindings()

    const search = await screen.findByLabelText(/search/i)
    await user.type(search, 'definitely-not-present')

    expect(await screen.findByText(/no findings match these filters/i)).toBeInTheDocument()
    expect(screen.getByText(/the scan still contains 2 finding/i)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /clear filters/i }))
    expect((await screen.findAllByText('rsa-keypair')).length).toBeGreaterThan(0)
  })

  it('filters by severity without changing the scan identity', async () => {
    stubScanApi()
    const user = userEvent.setup()
    renderFindings()

    await screen.findAllByText('rsa-keypair')
    await user.selectOptions(screen.getByLabelText(/severity/i), 'WARNING')

    expect((await screen.findAllByText('weak-crypto-md5')).length).toBeGreaterThan(0)
    expect(screen.queryAllByText('rsa-keypair')).toHaveLength(0)
    expect(screen.getByText(/scan #12/i)).toBeInTheDocument()
  })

  it('opens a finding with evidence, recommendation and limitations as text', async () => {
    stubScanApi()
    const user = userEvent.setup()
    renderFindings()

    const [row] = await screen.findAllByText('rsa-keypair')
    await user.click(row)

    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/why the rule matched/i)).toBeInTheDocument()
    expect(within(dialog).getByText(/RSA key generation in a key-establishment path/i)).toBeInTheDocument()
    expect(within(dialog).getByText(/KeyPairGenerator kpg/)).toBeInTheDocument()
    expect(within(dialog).getByText(/Replace RSA key transport with ML-KEM/i)).toBeInTheDocument()
    expect(within(dialog).getByText(/static pattern evidence only/i)).toBeInTheDocument()
  })

  it('reports an unavailable scan instead of an empty table', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(JSON.stringify({ error: 'Unknown scan_id' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        }),
      ),
    )
    render(
      <MemoryRouter>
        <FindingsPage scanId={404} />
      </MemoryRouter>,
    )

    expect(await screen.findByText(/no stored scan with this id/i)).toBeInTheDocument()
  })
})
