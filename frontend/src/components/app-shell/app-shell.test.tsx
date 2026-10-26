// frontend/src/components/app-shell/app-shell.test.tsx
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AppShell } from './app-shell'
import { ThemeProvider } from './theme-provider'

const HEALTH = {
  status: 'ok',
  service: 'PiQuaChu API',
  version: '2.4.0',
  checks: {
    database: { status: 'ok' },
    rate_limiter: { backend: 'in-memory', failure_mode: 'closed' },
    job_backend: 'threads',
  },
  configuration: {
    environment: 'development',
    tenancy_mode: 'local',
    warnings: [],
  },
}

const SESSION = {
  authenticated: false,
  method: null,
  principal: null,
  permissions: [],
  providers: [],
  configured: false,
  problems: [],
}

function renderShell(initialPath = '/') {
  return render(
    <ThemeProvider>
      <MemoryRouter initialEntries={[initialPath]}>
        <Routes>
          <Route element={<AppShell />}>
            <Route index element={<p>home page</p>} />
            <Route path="scan" element={<p>scan page</p>} />
            <Route path="history" element={<p>history page</p>} />
            <Route path="standards" element={<p>standards page</p>} />
            <Route path="reliability" element={<p>reliability page</p>} />
            <Route path="settings" element={<p>settings page</p>} />
          </Route>
        </Routes>
      </MemoryRouter>
    </ThemeProvider>,
  )
}

function jsonResponse(body: unknown) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

beforeEach(() => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) =>
      String(input).includes('/auth/session') ? jsonResponse(SESSION) : jsonResponse(HEALTH),
    ),
  )
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('AppShell', () => {
  it('renders the top navigation model and the routed page', () => {
    renderShell('/scan')

    const nav = screen.getByRole('navigation', { name: /primary/i })
    expect(within(nav).getByRole('link', { name: /home/i })).toHaveAttribute('href', '/')
    expect(within(nav).getByRole('link', { name: /^scan$/i })).toHaveAttribute('href', '/scan')
    expect(within(nav).getByRole('link', { name: /history/i })).toHaveAttribute('href', '/history')
    expect(within(nav).getByRole('link', { name: /standards/i })).toHaveAttribute('href', '/standards')
    expect(within(nav).getByRole('link', { name: /reliability/i })).toHaveAttribute(
      'href',
      '/reliability',
    )
    expect(screen.getByText('scan page')).toBeInTheDocument()
  })

  it('does not render a permanent sidebar', () => {
    const { container } = renderShell()
    expect(container.querySelector('aside')).toBeNull()
  })

  it('marks the current section with aria-current', () => {
    renderShell('/history')
    const nav = screen.getByRole('navigation', { name: /primary/i })
    expect(within(nav).getByRole('link', { name: /history/i })).toHaveAttribute(
      'aria-current',
      'page',
    )
  })

  it('offers a skip link to the main landmark', () => {
    renderShell()
    expect(screen.getByRole('link', { name: /skip to content/i })).toHaveAttribute(
      'href',
      '#main',
    )
    expect(screen.getByRole('main')).toBeInTheDocument()
  })

  it('toggles the theme class and persists the preference', async () => {
    const user = userEvent.setup()
    renderShell()

    await waitFor(() =>
      expect(document.documentElement.classList.contains('dark')).toBe(true),
    )

    await user.click(screen.getByRole('button', { name: /switch to light theme/i }))

    await waitFor(() =>
      expect(document.documentElement.classList.contains('dark')).toBe(false),
    )
    expect(localStorage.getItem('piquachu.theme')).toBe('light')
  })

  it('opens the mobile navigation as a modal dialog and restores focus on Escape', async () => {
    const user = userEvent.setup()
    renderShell()

    const trigger = screen.getByRole('button', { name: /open navigation/i })
    await user.click(trigger)

    const dialog = screen.getByRole('dialog', { name: /navigation/i })
    expect(dialog).toBeInTheDocument()
    expect(within(dialog).getByRole('link', { name: /home/i })).toBeInTheDocument()

    await user.keyboard('{Escape}')

    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    await waitFor(() => expect(trigger).toHaveFocus())
  })

  it('reports the API connection from a real health response', async () => {
    renderShell()
    await waitFor(() =>
      expect(screen.getAllByText(/api connected/i).length).toBeGreaterThan(0),
    )
  })

  it('shows unavailable (not a green light) when the API cannot be reached', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('Failed to fetch')
      }),
    )
    renderShell()
    await waitFor(() =>
      expect(screen.getAllByText(/api unavailable/i).length).toBeGreaterThan(0),
    )
  })

  it('links to sign-in when the API reports no credential', async () => {
    renderShell()
    const link = await screen.findAllByRole('link', { name: /sign in/i })
    expect(link[0]).toHaveAttribute('href', expect.stringContaining('/login?return_to='))
  })
})
