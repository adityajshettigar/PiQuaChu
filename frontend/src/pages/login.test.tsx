// frontend/src/pages/login.test.tsx
import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { LoginPage } from './login'
import { jsonResponse, SESSION_UNAUTHENTICATED } from '@/test/fixtures'

const SESSION_CONFIGURED = {
  ...SESSION_UNAUTHENTICATED,
  configured: true,
  provider: 'Example SSO',
  issuer: 'https://id.example.com',
  problems: [],
  providers: [
    {
      id: 'oidc',
      name: 'Example SSO',
      issuer: 'https://id.example.com',
      scopes: 'openid profile email',
    },
  ],
}

afterEach(() => {
  vi.unstubAllGlobals()
})

function renderLogin(path: string) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => jsonResponse(SESSION_CONFIGURED)),
  )
  return render(
    <MemoryRouter initialEntries={[path]}>
      <LoginPage />
    </MemoryRouter>,
  )
}

describe('LoginPage', () => {
  it('offers the configured provider through the server login endpoint', async () => {
    renderLogin('/login?return_to=%2Fresults%2F12')

    const link = await screen.findByRole('link', { name: /continue with example sso/i })
    expect(link.getAttribute('href')).toMatch(
      /\/api\/v1\/auth\/login\?return_to=%2Fresults%2F12$/,
    )
    expect(screen.getByText('https://id.example.com')).toBeInTheDocument()
  })

  it('rejects an external return URL and falls back to the home path', async () => {
    renderLogin('/login?return_to=%2F%2Fevil.example')

    const link = await screen.findByRole('link', { name: /continue with example sso/i })
    expect(link.getAttribute('href')).toMatch(/return_to=%2F$/)
  })

  it('shows an already-signed-in state without offering a second login', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse({
          ...SESSION_CONFIGURED,
          authenticated: true,
          method: 'session',
          principal: { id: 'oidc:abc', tenant_id: 'local', name: 'Ada', role: 'analyst' },
        }),
      ),
    )

    render(
      <MemoryRouter initialEntries={['/login']}>
        <LoginPage />
      </MemoryRouter>,
    )

    expect(await screen.findByText('Ada')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /continue/i })).toHaveAttribute('href', '/')
    expect(
      screen.queryByRole('link', { name: /continue with example sso/i }),
    ).not.toBeInTheDocument()
  })

  it('reports a failed callback instead of implying success', async () => {
    renderLogin('/login?error=sso_failed')

    expect(
      await screen.findByText(/the sign-in did not complete/i),
    ).toBeInTheDocument()
  })
})
