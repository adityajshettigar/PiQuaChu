// frontend/src/lib/api.test.ts
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api, apiFetch, API_BASE_URL, API_KEY, ApiError, loginUrl } from './api'

function mockFetch(impl: typeof fetch) {
  vi.stubGlobal('fetch', impl)
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('apiFetch', () => {
  it('returns parsed JSON on success', async () => {
    mockFetch(
      vi.fn(async () =>
        new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      ) as unknown as typeof fetch,
    )
    await expect(apiFetch<{ ok: boolean }>('/x')).resolves.toEqual({ ok: true })
  })

  it.each([
    [401, 'unauthorized'],
    [403, 'forbidden'],
    [404, 'not_found'],
    [413, 'too_large'],
    [429, 'rate_limited'],
    [500, 'server'],
    [418, 'unknown'],
  ])('maps HTTP %i to the %s kind', async (status, kind) => {
    mockFetch(
      vi.fn(async () => new Response('{}', { status })) as unknown as typeof fetch,
    )
    await expect(apiFetch('/x')).rejects.toMatchObject({ kind })
  })

  it('explains a missing key instead of blaming a key that was never sent', async () => {
    mockFetch(
      vi.fn(async () => new Response('{"error":"Unauthorized."}', { status: 401 })) as unknown as typeof fetch,
    )
    const error = await apiFetch('/x').catch((thrown: unknown) => thrown)

    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({ kind: 'unauthorized', status: 401 })
    // `API_KEY` is baked in at build time; only assert the wording when the
    // test run genuinely has no key configured.
    if (!API_KEY) {
      expect((error as ApiError).message).toMatch(/no X-API-Key is configured/i)
    }
  })

  it('maps a transport failure to a network error', async () => {
    mockFetch(vi.fn(async () => {
      throw new TypeError('Failed to fetch')
    }) as unknown as typeof fetch)
    await expect(apiFetch('/x')).rejects.toBeInstanceOf(ApiError)
    await expect(apiFetch('/x')).rejects.toMatchObject({ kind: 'network' })
  })

  it('maps an aborted request to the aborted kind', async () => {
    mockFetch(vi.fn(async () => {
      throw new DOMException('aborted', 'AbortError')
    }) as unknown as typeof fetch)
    await expect(apiFetch('/x')).rejects.toMatchObject({ kind: 'aborted' })
  })

  it('rejects malformed JSON instead of returning a partial object', async () => {
    mockFetch(
      vi.fn(async () =>
        new Response('<html>not json</html>', { status: 200 }),
      ) as unknown as typeof fetch,
    )
    await expect(apiFetch('/x')).rejects.toMatchObject({ kind: 'malformed' })
  })

  it('does not parse JSON for export requests', async () => {
    const response = new Response('dummy', { status: 200 })
    mockFetch(vi.fn(async () => response) as unknown as typeof fetch)
    const result = await apiFetch<Response>('/x', { parseJson: false })
    expect(result).toBe(response)
  })
})

describe('typed helpers', () => {
  it('addresses a stored scan by its numeric id', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL) =>
      new Response(JSON.stringify({ scan_id: 12, findings: [] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    mockFetch(fetchMock as unknown as typeof fetch)

    await api.scan(12)

    expect(String(fetchMock.mock.calls[0][0])).toBe(`${API_BASE_URL}/api/v1/scans/12`)
  })

  it('sends the scan id with an assistant question as JSON', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      new Response(JSON.stringify({ answer: 'ok' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    mockFetch(fetchMock as unknown as typeof fetch)

    await api.assistant('What first?', 5)

    const init = fetchMock.mock.calls[0][1]
    expect(init?.method).toBe('POST')
    expect(init?.body).toBe(JSON.stringify({ question: 'What first?', scan_id: 5 }))
    expect((init?.headers as Record<string, string>)['Content-Type']).toBe('application/json')
  })

  it('reports a missing stored scan as not_found', async () => {
    mockFetch(vi.fn(async () => new Response('{}', { status: 404 })) as unknown as typeof fetch)
    await expect(api.scan(999)).rejects.toMatchObject({ kind: 'not_found' })
  })

  it('builds a login URL with an encoded return path', () => {
    expect(loginUrl('/results/12?tab=findings')).toBe(
      `${API_BASE_URL}/api/v1/auth/login?return_to=%2Fresults%2F12%3Ftab%3Dfindings`,
    )
  })
})
