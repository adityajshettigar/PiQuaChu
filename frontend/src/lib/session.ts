// frontend/src/lib/session.ts
//
// One small hook for "who is this browser, as far as the API is concerned".
// It reads the backend's own answer (/api/v1/auth/session) — it never assumes
// a user is signed in because a cookie exists client-side.
import { useCallback, useEffect, useRef, useState } from 'react'
import { api, ApiError, type AuthSessionResponse } from './api'

export type SessionLoadState = 'loading' | 'ready' | 'error'

export interface SessionState {
  state: SessionLoadState
  session: AuthSessionResponse | null
  error: string | null
  reload: () => void
  signOut: () => Promise<void>
}

export function useSession(): SessionState {
  const [state, setState] = useState<SessionLoadState>('loading')
  const [session, setSession] = useState<AuthSessionResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const controllerRef = useRef<AbortController | null>(null)

  const request = useCallback(() => {
    controllerRef.current?.abort()
    const controller = new AbortController()
    controllerRef.current = controller
    api.session(controller.signal).then(
      (result) => {
        // TypeScript does not validate network JSON: reject a shape the UI
        // cannot reason about instead of treating it as signed-out.
        if (
          !result ||
          typeof result.authenticated !== 'boolean' ||
          !Array.isArray(result.providers) ||
          !Array.isArray(result.problems)
        ) {
          setError('The session endpoint returned a response this interface could not read.')
          setState('error')
          return
        }
        setSession(result)
        setError(null)
        setState('ready')
      },
      (err: unknown) => {
        if (err instanceof ApiError && err.kind === 'aborted') return
        setError(err instanceof ApiError ? err.message : 'Session state is unavailable.')
        setState('error')
      },
    )
  }, [])

  useEffect(() => {
    request()
    return () => controllerRef.current?.abort()
  }, [request])

  const reload = useCallback(() => {
    setState('loading')
    request()
  }, [request])

  const signOut = useCallback(async () => {
    try {
      await api.logout()
    } catch {
      // A failed logout still clears the local view; the cookie may already be
      // gone (expired session) and the server state is re-read below.
    }
    reload()
  }, [reload])

  return { state, session, error, reload, signOut }
}
