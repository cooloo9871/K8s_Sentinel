import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { authApi, SESSION_CHECK, SESSION_ENDED, type AuthUser } from '../api/client'

interface AuthState {
  user: AuthUser | null
  loading: boolean
  logout: () => Promise<void>
  refresh: () => Promise<void>
}

const AuthContext = createContext<AuthState>({
  user: null, loading: true, logout: async () => {}, refresh: async () => {},
})

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    authApi.me()
      .then(setUser)
      .catch(() => setUser(null))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    const ended = () => setUser(null)
    // me() answering 401 fires SESSION_ENDED through the interceptor.
    const check = () => { authApi.me().catch(() => {}) }
    window.addEventListener(SESSION_ENDED, ended)
    window.addEventListener(SESSION_CHECK, check)
    return () => {
      window.removeEventListener(SESSION_ENDED, ended)
      window.removeEventListener(SESSION_CHECK, check)
    }
  }, [])

  const logout = async () => {
    await authApi.logout().catch(() => {})
    setUser(null)
  }

  // Re-fetches the current user, used after the forced first-login password
  // change so the app can leave the change screen once the flag clears.
  const refresh = async () => {
    setUser(await authApi.me().catch(() => null))
  }

  return (
    <AuthContext.Provider value={{ user, loading, logout, refresh }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  return useContext(AuthContext)
}
