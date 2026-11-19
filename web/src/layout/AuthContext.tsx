import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { authApi, SESSION_CHECK, SESSION_ENDED, type AuthUser, type Area, type Level } from '../api/client'

interface AuthState {
  user: AuthUser | null
  loading: boolean
  // The account is limited to some namespaces: it sees nothing that belongs to
  // the cluster as a whole. The server enforces it; this hides the dead ends.
  limited: boolean
  // What the account's role grants on an area. Manage includes view. The
  // server decides; this keeps the interface from offering what it would refuse.
  can: (area: Area, level: Exclude<Level, 'none'>) => boolean
  logout: () => Promise<void>
  refresh: () => Promise<void>
}

const AuthContext = createContext<AuthState>({
  user: null, loading: true, limited: false, can: () => false, logout: async () => {}, refresh: async () => {},
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

  const can = (area: Area, level: Exclude<Level, 'none'>) => {
    const has = user?.permissions?.[area]
    return has === 'manage' || (level === 'view' && has === 'view')
  }

  return (
    <AuthContext.Provider value={{ user, loading, limited: (user?.namespaces?.length ?? 0) > 0, can, logout, refresh }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  return useContext(AuthContext)
}
