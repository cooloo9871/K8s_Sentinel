import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AppLayout } from './layout/AppLayout'
import { AppToaster } from './layout/AppToaster'
import { SecurityEventsProvider } from './layout/SecurityEventsProvider'
import { DiscoveryProvider } from './layout/DiscoveryProvider'
import { AuthProvider, useAuth } from './layout/AuthContext'
import { LoginPage } from './pages/LoginPage'
import { DashboardPage } from './pages/DashboardPage'
import { PolicyListPage } from './pages/PolicyListPage'
import { PolicyEditPage } from './pages/PolicyEditPage'
import { ModePage } from './pages/ModePage'
import { NamespacesPage } from './pages/NamespacesPage'
import { SecurityEventsPage } from './pages/SecurityEventsPage'
import { DiscoveryPage } from './pages/DiscoveryPage'
import { TetragonStatusPage } from './pages/TetragonStatusPage'
import { PolicyTemplatesPage } from './pages/PolicyTemplatesPage'
import { UsersPage } from './pages/UsersPage'

function AppRoutes() {
  const { user, loading, logout } = useAuth()

  if (loading) return null

  if (!user) {
    return (
      <LoginPage onLogin={() => window.location.replace('/dashboard')} />
    )
  }

  return (
    <SecurityEventsProvider>
    <DiscoveryProvider>
      <Routes>
        <Route element={<AppLayout onLogout={logout} />}>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/policies" element={<Navigate to="/policies/tracing" replace />} />
          <Route path="/policies/tracing" element={<PolicyListPage />} />
          <Route path="/policies/tracing/new" element={<PolicyEditPage />} />
          <Route path="/policies/templates" element={<PolicyTemplatesPage />} />
          <Route path="/policies/tracing/:name/edit" element={<PolicyEditPage />} />
          <Route path="/cluster/mode" element={<ModePage />} />
          <Route path="/cluster/namespaces" element={<NamespacesPage />} />
          <Route path="/cluster/tetragon" element={<TetragonStatusPage />} />
          <Route path="/security/events" element={<SecurityEventsPage />} />
          <Route path="/security/discovery" element={<DiscoveryPage />} />
          <Route path="/settings/users" element={<UsersPage />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Route>
      </Routes>
    </DiscoveryProvider>
    </SecurityEventsProvider>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <AppToaster>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </AppToaster>
    </BrowserRouter>
  )
}
