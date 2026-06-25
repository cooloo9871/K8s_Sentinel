import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AppLayout } from './layout/AppLayout'
import { AppToaster } from './layout/AppToaster'
import { SecurityEventsProvider } from './layout/SecurityEventsProvider'
import { DiscoveryProvider } from './layout/DiscoveryProvider'
import { AdmissionRetentionProvider } from './layout/AdmissionRetentionContext'
import { AuthProvider, useAuth } from './layout/AuthContext'
import { LoginPage } from './pages/LoginPage'
import { DashboardPage } from './pages/DashboardPage'
import { PolicyListPage } from './pages/PolicyListPage'
import { PolicyEditPage } from './pages/PolicyEditPage'
import { ModePage } from './pages/ModePage'

import { SecurityEventsPage } from './pages/SecurityEventsPage'
import { DiscoveryPage } from './pages/DiscoveryPage'
import { TetragonStatusPage } from './pages/TetragonStatusPage'
import { PolicyTemplatesPage } from './pages/PolicyTemplatesPage'
import { UsersPage } from './pages/UsersPage'
import { AlertsPage } from './pages/AlertsPage'

import { AdmissionEventsPage } from './pages/AdmissionEventsPage'
import { VAPPage } from './pages/VAPPage'
import { RsyslogPage } from './pages/RsyslogPage'
import { SecurityRetentionPage } from './pages/SecurityRetentionPage'
import { NetworkTopologyPage } from './pages/NetworkTopologyPage'

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
    <AdmissionRetentionProvider>
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

          <Route path="/cluster/tetragon" element={<TetragonStatusPage />} />
          <Route path="/security/events" element={<SecurityEventsPage />} />
          <Route path="/security/discovery" element={<DiscoveryPage />} />
          <Route path="/settings/users" element={<UsersPage />} />
          <Route path="/security/alerts" element={<AlertsPage />} />
          <Route path="/security/rsyslog" element={<RsyslogPage />} />
          <Route path="/settings/retention" element={<SecurityRetentionPage />} />
          <Route path="/security/admission" element={<AdmissionEventsPage />} />
          <Route path="/policies/admission" element={<VAPPage />} />
          <Route path="/network/topology" element={<NetworkTopologyPage />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Route>
      </Routes>
    </DiscoveryProvider>
    </AdmissionRetentionProvider>
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
