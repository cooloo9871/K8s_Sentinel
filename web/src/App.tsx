import { Fragment, type ReactElement, type ReactNode } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AppLayout } from './layout/AppLayout'
import { AppToaster } from './layout/AppToaster'
import { SecurityEventsProvider } from './layout/SecurityEventsProvider'
import { AdmissionEventsProvider } from './layout/AdmissionEventsProvider'
import { DiscoveryProvider } from './layout/DiscoveryProvider'
import { AuthProvider, useAuth } from './layout/AuthContext'
import type { Area } from './api/client'
import { RolesPage } from './pages/RolesPage'
import { LoginPage } from './pages/LoginPage'
import { ForcePasswordChangePage } from './pages/ForcePasswordChangePage'
import { DashboardPage } from './pages/DashboardPage'
import { PolicyListPage } from './pages/PolicyListPage'
import { PolicyEditPage } from './pages/PolicyEditPage'

import { SecurityEventsPage } from './pages/SecurityEventsPage'
import { DiscoveryPage } from './pages/DiscoveryPage'
import { TetragonStatusPage } from './pages/TetragonStatusPage'
import { PolicyTemplatesPage } from './pages/PolicyTemplatesPage'
import { UsersPage } from './pages/UsersPage'
import { AlertsPage } from './pages/AlertsPage'

import { AdmissionEventsPage } from './pages/AdmissionEventsPage'
import { VAPPage } from './pages/VAPPage'
import { QuarantinePage } from './pages/QuarantinePage'
import { CNPPage } from './pages/CNPPage'
import { RsyslogPage } from './pages/RsyslogPage'
import { SecurityRetentionPage } from './pages/SecurityRetentionPage'
import { AuditLogPage } from './pages/AuditLogPage'
import { NetworkTopologyPage } from './pages/NetworkTopologyPage'
import { VulnerabilitiesPage } from './pages/VulnerabilitiesPage'
import { RegistriesPage } from './pages/RegistriesPage'

function EventProviders({ children }: { children: ReactNode }) {
  return (
    <SecurityEventsProvider>
      <AdmissionEventsProvider>{children}</AdmissionEventsProvider>
    </SecurityEventsProvider>
  )
}

function AppRoutes() {
  const { user, loading, limited, can, logout, refresh } = useAuth()

  if (loading) return null

  if (!user) {
    return (
      <LoginPage onLogin={() => window.location.replace('/dashboard')} />
    )
  }

  // The default admin must set a real password before reaching the app; the
  // backend enforces the same gate, this makes it the only thing on screen.
  if (user.mustChangePassword) {
    return <ForcePasswordChangePage username={user.username} onDone={refresh} />
  }

  // A page about the cluster as a whole has nothing to show an account that is
  // limited to namespaces; a link to one lands on the dashboard.
  // The same goes for a page the account's role does not show it.
  const page = (area: Area, element: ReactElement, clusterOnly = false) =>
    !can(area, 'view') || (clusterOnly && limited) ? <Navigate to="/dashboard" replace /> : element

  // Without the permission there is nothing to stream, and asking would only
  // be refused over and over.
  const Events = can('events', 'view') ? EventProviders : Fragment
  const Discovery = can('tracing', 'view') ? DiscoveryProvider : Fragment

  return (
    <Events>
    <Discovery>
      <Routes>
        <Route element={<AppLayout onLogout={logout} />}>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/policies" element={<Navigate to="/policies/tracing" replace />} />
          <Route path="/policies/tracing" element={page('tracing', <PolicyListPage />)} />
          <Route path="/policies/tracing/new" element={page('tracing', <PolicyEditPage />)} />
          <Route path="/policies/templates" element={page('tracing', <PolicyTemplatesPage />)} />

          <Route path="/policies/tracing/:name/edit" element={page('tracing', <PolicyEditPage />)} />

          <Route path="/cluster/tetragon" element={page('events', <TetragonStatusPage />, true)} />
          <Route path="/security/events" element={page('events', <SecurityEventsPage />)} />
          <Route path="/security/discovery" element={page('tracing', <DiscoveryPage />)} />
          <Route path="/settings/users" element={page('system', <UsersPage />, true)} />
          <Route path="/settings/users/new" element={page('system', <UsersPage />, true)} />
          <Route path="/settings/roles" element={page('system', <RolesPage />, true)} />
          <Route path="/settings/roles/new" element={page('system', <RolesPage />, true)} />
          <Route path="/settings/roles/:name/edit" element={page('system', <RolesPage />, true)} />
          <Route path="/security/alerts" element={page('notifications', <AlertsPage />, true)} />
          <Route path="/security/alerts/new" element={page('notifications', <AlertsPage />, true)} />
          <Route path="/security/alerts/:id/edit" element={page('notifications', <AlertsPage />, true)} />
          <Route path="/security/rsyslog" element={page('notifications', <RsyslogPage />, true)} />
          <Route path="/security/rsyslog/new" element={page('notifications', <RsyslogPage />, true)} />
          <Route path="/security/rsyslog/:id/edit" element={page('notifications', <RsyslogPage />, true)} />
          <Route path="/settings/retention" element={page('system', <SecurityRetentionPage />, true)} />
          <Route path="/settings/audit" element={page('system', <AuditLogPage />, true)} />
          <Route path="/security/admission" element={page('events', <AdmissionEventsPage />)} />
          <Route path="/policies/admission" element={page('admission', <VAPPage />)} />
          <Route path="/policies/admission/new" element={page('admission', <VAPPage />)} />
          <Route path="/policies/admission/:name/edit" element={page('admission', <VAPPage />)} />
          <Route path="/policies/admission/bindings/new" element={page('admission', <VAPPage />)} />
          <Route path="/policies/admission/bindings/:name/edit" element={page('admission', <VAPPage />)} />
          <Route path="/policies/network" element={page('network', <CNPPage />)} />
          <Route path="/policies/network/new" element={page('network', <CNPPage />)} />
          <Route path="/policies/network/:name/edit" element={page('network', <CNPPage />)} />
          <Route path="/policies/quarantine" element={page('quarantine', <QuarantinePage />)} />
          <Route path="/network/topology" element={page('network', <NetworkTopologyPage />)} />
          <Route path="/vulnerabilities" element={page('vulnerabilities', <VulnerabilitiesPage />)} />
          <Route path="/registries" element={page('vulnerabilities', <RegistriesPage />, true)} />
          <Route path="/registries/new" element={page('vulnerabilities', <RegistriesPage />, true)} />
          <Route path="/registries/:id" element={page('vulnerabilities', <RegistriesPage />, true)} />
          <Route path="/registries/:id/edit" element={page('vulnerabilities', <RegistriesPage />, true)} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Route>
      </Routes>
    </Discovery>
    </Events>
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
