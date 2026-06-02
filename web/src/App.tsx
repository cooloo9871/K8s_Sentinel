import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AppLayout } from './layout/AppLayout'
import { AppToaster } from './layout/AppToaster'
import { LoginPage } from './pages/LoginPage'
import { DashboardPage } from './pages/DashboardPage'
import { PolicyListPage } from './pages/PolicyListPage'
import { PolicyEditPage } from './pages/PolicyEditPage'
import { ModePage } from './pages/ModePage'
import { NamespacesPage } from './pages/NamespacesPage'

export default function App() {
  return (
    <BrowserRouter>
      <AppToaster>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route element={<AppLayout />}>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/policies" element={<Navigate to="/policies/tracing" replace />} />
            <Route path="/policies/tracing" element={<PolicyListPage />} />
            <Route path="/policies/tracing/new" element={<PolicyEditPage />} />
            <Route path="/policies/tracing/:name/edit" element={<PolicyEditPage />} />
            <Route path="/cluster/mode" element={<ModePage />} />
            <Route path="/cluster/namespaces" element={<NamespacesPage />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Route>
        </Routes>
      </AppToaster>
    </BrowserRouter>
  )
}
