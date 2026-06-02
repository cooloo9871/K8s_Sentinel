# Sentinel UI Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Ant Design with CoreUI React to achieve a NeuVector-style enterprise security console UI with dark sidebar, light content area, Dashboard page, and reorganised navigation.

**Architecture:** The layout shell (`AppLayout`) wraps all authenticated routes via React Router's `<Outlet>`, providing a fixed dark `CSidebar` and a `CHeader`. A React context (`AppToaster`) replaces Ant Design's global `message.*` API. The `PolicyForm` component switches from `Form.useForm()` to plain `useState` arrays; `PolicyEditPage` owns all form/YAML state and exposes a single Save button in the header.

**Tech Stack:** React 19, Vite 8, TypeScript, React Router DOM 7, `@coreui/react` 5.x, `@coreui/coreui` 5.x (CSS), `@coreui/icons-react` 2.x, `@monaco-editor/react` (unchanged), Axios (unchanged)

---

## File Map

| Action | Path | Responsibility |
|---|---|---|
| Modify | `web/package.json` | swap antd → CoreUI packages |
| Rewrite | `web/src/main.tsx` | import CoreUI CSS |
| Rewrite | `web/src/index.css` | remove dark theme, bare reset |
| Delete | `web/src/App.css` | unused after layout moves to AppLayout |
| Rewrite | `web/src/App.tsx` | new route tree with AppLayout |
| **Create** | `web/src/layout/AppToaster.tsx` | global toast context + CToaster |
| **Create** | `web/src/layout/AppSidebar.tsx` | CSidebar multi-level nav |
| **Create** | `web/src/layout/AppHeader.tsx` | CHeader + breadcrumb + mode badge |
| **Create** | `web/src/layout/AppLayout.tsx` | flex wrapper using Outlet |
| Rewrite | `web/src/pages/LoginPage.tsx` | CCard + CForm |
| **Create** | `web/src/pages/DashboardPage.tsx` | stat cards + recent policies table |
| **Create** | `web/src/components/StatCard.tsx` | reusable stat card |
| Rewrite | `web/src/pages/PolicyListPage.tsx` | CTable + search + CModal delete |
| Rewrite | `web/src/components/PolicyForm/ProcessSection.tsx` | Bootstrap inputs |
| Rewrite | `web/src/components/PolicyForm/FileSection.tsx` | Bootstrap inputs |
| Rewrite | `web/src/components/PolicyForm/NetworkSection.tsx` | Bootstrap inputs |
| Rewrite | `web/src/components/PolicyForm/PolicyForm.tsx` | useState-driven, YAML preview inline |
| Delete | `web/src/components/PolicyForm/YamlPreview.tsx` | inlined into PolicyForm |
| Rewrite | `web/src/pages/PolicyEditPage.tsx` | CTabs, header Save/Cancel |
| Rewrite | `web/src/components/YamlEditor.tsx` | remove own Apply btn, add onValueChange |
| **Create** | `web/src/pages/ModePage.tsx` | mode display + switch |
| **Create** | `web/src/pages/NamespacesPage.tsx` | namespace list with policy count |
| Delete | `web/src/components/ModeToggle.tsx` | replaced by ModePage + header badge |

---

## Task 1: Swap npm Packages

**Files:**
- Modify: `web/package.json`

- [ ] **Step 1: Uninstall Ant Design**

```bash
cd web && npm uninstall antd @ant-design/icons
```

Expected: no errors, `antd` and `@ant-design/icons` removed from `package.json`.

- [ ] **Step 2: Install CoreUI packages**

```bash
npm install @coreui/react @coreui/coreui @coreui/icons @coreui/icons-react
```

If peer-dep warnings appear about React 19, add `--legacy-peer-deps`. Expected: 4 packages added to `dependencies`.

- [ ] **Step 3: Verify package.json dependencies section**

`package.json` `dependencies` should now contain:
```json
"@coreui/coreui": "^5.x.x",
"@coreui/icons": "^2.x.x",
"@coreui/icons-react": "^2.x.x",
"@coreui/react": "^5.x.x",
"@monaco-editor/react": "^4.7.0",
"axios": "^1.16.1",
"js-yaml": "^4.1.1",
"react": "^19.2.6",
"react-dom": "^19.2.6",
"react-router-dom": "^7.15.1"
```
`antd` and `@ant-design/icons` must NOT appear.

- [ ] **Step 4: Commit**

```bash
git add web/package.json web/package-lock.json
git commit -m "chore: swap antd for @coreui/react"
```

---

## Task 2: Replace Global Styles & CSS Entry

**Files:**
- Rewrite: `web/src/main.tsx`
- Rewrite: `web/src/index.css`
- Delete: `web/src/App.css`

- [ ] **Step 1: Rewrite `web/src/main.tsx`**

Replace the entire file:

```tsx
import React from 'react'
import ReactDOM from 'react-dom/client'
import '@coreui/coreui/dist/css/coreui.min.css'
import App from './App.tsx'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
```

- [ ] **Step 2: Rewrite `web/src/index.css`**

Replace the entire file with a minimal reset that doesn't override CoreUI:

```css
*, *::before, *::after {
  box-sizing: border-box;
}
```

- [ ] **Step 3: Delete `web/src/App.css`**

```bash
rm web/src/App.css
```

- [ ] **Step 4: Remove App.css import from App.tsx**

Open `web/src/App.tsx` and remove the line `import './App.css'` if it exists. (Check first — the current file doesn't import it, so this step may be a no-op.)

- [ ] **Step 5: Verify build still compiles**

```bash
cd web && npm run build 2>&1 | tail -20
```

Expected: TypeScript errors about missing antd imports in existing pages — that is expected and will be fixed in subsequent tasks. The Vite bundler itself should not crash. If you see `Cannot find module '@coreui/coreui'`, re-run `npm install`.

- [ ] **Step 6: Verify existing unit tests still pass**

```bash
npm run test
```

Expected: `formToYaml.test.ts` tests PASS (they have no UI dependencies).

- [ ] **Step 7: Commit**

```bash
git add web/src/main.tsx web/src/index.css
git rm web/src/App.css
git commit -m "chore: replace global styles with CoreUI CSS"
```

---

## Task 3: AppToaster — Global Toast Context

**Files:**
- Create: `web/src/layout/AppToaster.tsx`

- [ ] **Step 1: Create the layout directory**

```bash
mkdir -p web/src/layout
```

- [ ] **Step 2: Write `web/src/layout/AppToaster.tsx`**

```tsx
import { createContext, useCallback, useContext, useRef, useState } from 'react'
import { CToast, CToastBody, CToaster } from '@coreui/react'

interface ToastItem { id: number; color: string; message: string }

interface ToastContextValue {
  success: (msg: string) => void
  error: (msg: string) => void
}

const ToastContext = createContext<ToastContextValue>({
  success: () => {},
  error: () => {},
})

export function useToast() {
  return useContext(ToastContext)
}

export function AppToaster({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([])
  const nextId = useRef(0)

  const addToast = useCallback((color: string, message: string) => {
    const id = ++nextId.current
    setToasts((prev) => [...prev, { id, color, message }])
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id))
    }, 4000)
  }, [])

  const value: ToastContextValue = {
    success: (msg) => addToast('success', msg),
    error: (msg) => addToast('danger', msg),
  }

  return (
    <ToastContext.Provider value={value}>
      {children}
      <CToaster
        placement="top-end"
        style={{ position: 'fixed', top: '1rem', right: '1rem', zIndex: 9999 }}
      >
        {toasts.map((t) => (
          <CToast key={t.id} visible autohide={false} color={t.color}>
            <CToastBody className="text-white">{t.message}</CToastBody>
          </CToast>
        ))}
      </CToaster>
    </ToastContext.Provider>
  )
}
```

- [ ] **Step 3: Verify TypeScript compiles this file in isolation**

```bash
cd web && npx tsc --noEmit --skipLibCheck 2>&1 | grep AppToaster
```

Expected: no output (no errors for AppToaster).

- [ ] **Step 4: Commit**

```bash
git add web/src/layout/AppToaster.tsx
git commit -m "feat: add AppToaster global toast context"
```

---

## Task 4: AppSidebar

**Files:**
- Create: `web/src/layout/AppSidebar.tsx`

- [ ] **Step 1: Write `web/src/layout/AppSidebar.tsx`**

```tsx
import {
  CSidebar,
  CSidebarBrand,
  CSidebarNav,
  CNavTitle,
  CNavItem,
  CNavGroup,
} from '@coreui/react'
import { NavLink } from 'react-router-dom'

export function AppSidebar() {
  return (
    <CSidebar
      colorScheme="dark"
      style={{ background: '#1b2a3b', minHeight: '100vh', width: 240, flexShrink: 0 }}
    >
      <CSidebarBrand
        style={{
          background: '#142030',
          color: '#fff',
          fontWeight: 700,
          fontSize: '1.1rem',
          padding: '1rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
        }}
      >
        <span
          style={{
            width: 28,
            height: 28,
            background: '#2d7dd2',
            borderRadius: 6,
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
            <rect x="1" y="1" width="12" height="12" rx="2" stroke="white" strokeWidth="2" />
          </svg>
        </span>
        Sentinel
      </CSidebarBrand>

      <CSidebarNav>
        <CNavItem component={NavLink} to="/dashboard">
          Dashboard
        </CNavItem>

        <CNavTitle>Policies</CNavTitle>
        <CNavGroup toggler="All Policies" visible>
          <CNavItem component={NavLink} to="/policies/tracing">
            TracingPolicy
          </CNavItem>
        </CNavGroup>

        <CNavTitle>Cluster</CNavTitle>
        <CNavItem component={NavLink} to="/cluster/mode">
          Mode Control
        </CNavItem>
        <CNavItem component={NavLink} to="/cluster/namespaces">
          Namespaces
        </CNavItem>
      </CSidebarNav>
    </CSidebar>
  )
}
```

- [ ] **Step 2: Verify TypeScript compiles**

```bash
cd web && npx tsc --noEmit --skipLibCheck 2>&1 | grep AppSidebar
```

Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add web/src/layout/AppSidebar.tsx
git commit -m "feat: add AppSidebar with CoreUI CSidebar navigation"
```

---

## Task 5: AppHeader

**Files:**
- Create: `web/src/layout/AppHeader.tsx`

- [ ] **Step 1: Write `web/src/layout/AppHeader.tsx`**

```tsx
import { useEffect, useState } from 'react'
import { useLocation, useNavigate, Link } from 'react-router-dom'
import {
  CHeader,
  CHeaderNav,
  CContainer,
  CBreadcrumb,
  CBreadcrumbItem,
  CBadge,
  CDropdown,
  CDropdownToggle,
  CDropdownMenu,
  CDropdownItem,
} from '@coreui/react'
import { modeApi, authApi } from '../api/client'
import type { Mode } from '../api/types'

const ROUTE_LABELS: Record<string, string> = {
  '': 'Home',
  dashboard: 'Dashboard',
  policies: 'Policies',
  tracing: 'TracingPolicy',
  new: 'New Policy',
  cluster: 'Cluster',
  mode: 'Mode Control',
  namespaces: 'Namespaces',
}

function useBreadcrumbs() {
  const { pathname } = useLocation()
  const segments = pathname.split('/').filter(Boolean)
  const crumbs: { label: string; to?: string }[] = [{ label: 'Home', to: '/dashboard' }]
  let path = ''
  segments.forEach((seg, i) => {
    path += `/${seg}`
    const isLast = i === segments.length - 1
    const label = ROUTE_LABELS[seg] ?? seg
    crumbs.push(isLast ? { label } : { label, to: path })
  })
  return crumbs
}

export function AppHeader() {
  const [mode, setMode] = useState<Mode>('Monitoring')
  const navigate = useNavigate()
  const breadcrumbs = useBreadcrumbs()

  useEffect(() => {
    modeApi.get().then(setMode).catch(() => {})
  }, [])

  const handleLogout = async () => {
    await authApi.logout()
    navigate('/login')
  }

  const modeColor = mode === 'Protect' ? 'danger' : mode === 'Mixed' ? 'warning' : 'success'

  return (
    <CHeader position="sticky" className="mb-4" style={{ background: '#fff', borderBottom: '1px solid #dee2e6' }}>
      <CContainer fluid>
        <CBreadcrumb style={{ margin: 0 }}>
          {breadcrumbs.map((c, i) =>
            c.to ? (
              <CBreadcrumbItem key={i}>
                <Link to={c.to} style={{ color: '#2d7dd2', textDecoration: 'none' }}>
                  {c.label}
                </Link>
              </CBreadcrumbItem>
            ) : (
              <CBreadcrumbItem key={i} active>
                {c.label}
              </CBreadcrumbItem>
            )
          )}
        </CBreadcrumb>

        <CHeaderNav className="ms-auto">
          <CBadge color={modeColor} className="me-3">
            {mode.toUpperCase()}
          </CBadge>
          <CDropdown variant="nav-item">
            <CDropdownToggle caret={false}>admin</CDropdownToggle>
            <CDropdownMenu>
              <CDropdownItem onClick={handleLogout} style={{ cursor: 'pointer' }}>
                Logout
              </CDropdownItem>
            </CDropdownMenu>
          </CDropdown>
        </CHeaderNav>
      </CContainer>
    </CHeader>
  )
}
```

- [ ] **Step 2: Verify TypeScript compiles**

```bash
cd web && npx tsc --noEmit --skipLibCheck 2>&1 | grep AppHeader
```

Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add web/src/layout/AppHeader.tsx
git commit -m "feat: add AppHeader with breadcrumb and mode badge"
```

---

## Task 6: AppLayout + Update App.tsx Routing

**Files:**
- Create: `web/src/layout/AppLayout.tsx`
- Rewrite: `web/src/App.tsx`

- [ ] **Step 1: Write `web/src/layout/AppLayout.tsx`**

```tsx
import { Outlet } from 'react-router-dom'
import { CContainer } from '@coreui/react'
import { AppSidebar } from './AppSidebar'
import { AppHeader } from './AppHeader'

export function AppLayout() {
  return (
    <div style={{ display: 'flex', minHeight: '100vh' }}>
      <AppSidebar />
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        <AppHeader />
        <main style={{ flex: 1, background: '#f5f6fa' }}>
          <CContainer lg className="py-4">
            <Outlet />
          </CContainer>
        </main>
      </div>
    </div>
  )
}
```

- [ ] **Step 2: Rewrite `web/src/App.tsx`**

Replace the entire file. The imports for the new pages will resolve once those files are created in later tasks — TypeScript will error on missing modules until then, but the structure is correct:

```tsx
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
```

- [ ] **Step 3: Commit**

```bash
git add web/src/layout/AppLayout.tsx web/src/App.tsx
git commit -m "feat: add AppLayout and update route tree"
```

> **Note:** After this commit, `npm run build` will show TypeScript errors for missing page imports (`DashboardPage`, `ModePage`, `NamespacesPage`). This is expected — those files are created in Tasks 9, 15, 16. The build will be clean after Task 17.

---

## Task 7: LoginPage

**Files:**
- Rewrite: `web/src/pages/LoginPage.tsx`

- [ ] **Step 1: Rewrite `web/src/pages/LoginPage.tsx`**

```tsx
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  CCard,
  CCardBody,
  CForm,
  CFormInput,
  CFormLabel,
  CButton,
  CAlert,
} from '@coreui/react'
import { authApi } from '../api/client'

export function LoginPage() {
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      await authApi.login(username, password)
      navigate('/dashboard')
    } catch {
      setError('Invalid username or password')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        minHeight: '100vh',
        background: '#f5f6fa',
      }}
    >
      <CCard style={{ width: 400 }}>
        <CCardBody className="p-4">
          <h4 className="text-center mb-4" style={{ color: '#1b2a3b', fontWeight: 700 }}>
            Sentinel
          </h4>
          {error && (
            <CAlert color="danger" className="mb-3">
              {error}
            </CAlert>
          )}
          <CForm onSubmit={handleSubmit}>
            <div className="mb-3">
              <CFormLabel>Username</CFormLabel>
              <CFormInput
                autoFocus
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </div>
            <div className="mb-3">
              <CFormLabel>Password</CFormLabel>
              <CFormInput
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
            <CButton
              type="submit"
              color="primary"
              className="w-100"
              disabled={loading}
            >
              {loading ? 'Signing in…' : 'Login'}
            </CButton>
          </CForm>
        </CCardBody>
      </CCard>
    </div>
  )
}
```

- [ ] **Step 2: Verify TypeScript compiles this file**

```bash
cd web && npx tsc --noEmit --skipLibCheck 2>&1 | grep LoginPage
```

Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add web/src/pages/LoginPage.tsx
git commit -m "feat: rewrite LoginPage with CoreUI CCard + CForm"
```

---

## Task 8: StatCard Component

**Files:**
- Create: `web/src/components/StatCard.tsx`

- [ ] **Step 1: Write `web/src/components/StatCard.tsx`**

```tsx
import { CCard, CCardBody } from '@coreui/react'

interface Props {
  title: string
  value: string | number
  subtitle?: string
  borderColor: string
}

export function StatCard({ title, value, subtitle, borderColor }: Props) {
  return (
    <CCard style={{ borderLeft: `4px solid ${borderColor}` }}>
      <CCardBody>
        <div
          style={{
            fontSize: '0.65rem',
            color: '#6c757d',
            textTransform: 'uppercase',
            letterSpacing: '0.5px',
            marginBottom: '0.4rem',
          }}
        >
          {title}
        </div>
        <div style={{ fontSize: '1.6rem', fontWeight: 700, color: '#1b2a3b' }}>{value}</div>
        {subtitle && (
          <div style={{ fontSize: '0.7rem', color: '#6c757d', marginTop: '0.2rem' }}>
            {subtitle}
          </div>
        )}
      </CCardBody>
    </CCard>
  )
}
```

- [ ] **Step 2: Commit**

```bash
git add web/src/components/StatCard.tsx
git commit -m "feat: add StatCard component for Dashboard"
```

---

## Task 9: DashboardPage

**Files:**
- Create: `web/src/pages/DashboardPage.tsx`

- [ ] **Step 1: Write `web/src/pages/DashboardPage.tsx`**

```tsx
import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  CRow,
  CCol,
  CCard,
  CCardHeader,
  CCardBody,
  CTable,
  CTableHead,
  CTableBody,
  CTableRow,
  CTableHeaderCell,
  CTableDataCell,
  CBadge,
  CButton,
  CSpinner,
  CModal,
  CModalHeader,
  CModalTitle,
  CModalBody,
  CModalFooter,
} from '@coreui/react'
import { policyApi, modeApi, namespaceApi } from '../api/client'
import { useToast } from '../layout/AppToaster'
import { StatCard } from '../components/StatCard'
import type { PolicyRecord, Mode } from '../api/types'

export function DashboardPage() {
  const navigate = useNavigate()
  const toast = useToast()
  const [policies, setPolicies] = useState<PolicyRecord[]>([])
  const [mode, setMode] = useState<Mode>('Monitoring')
  const [namespaceCount, setNamespaceCount] = useState(0)
  const [loading, setLoading] = useState(true)
  const [switchModal, setSwitchModal] = useState(false)
  const [switching, setSwitching] = useState(false)

  useEffect(() => {
    Promise.all([policyApi.list(), modeApi.get(), namespaceApi.list()])
      .then(([p, m, ns]) => {
        setPolicies(p)
        setMode(m)
        setNamespaceCount(ns.length)
      })
      .catch(() => toast.error('Failed to load dashboard'))
      .finally(() => setLoading(false))
  }, [])

  const handleModeSwitch = async () => {
    const next = mode === 'Protect' ? 'Monitoring' : 'Protect'
    setSwitching(true)
    try {
      await modeApi.set(next)
      setMode(next)
      toast.success(`Mode switched to ${next}`)
    } catch {
      toast.error('Failed to switch mode')
    } finally {
      setSwitching(false)
      setSwitchModal(false)
    }
  }

  const clusterCount = policies.filter((p) => p.scope === 'cluster').length
  const recent = policies.slice(0, 5)
  const modeColor = mode === 'Protect' ? '#dc3545' : mode === 'Mixed' ? '#fd7e14' : '#28a745'
  const nextMode = mode === 'Protect' ? 'Monitoring' : 'Protect'

  if (loading) {
    return (
      <div className="d-flex justify-content-center py-5">
        <CSpinner color="primary" />
      </div>
    )
  }

  return (
    <>
      <h4 className="mb-4" style={{ color: '#1b2a3b', fontWeight: 600 }}>
        Dashboard
      </h4>

      <CRow className="mb-4 g-3">
        <CCol sm={6} xl={3}>
          <StatCard
            title="Total Policies"
            value={policies.length}
            subtitle="TracingPolicy"
            borderColor="#2d7dd2"
          />
        </CCol>
        <CCol sm={6} xl={3}>
          <StatCard
            title="Current Mode"
            value={mode.toUpperCase()}
            subtitle={mode === 'Protect' ? '攔截違規行為' : '觀測模式，不攔截'}
            borderColor={modeColor}
          />
        </CCol>
        <CCol sm={6} xl={3}>
          <StatCard
            title="Namespaces"
            value={namespaceCount}
            subtitle="已列管的命名空間"
            borderColor="#28a745"
          />
        </CCol>
        <CCol sm={6} xl={3}>
          <StatCard
            title="Cluster-scoped"
            value={clusterCount}
            subtitle="跨命名空間 Policy"
            borderColor="#dc3545"
          />
        </CCol>
      </CRow>

      <CRow className="g-3">
        <CCol xl={8}>
          <CCard>
            <CCardHeader className="d-flex justify-content-between align-items-center">
              <strong>Recent Policies</strong>
              <CButton
                color="link"
                size="sm"
                onClick={() => navigate('/policies/tracing')}
              >
                View All →
              </CButton>
            </CCardHeader>
            <CCardBody className="p-0">
              <CTable hover responsive className="mb-0">
                <CTableHead>
                  <CTableRow style={{ background: '#f8f9fa' }}>
                    <CTableHeaderCell>Name</CTableHeaderCell>
                    <CTableHeaderCell>Scope</CTableHeaderCell>
                    <CTableHeaderCell>Namespace</CTableHeaderCell>
                    <CTableHeaderCell>Created</CTableHeaderCell>
                  </CTableRow>
                </CTableHead>
                <CTableBody>
                  {recent.length === 0 ? (
                    <CTableRow>
                      <CTableDataCell colSpan={4} className="text-center text-muted py-4">
                        No policies yet
                      </CTableDataCell>
                    </CTableRow>
                  ) : (
                    recent.map((p) => (
                      <CTableRow
                        key={`${p.scope}-${p.namespace ?? ''}-${p.name}`}
                        style={{ cursor: 'pointer' }}
                        onClick={() =>
                          navigate(
                            `/policies/tracing/${p.name}/edit?namespace=${p.namespace ?? ''}`
                          )
                        }
                      >
                        <CTableDataCell style={{ color: '#2d7dd2', fontWeight: 500 }}>
                          {p.name}
                        </CTableDataCell>
                        <CTableDataCell>
                          <CBadge color={p.scope === 'cluster' ? 'danger' : 'primary'}>
                            {p.scope}
                          </CBadge>
                        </CTableDataCell>
                        <CTableDataCell className="text-muted">
                          {p.namespace ?? '—'}
                        </CTableDataCell>
                        <CTableDataCell className="text-muted">{p.createdAt}</CTableDataCell>
                      </CTableRow>
                    ))
                  )}
                </CTableBody>
              </CTable>
            </CCardBody>
          </CCard>
        </CCol>

        <CCol xl={4}>
          <CCard>
            <CCardHeader>
              <strong>Enforcement Mode</strong>
            </CCardHeader>
            <CCardBody className="text-center">
              <div
                style={{
                  border: `2px solid ${modeColor}`,
                  borderRadius: 6,
                  padding: '0.75rem',
                  marginBottom: '0.75rem',
                }}
              >
                <div className="text-muted mb-1" style={{ fontSize: '0.7rem' }}>
                  目前模式
                </div>
                <div style={{ fontWeight: 700, color: modeColor, fontSize: '1.1rem' }}>
                  {mode.toUpperCase()}
                </div>
              </div>
              <CButton
                color={nextMode === 'Protect' ? 'danger' : 'success'}
                variant="outline"
                size="sm"
                className="w-100"
                onClick={() => setSwitchModal(true)}
              >
                切換至 {nextMode.toUpperCase()}
              </CButton>
              {nextMode === 'Protect' && (
                <p className="text-danger mt-2 mb-0" style={{ fontSize: '0.7rem' }}>
                  ⚠ 啟用後將攔截違規行為
                </p>
              )}
            </CCardBody>
          </CCard>
        </CCol>
      </CRow>

      <CModal visible={switchModal} onClose={() => setSwitchModal(false)}>
        <CModalHeader>
          <CModalTitle>切換模式</CModalTitle>
        </CModalHeader>
        <CModalBody>
          確定要將模式切換為 <strong>{nextMode.toUpperCase()}</strong> 嗎？
          {nextMode === 'Protect' && (
            <p className="text-danger mt-2 mb-0">警告：Protect 模式將攔截違規行為。</p>
          )}
        </CModalBody>
        <CModalFooter>
          <CButton color="secondary" variant="outline" onClick={() => setSwitchModal(false)}>
            取消
          </CButton>
          <CButton
            color={nextMode === 'Protect' ? 'danger' : 'success'}
            onClick={handleModeSwitch}
            disabled={switching}
          >
            {switching ? '切換中…' : `切換至 ${nextMode}`}
          </CButton>
        </CModalFooter>
      </CModal>
    </>
  )
}
```

- [ ] **Step 2: Verify TypeScript**

```bash
cd web && npx tsc --noEmit --skipLibCheck 2>&1 | grep DashboardPage
```

Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add web/src/pages/DashboardPage.tsx
git commit -m "feat: add DashboardPage with stat cards and mode widget"
```

---

## Task 10: PolicyListPage

**Files:**
- Rewrite: `web/src/pages/PolicyListPage.tsx`

- [ ] **Step 1: Rewrite `web/src/pages/PolicyListPage.tsx`**

```tsx
import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  CTable,
  CTableHead,
  CTableBody,
  CTableRow,
  CTableHeaderCell,
  CTableDataCell,
  CBadge,
  CButton,
  CFormInput,
  CFormSelect,
  CModal,
  CModalHeader,
  CModalTitle,
  CModalBody,
  CModalFooter,
  CSpinner,
  CCard,
  CCardBody,
} from '@coreui/react'
import { policyApi } from '../api/client'
import { useToast } from '../layout/AppToaster'
import type { PolicyRecord } from '../api/types'

export function PolicyListPage() {
  const navigate = useNavigate()
  const toast = useToast()
  const [policies, setPolicies] = useState<PolicyRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [scopeFilter, setScopeFilter] = useState('all')
  const [deleteTarget, setDeleteTarget] = useState<PolicyRecord | null>(null)
  const [deleting, setDeleting] = useState(false)

  const fetchPolicies = async () => {
    setLoading(true)
    try {
      setPolicies(await policyApi.list())
    } catch {
      toast.error('Failed to load policies')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchPolicies() }, [])

  const handleDelete = async () => {
    if (!deleteTarget) return
    setDeleting(true)
    try {
      await policyApi.delete(deleteTarget.name, deleteTarget.namespace)
      toast.success('Policy deleted')
      setDeleteTarget(null)
      fetchPolicies()
    } catch {
      toast.error('Failed to delete policy')
    } finally {
      setDeleting(false)
    }
  }

  const filtered = policies.filter((p) => {
    const matchName = p.name.toLowerCase().includes(search.toLowerCase())
    const matchScope = scopeFilter === 'all' || p.scope === scopeFilter
    return matchName && matchScope
  })

  return (
    <>
      <div className="d-flex justify-content-between align-items-center mb-3">
        <div>
          <h4 className="mb-0" style={{ color: '#1b2a3b', fontWeight: 600 }}>
            TracingPolicy
          </h4>
          <div className="text-muted" style={{ fontSize: '0.75rem' }}>
            Cilium 追蹤策略管理
          </div>
        </div>
        <CButton color="primary" onClick={() => navigate('/policies/tracing/new')}>
          + New Policy
        </CButton>
      </div>

      <CCard>
        <CCardBody className="p-0">
          <div
            className="d-flex align-items-center gap-2 px-3 py-2"
            style={{ borderBottom: '1px solid #dee2e6' }}
          >
            <CFormInput
              placeholder="搜尋 Policy 名稱…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{ width: 220 }}
              size="sm"
            />
            <CFormSelect
              value={scopeFilter}
              onChange={(e) => setScopeFilter(e.target.value)}
              style={{ width: 140 }}
              size="sm"
            >
              <option value="all">所有 Scope</option>
              <option value="namespaced">namespace</option>
              <option value="cluster">cluster</option>
            </CFormSelect>
            <span className="ms-auto text-muted" style={{ fontSize: '0.75rem' }}>
              共 {filtered.length} 筆
            </span>
          </div>

          {loading ? (
            <div className="d-flex justify-content-center py-5">
              <CSpinner color="primary" />
            </div>
          ) : (
            <CTable hover responsive className="mb-0">
              <CTableHead>
                <CTableRow style={{ background: '#f8f9fa' }}>
                  <CTableHeaderCell>Name</CTableHeaderCell>
                  <CTableHeaderCell>Scope</CTableHeaderCell>
                  <CTableHeaderCell>Namespace</CTableHeaderCell>
                  <CTableHeaderCell>Created</CTableHeaderCell>
                  <CTableHeaderCell className="text-center">Actions</CTableHeaderCell>
                </CTableRow>
              </CTableHead>
              <CTableBody>
                {filtered.length === 0 ? (
                  <CTableRow>
                    <CTableDataCell colSpan={5} className="text-center text-muted py-4">
                      No policies found
                    </CTableDataCell>
                  </CTableRow>
                ) : (
                  filtered.map((p) => (
                    <CTableRow key={`${p.scope}-${p.namespace ?? ''}-${p.name}`}>
                      <CTableDataCell
                        style={{ color: '#2d7dd2', fontWeight: 500, cursor: 'pointer' }}
                        onClick={() =>
                          navigate(
                            `/policies/tracing/${p.name}/edit?namespace=${p.namespace ?? ''}`
                          )
                        }
                      >
                        {p.name}
                      </CTableDataCell>
                      <CTableDataCell>
                        <CBadge color={p.scope === 'cluster' ? 'danger' : 'primary'}>
                          {p.scope}
                        </CBadge>
                      </CTableDataCell>
                      <CTableDataCell className="text-muted">
                        {p.namespace ?? '—'}
                      </CTableDataCell>
                      <CTableDataCell className="text-muted">{p.createdAt}</CTableDataCell>
                      <CTableDataCell className="text-center">
                        <CButton
                          color="primary"
                          variant="outline"
                          size="sm"
                          className="me-1"
                          onClick={() =>
                            navigate(
                              `/policies/tracing/${p.name}/edit?namespace=${p.namespace ?? ''}`
                            )
                          }
                        >
                          Edit
                        </CButton>
                        <CButton
                          color="danger"
                          variant="outline"
                          size="sm"
                          onClick={() => setDeleteTarget(p)}
                        >
                          Delete
                        </CButton>
                      </CTableDataCell>
                    </CTableRow>
                  ))
                )}
              </CTableBody>
            </CTable>
          )}
        </CCardBody>
      </CCard>

      <CModal visible={!!deleteTarget} onClose={() => setDeleteTarget(null)}>
        <CModalHeader>
          <CModalTitle>刪除 Policy</CModalTitle>
        </CModalHeader>
        <CModalBody>
          確定要刪除 <strong>{deleteTarget?.name}</strong> 嗎？此操作無法復原。
        </CModalBody>
        <CModalFooter>
          <CButton color="secondary" variant="outline" onClick={() => setDeleteTarget(null)}>
            取消
          </CButton>
          <CButton color="danger" onClick={handleDelete} disabled={deleting}>
            {deleting ? '刪除中…' : '確認刪除'}
          </CButton>
        </CModalFooter>
      </CModal>
    </>
  )
}
```

- [ ] **Step 2: Verify TypeScript**

```bash
cd web && npx tsc --noEmit --skipLibCheck 2>&1 | grep PolicyListPage
```

Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add web/src/pages/PolicyListPage.tsx
git commit -m "feat: rewrite PolicyListPage with CoreUI CTable and search"
```

---

## Task 11: PolicyForm Sub-components (ProcessSection, FileSection, NetworkSection)

**Files:**
- Rewrite: `web/src/components/PolicyForm/ProcessSection.tsx`
- Rewrite: `web/src/components/PolicyForm/FileSection.tsx`
- Rewrite: `web/src/components/PolicyForm/NetworkSection.tsx`

- [ ] **Step 1: Rewrite `ProcessSection.tsx`**

```tsx
import { CFormInput, CButton } from '@coreui/react'

interface Props {
  binaries: string[]
  onChange: (binaries: string[]) => void
}

export function ProcessSection({ binaries, onChange }: Props) {
  const update = (i: number, val: string) => {
    const next = [...binaries]
    next[i] = val
    onChange(next)
  }
  const add = () => onChange([...binaries, ''])
  const remove = (i: number) => onChange(binaries.filter((_, j) => j !== i))

  return (
    <div className="mb-3">
      {binaries.map((b, i) => (
        <div key={i} className="d-flex align-items-center gap-2 mb-2">
          <CFormInput
            placeholder="/usr/bin/nginx"
            value={b}
            onChange={(e) => update(i, e.target.value)}
            size="sm"
          />
          <CButton
            color="danger"
            variant="ghost"
            size="sm"
            onClick={() => remove(i)}
            style={{ flexShrink: 0 }}
          >
            ✕
          </CButton>
        </div>
      ))}
      <CButton color="primary" variant="outline" size="sm" onClick={add}>
        + Add
      </CButton>
    </div>
  )
}
```

- [ ] **Step 2: Rewrite `FileSection.tsx`**

```tsx
import { CFormInput, CFormSelect, CButton } from '@coreui/react'
import type { FileRule } from '../../api/types'

type FileEntry = { path: string; operation: FileRule['operation'] }

interface Props {
  rules: FileEntry[]
  onChange: (rules: FileEntry[]) => void
}

export function FileSection({ rules, onChange }: Props) {
  const update = (i: number, patch: Partial<FileEntry>) => {
    const next = [...rules]
    next[i] = { ...next[i], ...patch }
    onChange(next)
  }
  const add = () => onChange([...rules, { path: '', operation: 'read' }])
  const remove = (i: number) => onChange(rules.filter((_, j) => j !== i))

  return (
    <div className="mb-3">
      {rules.map((r, i) => (
        <div key={i} className="d-flex align-items-center gap-2 mb-2">
          <CFormInput
            placeholder="/etc/nginx/nginx.conf"
            value={r.path}
            onChange={(e) => update(i, { path: e.target.value })}
            size="sm"
            style={{ flex: 2 }}
          />
          <CFormSelect
            value={r.operation}
            onChange={(e) =>
              update(i, { operation: e.target.value as FileRule['operation'] })
            }
            size="sm"
            style={{ flex: 1 }}
          >
            <option value="read">read</option>
            <option value="write">write</option>
            <option value="open">open</option>
          </CFormSelect>
          <CButton color="danger" variant="ghost" size="sm" onClick={() => remove(i)}>
            ✕
          </CButton>
        </div>
      ))}
      <CButton color="primary" variant="outline" size="sm" onClick={add}>
        + Add
      </CButton>
    </div>
  )
}
```

- [ ] **Step 3: Rewrite `NetworkSection.tsx`**

```tsx
import { CFormInput, CFormSelect, CButton } from '@coreui/react'
import type { NetworkRule } from '../../api/types'

type NetEntry = { protocol: NetworkRule['protocol']; cidr: string; port: string }

interface Props {
  rules: NetEntry[]
  onChange: (rules: NetEntry[]) => void
}

export function NetworkSection({ rules, onChange }: Props) {
  const update = (i: number, patch: Partial<NetEntry>) => {
    const next = [...rules]
    next[i] = { ...next[i], ...patch }
    onChange(next)
  }
  const add = () => onChange([...rules, { protocol: 'TCP', cidr: '', port: '' }])
  const remove = (i: number) => onChange(rules.filter((_, j) => j !== i))

  return (
    <div className="mb-3">
      {rules.map((r, i) => (
        <div key={i} className="d-flex align-items-center gap-2 mb-2">
          <CFormSelect
            value={r.protocol}
            onChange={(e) =>
              update(i, { protocol: e.target.value as NetworkRule['protocol'] })
            }
            size="sm"
            style={{ width: 80, flexShrink: 0 }}
          >
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
          </CFormSelect>
          <CFormInput
            placeholder="10.0.0.0/8"
            value={r.cidr}
            onChange={(e) => update(i, { cidr: e.target.value })}
            size="sm"
            style={{ flex: 2 }}
          />
          <CFormInput
            placeholder="Port"
            value={r.port}
            onChange={(e) => update(i, { port: e.target.value })}
            size="sm"
            style={{ width: 80, flexShrink: 0 }}
            type="number"
            min={1}
            max={65535}
          />
          <CButton color="danger" variant="ghost" size="sm" onClick={() => remove(i)}>
            ✕
          </CButton>
        </div>
      ))}
      <CButton color="primary" variant="outline" size="sm" onClick={add}>
        + Add
      </CButton>
    </div>
  )
}
```

- [ ] **Step 4: Verify TypeScript**

```bash
cd web && npx tsc --noEmit --skipLibCheck 2>&1 | grep -E "ProcessSection|FileSection|NetworkSection"
```

Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add web/src/components/PolicyForm/ProcessSection.tsx \
        web/src/components/PolicyForm/FileSection.tsx \
        web/src/components/PolicyForm/NetworkSection.tsx
git commit -m "feat: rewrite PolicyForm sub-components with Bootstrap inputs"
```

---

## Task 12: PolicyForm (Main Form Component)

**Files:**
- Rewrite: `web/src/components/PolicyForm/PolicyForm.tsx`
- Delete: `web/src/components/PolicyForm/YamlPreview.tsx`

The new `PolicyForm` is a **controlled component**: it receives `value` and calls `onChange` on every change. The parent (`PolicyEditPage`) owns the state and the Save button. YAML preview is inlined (no separate `YamlPreview` component).

- [ ] **Step 1: Rewrite `web/src/components/PolicyForm/PolicyForm.tsx`**

```tsx
import { useMemo } from 'react'
import {
  CCard,
  CCardHeader,
  CCardBody,
  CFormInput,
  CFormLabel,
  CFormSelect,
  CRow,
  CCol,
} from '@coreui/react'
import { ProcessSection } from './ProcessSection'
import { FileSection } from './FileSection'
import { NetworkSection } from './NetworkSection'
import { formToYaml } from '../../utils/formToYaml'
import type { PolicyFormInput, FileRule, NetworkRule } from '../../api/types'

type FileEntry = { path: string; operation: FileRule['operation'] }
type NetEntry = { protocol: NetworkRule['protocol']; cidr: string; port: string }

interface Props {
  namespaces: string[]
  action: string
  value: PolicyFormInput
  onChange: (v: PolicyFormInput) => void
}

export function PolicyForm({ namespaces, action, value, onChange }: Props) {
  const yamlPreview = useMemo(() => {
    if (!value.name) return ''
    try {
      return formToYaml(value, action)
    } catch {
      return ''
    }
  }, [value, action])

  const processBinaries = value.process?.map((p) => p.binaries[0] ?? '') ?? []
  const fileEntries: FileEntry[] =
    value.file?.map((f) => ({ path: f.paths[0] ?? '', operation: f.operation })) ?? []
  const netEntries: NetEntry[] =
    value.network?.map((n) => ({
      protocol: n.protocol,
      cidr: n.cidr,
      port: n.port?.toString() ?? '',
    })) ?? []

  const setProcessBinaries = (binaries: string[]) =>
    onChange({ ...value, process: binaries.map((b) => ({ binaries: [b] })) })

  const setFileEntries = (entries: FileEntry[]) =>
    onChange({
      ...value,
      file: entries.map((e) => ({ paths: [e.path], operation: e.operation })),
    })

  const setNetEntries = (entries: NetEntry[]) =>
    onChange({
      ...value,
      network: entries.map((e) => ({
        protocol: e.protocol,
        cidr: e.cidr,
        port: e.port ? parseInt(e.port, 10) : undefined,
      })),
    })

  return (
    <CRow className="g-3">
      <CCol lg={8}>
        {/* Basic Info */}
        <CCard className="mb-3">
          <CCardHeader>
            <strong style={{ fontSize: '0.85rem' }}>Basic Information</strong>
          </CCardHeader>
          <CCardBody>
            <CRow className="g-3">
              <CCol md={6}>
                <CFormLabel>
                  Policy Name <span className="text-danger">*</span>
                </CFormLabel>
                <CFormInput
                  placeholder="my-policy"
                  value={value.name}
                  onChange={(e) => onChange({ ...value, name: e.target.value })}
                />
              </CCol>
              <CCol md={6}>
                <CFormLabel>Namespace</CFormLabel>
                <CFormSelect
                  value={value.namespace ?? ''}
                  onChange={(e) =>
                    onChange({ ...value, namespace: e.target.value || undefined })
                  }
                >
                  <option value="">cluster-wide</option>
                  {namespaces.map((n) => (
                    <option key={n} value={n}>
                      {n}
                    </option>
                  ))}
                </CFormSelect>
              </CCol>
            </CRow>
          </CCardBody>
        </CCard>

        {/* Process Rules */}
        <CCard className="mb-3">
          <CCardHeader className="d-flex justify-content-between align-items-center">
            <strong style={{ fontSize: '0.85rem' }}>Process Rules</strong>
          </CCardHeader>
          <CCardBody>
            <ProcessSection binaries={processBinaries} onChange={setProcessBinaries} />
          </CCardBody>
        </CCard>

        {/* File Rules */}
        <CCard className="mb-3">
          <CCardHeader>
            <strong style={{ fontSize: '0.85rem' }}>File Rules</strong>
          </CCardHeader>
          <CCardBody>
            <FileSection rules={fileEntries} onChange={setFileEntries} />
          </CCardBody>
        </CCard>

        {/* Network Rules */}
        <CCard>
          <CCardHeader>
            <strong style={{ fontSize: '0.85rem' }}>Network Rules</strong>
          </CCardHeader>
          <CCardBody>
            <NetworkSection rules={netEntries} onChange={setNetEntries} />
          </CCardBody>
        </CCard>
      </CCol>

      {/* YAML Preview */}
      <CCol lg={4}>
        <div style={{ position: 'sticky', top: '5rem' }}>
          <div
            style={{
              background: '#1e1e1e',
              borderRadius: 6,
              overflow: 'hidden',
            }}
          >
            <div
              style={{
                padding: '0.5rem 0.85rem',
                background: '#252526',
                borderBottom: '1px solid #3c3c3c',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <span style={{ fontSize: '0.75rem', color: '#9cdcfe', fontFamily: 'monospace' }}>
                YAML Preview
              </span>
              <span
                style={{
                  fontSize: '0.65rem',
                  color: yamlPreview ? '#4ec94e' : '#6c757d',
                  background: yamlPreview ? '#1a3a1a' : '#2a2a2a',
                  padding: '1px 6px',
                  borderRadius: 3,
                }}
              >
                {yamlPreview ? '✓ valid' : '—'}
              </span>
            </div>
            <pre
              style={{
                margin: 0,
                padding: '0.75rem',
                fontFamily: 'monospace',
                fontSize: '0.7rem',
                lineHeight: 1.6,
                color: '#d4d4d4',
                minHeight: 200,
                maxHeight: 500,
                overflow: 'auto',
                whiteSpace: 'pre-wrap',
              }}
            >
              {yamlPreview || <span style={{ color: '#555' }}>Enter a policy name to preview…</span>}
            </pre>
          </div>
        </div>
      </CCol>
    </CRow>
  )
}
```

- [ ] **Step 2: Delete `YamlPreview.tsx`**

```bash
git rm web/src/components/PolicyForm/YamlPreview.tsx
```

- [ ] **Step 3: Verify TypeScript**

```bash
cd web && npx tsc --noEmit --skipLibCheck 2>&1 | grep PolicyForm
```

Expected: no output.

- [ ] **Step 4: Commit**

```bash
git add web/src/components/PolicyForm/PolicyForm.tsx
git commit -m "feat: rewrite PolicyForm with useState and inline YAML preview"
```

---

## Task 13: YamlEditor — Remove Own Apply Button

**Files:**
- Rewrite: `web/src/components/YamlEditor.tsx`

The Apply action moves to `PolicyEditPage`'s header Save button. `YamlEditor` now exposes `onValueChange` so the parent can read current YAML. YAML validation still happens before save (triggered by parent calling `validate()`).

- [ ] **Step 1: Rewrite `web/src/components/YamlEditor.tsx`**

```tsx
import { useState } from 'react'
import MonacoEditor from '@monaco-editor/react'
import { CAlert } from '@coreui/react'
import yaml from 'js-yaml'

interface Props {
  initialValue?: string
  onValueChange: (value: string, valid: boolean) => void
}

export function YamlEditor({ initialValue = '', onValueChange }: Props) {
  const [error, setError] = useState('')

  const handleChange = (v: string | undefined) => {
    const text = v ?? ''
    let valid = true
    let errMsg = ''
    try {
      yaml.load(text)
    } catch (e: unknown) {
      valid = false
      errMsg = e instanceof Error ? e.message : 'Invalid YAML'
    }
    setError(errMsg)
    onValueChange(text, valid)
  }

  return (
    <div>
      {error && (
        <CAlert color="danger" className="mb-2" style={{ fontSize: '0.8rem' }}>
          {error}
        </CAlert>
      )}
      <MonacoEditor
        height="500px"
        language="yaml"
        theme="vs-dark"
        defaultValue={initialValue}
        onChange={handleChange}
        options={{ minimap: { enabled: false }, fontSize: 13 }}
      />
    </div>
  )
}
```

- [ ] **Step 2: Verify TypeScript**

```bash
cd web && npx tsc --noEmit --skipLibCheck 2>&1 | grep YamlEditor
```

Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add web/src/components/YamlEditor.tsx
git commit -m "feat: update YamlEditor to expose onValueChange callback"
```

---

## Task 14: PolicyEditPage

**Files:**
- Rewrite: `web/src/pages/PolicyEditPage.tsx`

- [ ] **Step 1: Rewrite `web/src/pages/PolicyEditPage.tsx`**

```tsx
import { useEffect, useState } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import {
  CTabs,
  CTabList,
  CTab,
  CTabContent,
  CTabPanel,
  CButton,
  CSpinner,
} from '@coreui/react'
import { policyApi, namespaceApi, modeApi } from '../api/client'
import { useToast } from '../layout/AppToaster'
import { PolicyForm } from '../components/PolicyForm/PolicyForm'
import { YamlEditor } from '../components/YamlEditor'
import type { PolicyFormInput, Mode } from '../api/types'

const EMPTY_FORM: PolicyFormInput = {
  name: '',
  namespace: undefined,
  process: [],
  file: [],
  network: [],
}

export function PolicyEditPage() {
  const { name } = useParams<{ name: string }>()
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const toast = useToast()
  const namespace = searchParams.get('namespace') || undefined
  const isNew = !name

  const [namespaces, setNamespaces] = useState<string[]>([])
  const [mode, setMode] = useState<Mode>('Monitoring')
  const [initialYaml, setInitialYaml] = useState('')
  const [formValues, setFormValues] = useState<PolicyFormInput>(EMPTY_FORM)
  const [yamlValue, setYamlValue] = useState('')
  const [yamlValid, setYamlValid] = useState(true)
  const [activeTab, setActiveTab] = useState<string>('form')
  const [loading, setLoading] = useState(false)
  const [pageLoading, setPageLoading] = useState(!isNew)

  useEffect(() => {
    const work = [namespaceApi.list().then(setNamespaces), modeApi.get().then(setMode)]
    if (!isNew && name) {
      work.push(
        policyApi.get(name, namespace).then((r) => {
          setInitialYaml(r.rawYaml)
          setYamlValue(r.rawYaml)
        })
      )
    }
    Promise.all(work).finally(() => setPageLoading(false))
  }, [name, namespace, isNew])

  const action = mode === 'Protect' ? 'Sigkill' : 'Post'

  const handleSave = async () => {
    if (activeTab === 'form') {
      if (!formValues.name.trim()) {
        toast.error('Policy name is required')
        return
      }
      setLoading(true)
      try {
        const payload = { source: 'form' as const, form: formValues, action }
        if (isNew) await policyApi.create(payload)
        else await policyApi.update(name!, payload)
        toast.success('Policy applied')
        navigate('/policies/tracing')
      } catch {
        toast.error('Failed to apply policy')
      } finally {
        setLoading(false)
      }
    } else {
      if (!yamlValid) {
        toast.error('Fix YAML errors before saving')
        return
      }
      setLoading(true)
      try {
        const payload = { source: 'yaml' as const, rawYaml: yamlValue }
        if (isNew) await policyApi.create(payload)
        else await policyApi.update(name!, payload)
        toast.success('Policy applied')
        navigate('/policies/tracing')
      } catch {
        toast.error('Failed to apply YAML')
      } finally {
        setLoading(false)
      }
    }
  }

  if (pageLoading) {
    return (
      <div className="d-flex justify-content-center py-5">
        <CSpinner color="primary" />
      </div>
    )
  }

  return (
    <>
      <div className="d-flex justify-content-between align-items-start mb-3">
        <div>
          <h4 className="mb-0" style={{ color: '#1b2a3b', fontWeight: 600 }}>
            {isNew ? 'New Policy' : 'Edit Policy'}
          </h4>
          {!isNew && (
            <div className="text-muted" style={{ fontSize: '0.75rem' }}>
              {name}
            </div>
          )}
        </div>
        <div className="d-flex gap-2">
          <CButton
            color="secondary"
            variant="outline"
            onClick={() => navigate('/policies/tracing')}
          >
            Cancel
          </CButton>
          <CButton color="primary" onClick={handleSave} disabled={loading}>
            {loading ? 'Saving…' : 'Save Changes'}
          </CButton>
        </div>
      </div>

      <CTabs activeItemKey={activeTab} onActiveItemKeyChange={(k) => setActiveTab(k as string)}>
        <CTabList variant="underline-border" className="mb-3">
          <CTab itemKey="form">Form</CTab>
          <CTab itemKey="yaml">YAML</CTab>
        </CTabList>
        <CTabContent>
          <CTabPanel itemKey="form">
            <PolicyForm
              namespaces={namespaces}
              action={action}
              value={formValues}
              onChange={setFormValues}
            />
          </CTabPanel>
          <CTabPanel itemKey="yaml">
            <YamlEditor
              initialValue={initialYaml}
              onValueChange={(v, valid) => {
                setYamlValue(v)
                setYamlValid(valid)
              }}
            />
          </CTabPanel>
        </CTabContent>
      </CTabs>
    </>
  )
}
```

- [ ] **Step 2: Verify TypeScript**

```bash
cd web && npx tsc --noEmit --skipLibCheck 2>&1 | grep PolicyEditPage
```

Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add web/src/pages/PolicyEditPage.tsx
git commit -m "feat: rewrite PolicyEditPage with CTabs and header Save button"
```

---

## Task 15: ModePage

**Files:**
- Create: `web/src/pages/ModePage.tsx`

- [ ] **Step 1: Write `web/src/pages/ModePage.tsx`**

```tsx
import { useEffect, useState } from 'react'
import {
  CCard,
  CCardHeader,
  CCardBody,
  CButton,
  CSpinner,
  CModal,
  CModalHeader,
  CModalTitle,
  CModalBody,
  CModalFooter,
  CAlert,
} from '@coreui/react'
import { modeApi } from '../api/client'
import { useToast } from '../layout/AppToaster'
import type { Mode } from '../api/types'

const MODE_DESCRIPTIONS: Record<Mode, string> = {
  Monitoring: '觀測模式：記錄所有行為但不進行攔截，適合初期策略驗證與行為分析。',
  Protect: '保護模式：主動攔截違反策略的行為（Sigkill），適合生產環境強制執行。',
  Mixed: '混合模式：部分策略為 Monitoring，部分為 Protect，切換模式將統一套用。',
}

export function ModePage() {
  const toast = useToast()
  const [mode, setMode] = useState<Mode>('Monitoring')
  const [loading, setLoading] = useState(true)
  const [switchModal, setSwitchModal] = useState(false)
  const [switching, setSwitching] = useState(false)

  useEffect(() => {
    modeApi
      .get()
      .then(setMode)
      .catch(() => toast.error('Failed to load mode'))
      .finally(() => setLoading(false))
  }, [])

  const nextMode: 'Monitoring' | 'Protect' =
    mode === 'Protect' ? 'Monitoring' : 'Protect'

  const handleSwitch = async () => {
    setSwitching(true)
    try {
      await modeApi.set(nextMode)
      setMode(nextMode)
      toast.success(`Mode switched to ${nextMode}`)
    } catch {
      toast.error('Failed to switch mode')
    } finally {
      setSwitching(false)
      setSwitchModal(false)
    }
  }

  const modeColor = mode === 'Protect' ? '#dc3545' : mode === 'Mixed' ? '#fd7e14' : '#28a745'

  if (loading) {
    return (
      <div className="d-flex justify-content-center py-5">
        <CSpinner color="primary" />
      </div>
    )
  }

  return (
    <>
      <h4 className="mb-4" style={{ color: '#1b2a3b', fontWeight: 600 }}>
        Mode Control
      </h4>

      <CCard style={{ maxWidth: 480 }}>
        <CCardHeader>
          <strong>Enforcement Mode</strong>
        </CCardHeader>
        <CCardBody>
          <div
            style={{
              border: `2px solid ${modeColor}`,
              borderRadius: 8,
              padding: '1.25rem',
              textAlign: 'center',
              marginBottom: '1rem',
            }}
          >
            <div className="text-muted mb-1" style={{ fontSize: '0.75rem' }}>
              目前模式
            </div>
            <div style={{ fontSize: '1.8rem', fontWeight: 700, color: modeColor }}>
              {mode.toUpperCase()}
            </div>
          </div>

          <p className="text-muted mb-3" style={{ fontSize: '0.85rem' }}>
            {MODE_DESCRIPTIONS[mode]}
          </p>

          {mode === 'Mixed' && (
            <CAlert color="warning" className="mb-3" style={{ fontSize: '0.8rem' }}>
              混合模式：切換後所有 Policy 將統一套用新模式。
            </CAlert>
          )}

          <CButton
            color={nextMode === 'Protect' ? 'danger' : 'success'}
            variant="outline"
            className="w-100"
            onClick={() => setSwitchModal(true)}
          >
            切換至 {nextMode.toUpperCase()}
          </CButton>
        </CCardBody>
      </CCard>

      <CModal visible={switchModal} onClose={() => setSwitchModal(false)}>
        <CModalHeader>
          <CModalTitle>切換執行模式</CModalTitle>
        </CModalHeader>
        <CModalBody>
          確定要將模式從 <strong>{mode.toUpperCase()}</strong> 切換為{' '}
          <strong>{nextMode.toUpperCase()}</strong> 嗎？
          {nextMode === 'Protect' && (
            <p className="text-danger mt-2 mb-0" style={{ fontSize: '0.85rem' }}>
              ⚠ 警告：Protect 模式將主動攔截（Sigkill）違規行為，請確認策略正確後再切換。
            </p>
          )}
        </CModalBody>
        <CModalFooter>
          <CButton color="secondary" variant="outline" onClick={() => setSwitchModal(false)}>
            取消
          </CButton>
          <CButton
            color={nextMode === 'Protect' ? 'danger' : 'success'}
            onClick={handleSwitch}
            disabled={switching}
          >
            {switching ? '切換中…' : `切換至 ${nextMode}`}
          </CButton>
        </CModalFooter>
      </CModal>
    </>
  )
}
```

- [ ] **Step 2: Commit**

```bash
git add web/src/pages/ModePage.tsx
git commit -m "feat: add ModePage for enforcement mode control"
```

---

## Task 16: NamespacesPage

**Files:**
- Create: `web/src/pages/NamespacesPage.tsx`

- [ ] **Step 1: Write `web/src/pages/NamespacesPage.tsx`**

```tsx
import { useEffect, useState } from 'react'
import {
  CTable,
  CTableHead,
  CTableBody,
  CTableRow,
  CTableHeaderCell,
  CTableDataCell,
  CSpinner,
  CCard,
  CCardBody,
} from '@coreui/react'
import { namespaceApi, policyApi } from '../api/client'
import { useToast } from '../layout/AppToaster'
import type { PolicyRecord } from '../api/types'

export function NamespacesPage() {
  const toast = useToast()
  const [namespaces, setNamespaces] = useState<string[]>([])
  const [policies, setPolicies] = useState<PolicyRecord[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([namespaceApi.list(), policyApi.list()])
      .then(([ns, p]) => {
        setNamespaces(ns)
        setPolicies(p)
      })
      .catch(() => toast.error('Failed to load namespaces'))
      .finally(() => setLoading(false))
  }, [])

  const policyCountByNs = (ns: string) =>
    policies.filter((p) => p.namespace === ns).length

  return (
    <>
      <div className="d-flex justify-content-between align-items-center mb-3">
        <h4 className="mb-0" style={{ color: '#1b2a3b', fontWeight: 600 }}>
          Namespaces
        </h4>
      </div>

      <CCard>
        <CCardBody className="p-0">
          {loading ? (
            <div className="d-flex justify-content-center py-5">
              <CSpinner color="primary" />
            </div>
          ) : (
            <CTable hover responsive className="mb-0">
              <CTableHead>
                <CTableRow style={{ background: '#f8f9fa' }}>
                  <CTableHeaderCell>Namespace</CTableHeaderCell>
                  <CTableHeaderCell className="text-center">Policies</CTableHeaderCell>
                </CTableRow>
              </CTableHead>
              <CTableBody>
                {namespaces.length === 0 ? (
                  <CTableRow>
                    <CTableDataCell colSpan={2} className="text-center text-muted py-4">
                      No namespaces found
                    </CTableDataCell>
                  </CTableRow>
                ) : (
                  namespaces.map((ns) => (
                    <CTableRow key={ns}>
                      <CTableDataCell style={{ fontWeight: 500 }}>{ns}</CTableDataCell>
                      <CTableDataCell className="text-center">
                        {policyCountByNs(ns)}
                      </CTableDataCell>
                    </CTableRow>
                  ))
                )}
              </CTableBody>
            </CTable>
          )}
        </CCardBody>
      </CCard>
    </>
  )
}
```

- [ ] **Step 2: Commit**

```bash
git add web/src/pages/NamespacesPage.tsx
git commit -m "feat: add NamespacesPage with policy count per namespace"
```

---

## Task 17: Cleanup — Remove ModeToggle, Verify Full Build

**Files:**
- Delete: `web/src/components/ModeToggle.tsx`

- [ ] **Step 1: Delete `ModeToggle.tsx`**

`ModeToggle.tsx` is no longer imported anywhere (Mode is now in `ModePage` and `DashboardPage`). Confirm no imports remain:

```bash
grep -r "ModeToggle" web/src/
```

Expected: no output. If output appears, remove those imports first.

```bash
git rm web/src/components/ModeToggle.tsx
```

- [ ] **Step 2: Run existing unit tests**

```bash
cd web && npm run test
```

Expected: `formToYaml.test.ts` suite PASSES. These tests have no UI dependencies and must not regress.

- [ ] **Step 3: Run full TypeScript check**

```bash
cd web && npx tsc --noEmit --skipLibCheck 2>&1
```

Expected: no errors. If errors appear, fix them before continuing. Common issues:
- Missing import: add the missing import from `@coreui/react`
- Type mismatch on `CTab.onActiveItemKeyChange`: cast event param as `string`
- `CNavItem component` prop type: add `as any` if CoreUI types don't accept `NavLink` directly

- [ ] **Step 4: Run production build**

```bash
cd web && npm run build 2>&1 | tail -30
```

Expected: `✓ built in X.Xs` with no errors. Output files written to `dist/`.

- [ ] **Step 5: Commit**

```bash
git add web/src/
git commit -m "chore: remove ModeToggle, verify clean build"
```

---

## Task 18: Final Verification

- [ ] **Step 1: Run all tests**

```bash
cd web && npm run test
```

Expected: all tests PASS.

- [ ] **Step 2: Run build**

```bash
cd web && npm run build
```

Expected: clean build, no TypeScript errors.

- [ ] **Step 3: Start dev server and smoke-test**

```bash
cd web && npm run dev &
```

Open the dev server URL. Verify manually:
- [ ] Login page renders (no sidebar)
- [ ] After login, redirects to `/dashboard`
- [ ] Dashboard shows 4 stat cards and Recent Policies table
- [ ] Sidebar shows Dashboard / Policies / Cluster sections
- [ ] `/policies/tracing` shows policy table with search + filters
- [ ] "New Policy" opens form with Basic Info / Process / File / Network cards and YAML preview
- [ ] YAML tab in policy edit shows Monaco editor, Save button works
- [ ] `/cluster/mode` shows mode card with switch button
- [ ] `/cluster/namespaces` shows namespace list
- [ ] Delete policy shows confirmation modal

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "feat: complete Sentinel UI redesign to NeuVector/CoreUI style"
```

---

## Success Criteria

1. `npm run test` — all tests pass (formToYaml suite)
2. `npm run build` — clean build, no TypeScript errors
3. All 6 existing policy CRUD operations work (create via form, create via YAML, list, edit, delete, preview)
4. Mode switching works from Dashboard widget and ModePage
5. Visual: dark `#1b2a3b` sidebar, white header, `#f5f6fa` content background
6. All routes respond: `/dashboard`, `/policies/tracing`, `/policies/tracing/new`, `/policies/tracing/:name/edit`, `/cluster/mode`, `/cluster/namespaces`
