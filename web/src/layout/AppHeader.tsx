import { useEffect, useState } from 'react'
import { useLocation, Link } from 'react-router-dom'
import {
  CHeader,
  CHeaderNav,
  CContainer,
  CBreadcrumb,
  CBreadcrumbItem,
  CBadge,
} from '@coreui/react'
import { modeApi } from '../api/client'
import type { Mode } from '../api/types'

const ROUTE_LABELS: Record<string, string> = {
  dashboard: 'Dashboard',
  policies: 'Policies',
  tracing: 'TracingPolicy',
  new: 'New Policy',
  edit: 'Edit',
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
  const breadcrumbs = useBreadcrumbs()

  useEffect(() => {
    modeApi.get().then(setMode).catch(() => {})
  }, [])

  const modeColor = mode === 'Protect' ? 'danger' : mode === 'Mixed' ? 'warning' : 'success'

  return (
    <CHeader
      position="sticky"
      className="mb-4"
      style={{ background: '#fff', borderBottom: '1px solid #dee2e6' }}
    >
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
          <CBadge color={modeColor}>
            {mode.toUpperCase()}
          </CBadge>
        </CHeaderNav>
      </CContainer>
    </CHeader>
  )
}
