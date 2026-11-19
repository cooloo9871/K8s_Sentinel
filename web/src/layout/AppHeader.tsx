import { Fragment, useEffect, useState } from 'react'
import { useLocation, Link } from 'react-router-dom'
import {
  Breadcrumb,
  BreadcrumbList,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from '@/components/ui/breadcrumb'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { SidebarTrigger } from '@/components/ui/sidebar'
import { modeApi, MODE_CHANGED } from '../api/client'
import { useAuth } from './AuthContext'

const ROUTE_LABELS: Record<string, string> = {
  dashboard: 'Dashboard',
  policies: 'Policies',
  tracing: 'Tracing Policy',
  new: 'New',
  edit: 'Edit',
  templates: 'Templates',
  discovery: 'Behavior Discovery',
  admission: 'Admission Policy',
  security: 'Notifications',
  events: 'Security Events',
  alerts: 'Alerts',
  cluster: 'Cluster',
  namespaces: 'Namespaces',
  tetragon: 'Event Sources',
  retention: 'Event Retention',
  network: 'Network',
  topology: 'Network Topology',
  settings: 'Settings',
  users: 'Users',
  roles: 'Roles',
  quarantine: 'Quarantine',
  bindings: 'Bindings',
}

// Override the full breadcrumb trail for paths whose URL segments don't match
// the desired label hierarchy (e.g. /security/discovery lives under Policies).
const PATH_OVERRIDES: Record<string, { label: string; to?: string }[]> = {
  '/security/discovery': [
    { label: 'Policies' },
    { label: 'Behavior Discovery' },
  ],
  '/security/events': [
    { label: 'Notifications' },
    { label: 'Security Events' },
  ],
  '/security/alerts': [
    { label: 'Settings' },
    { label: 'Alerts' },
  ],
  '/security/rsyslog': [
    { label: 'Settings' },
    { label: 'Syslog' },
  ],
  '/security/admission': [
    { label: 'Notifications' },
    { label: 'Admission Events' },
  ],
  '/settings/audit': [
    { label: 'Notifications' },
    { label: 'Audit Log' },
  ],
  '/network/topology': [
    { label: 'Network Topology' },
  ],
  '/vulnerabilities': [
    { label: 'Vulnerabilities' },
    { label: 'Workloads' },
  ],
  '/policies/network': [
    { label: 'Policies' },
    { label: 'Network Policy' },
  ],
}

function useBreadcrumbs() {
  const { pathname } = useLocation()

  if (PATH_OVERRIDES[pathname]) {
    return [{ label: 'Home', to: '/dashboard' }, ...PATH_OVERRIDES[pathname]]
  }
  // The rest of a registry's path is its generated id, which names nothing.
  if (pathname === '/registries' || pathname.startsWith('/registries/')) {
    return [{ label: 'Home', to: '/dashboard' }, { label: 'Vulnerabilities' }, { label: 'Registries' }]
  }

  // A page under one of the overridden paths (its "new" or "edit" form) keeps
  // that trail, and the rest of the path follows it.
  const parent = Object.keys(PATH_OVERRIDES).find(p => pathname.startsWith(p + '/'))
  const segments = (parent ? pathname.slice(parent.length) : pathname).split('/').filter(Boolean)
  const crumbs: { label: string; to?: string }[] = [
    { label: 'Home', to: '/dashboard' }, ...(parent ? PATH_OVERRIDES[parent] : []),
  ]
  segments.forEach((seg) => {
    crumbs.push({ label: ROUTE_LABELS[seg] ?? seg })
  })
  return crumbs
}

interface Props {
  onLogout: () => Promise<void>
}

export function AppHeader({ onLogout }: Props) {
  const { user, limited, can } = useAuth()
  const [mode, setMode] = useState<{ protect: number; total: number } | null>(null)
  const breadcrumbs = useBreadcrumbs()

  useEffect(() => {
    // The count is of the cluster's policies.
    if (limited || !can('tracing', 'view')) return
    const read = () => { modeApi.get().then(setMode).catch(() => {}) }
    read()
    window.addEventListener(MODE_CHANGED, read)
    return () => window.removeEventListener(MODE_CHANGED, read)
  }, [limited])

  return (
    <header className="sticky top-0 z-50 flex h-14 w-full shrink-0 items-center gap-2 border-b bg-background px-4">
      <SidebarTrigger className="-ml-1" />

      <Breadcrumb>
        <BreadcrumbList>
          {breadcrumbs.map((c, i) => (
            <Fragment key={i}>
              {i > 0 && <BreadcrumbSeparator />}
              <BreadcrumbItem>
                {c.to ? (
                  <BreadcrumbLink asChild>
                    <Link to={c.to}>{c.label}</Link>
                  </BreadcrumbLink>
                ) : (
                  <BreadcrumbPage>{c.label}</BreadcrumbPage>
                )}
              </BreadcrumbItem>
            </Fragment>
          ))}
        </BreadcrumbList>
      </Breadcrumb>

      <div className="ml-auto flex items-center gap-2">
        {!limited && mode && (
          <Badge variant={mode.protect > 0 ? 'destructive' : 'outline'}>{mode.protect} / {mode.total} in Protect</Badge>
        )}
        <span className="text-xs text-muted-foreground">{user?.username}</span>
        <Button variant="ghost" size="sm" className="text-xs h-7" onClick={onLogout}>
          Sign out
        </Button>
      </div>
    </header>
  )
}
