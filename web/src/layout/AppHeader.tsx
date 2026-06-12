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
import { SidebarTrigger } from '@/components/ui/sidebar'
import { Separator } from '@/components/ui/separator'
import { modeApi } from '../api/client'
import type { Mode } from '../api/types'

const ROUTE_LABELS: Record<string, string> = {
  dashboard: 'Dashboard',
  policies: 'Policies',
  tracing: 'TracingPolicy',
  new: 'New Policy',
  edit: 'Edit',
  templates: 'Templates',
  discovery: 'Behavior Discovery',
  security: 'Notifications',
  events: 'Security Events',
  cluster: 'Cluster',
  mode: 'Mode Control',
  namespaces: 'Namespaces',
  tetragon: 'Tetragon Agents',
}

// Override the full breadcrumb trail for paths whose URL segments don't match
// the desired label hierarchy (e.g. /security/discovery lives under Policies).
const PATH_OVERRIDES: Record<string, { label: string; to?: string }[]> = {
  '/security/discovery': [
    { label: 'Policies', to: '/policies/tracing' },
    { label: 'Behavior Discovery' },
  ],
  '/security/events': [
    { label: 'Notifications' },
    { label: 'Security Events' },
  ],
}

function useBreadcrumbs() {
  const { pathname } = useLocation()

  if (PATH_OVERRIDES[pathname]) {
    return [{ label: 'Home', to: '/dashboard' }, ...PATH_OVERRIDES[pathname]]
  }

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

  const modeVariant =
    mode === 'Protect' ? 'destructive' : mode === 'Mixed' ? 'secondary' : 'outline'

  return (
    <header className="sticky top-0 z-10 flex h-14 shrink-0 items-center gap-2 border-b bg-background px-4">
      <SidebarTrigger className="-ml-1" />
      <Separator orientation="vertical" className="mr-2 h-4" />

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

      <Badge variant={modeVariant} className="ml-auto">
        {mode.toUpperCase()}
      </Badge>
    </header>
  )
}
