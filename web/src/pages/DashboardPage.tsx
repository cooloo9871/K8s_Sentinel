import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  IconShieldCheck,
  IconShieldLock,
  IconShieldX,
  IconActivity,
  IconLock,
  IconArrowRight,
  IconRefresh,
} from '@tabler/icons-react'
import { Card, CardContent } from '@/components/ui/card'
import {
  Table, TableHeader, TableBody, TableRow, TableHead, TableCell,
} from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { policyApi, modeApi, vapApi, admissionApi, type VAPRecord, type VAPBindingRecord, type AdmissionEvent } from '../api/client'
import { useToast } from '../layout/AppToaster'
import { useAuth } from '../layout/AuthContext'
import { useSecurityEvents } from '../layout/SecurityEventsProvider'
import type { PolicyRecord, Mode } from '../api/types'

interface StatProps {
  icon: React.ReactNode
  label: string
  value: string | number
  sub?: string
  accent?: string
}

function StatCard({ icon, label, value, sub, accent = '#2d7dd2' }: StatProps) {
  return (
    <Card className="overflow-hidden">
      <CardContent className="p-0">
        <div className="flex items-stretch">
          <div
            className="flex w-14 shrink-0 items-center justify-center"
            style={{ background: accent + '18' }}
          >
            <span style={{ color: accent }}>{icon}</span>
          </div>
          <div className="flex flex-col justify-center px-5 py-4">
            <p className="text-sm text-muted-foreground">{label}</p>
            <p className="mt-0.5 text-2xl font-bold leading-none">{value}</p>
            {sub && <p className="mt-1 text-xs text-muted-foreground">{sub}</p>}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

function RelativeTime({ iso }: { iso: string }) {
  if (!iso) return <span className="text-muted-foreground">—</span>
  const d = new Date(iso)
  if (isNaN(d.getTime())) return <span>{iso}</span>
  const diff = Math.floor((Date.now() - d.getTime()) / 60000)
  let label = diff < 1 ? 'just now'
    : diff < 60 ? `${diff}m ago`
    : diff < 1440 ? `${Math.floor(diff / 60)}h ago`
    : `${Math.floor(diff / 1440)}d ago`
  return <span title={d.toLocaleString()}>{label}</span>
}

export function DashboardPage() {
  const navigate = useNavigate()
  const toast = useToast()
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const { events: secEvents } = useSecurityEvents()
  const [policies, setPolicies] = useState<PolicyRecord[]>([])
  const [vapPolicies, setVapPolicies] = useState<VAPRecord[]>([])
  const [vapBindings, setVapBindings] = useState<VAPBindingRecord[]>([])
  const [admissionEvents, setAdmissionEvents] = useState<AdmissionEvent[]>([])
  const [mode, setMode] = useState<Mode>('Monitoring')
  // useRef-based cache: survives navigation, resets on logout (component tree remount)
  const hasLoaded = useRef(false)
  const [loading, setLoading] = useState(!hasLoaded.current)

  const load = (showSpinner = false) => {
    if (showSpinner) setLoading(true)
    // All data loaded together for consistent freshness
    Promise.all([policyApi.list(), modeApi.get(), admissionApi.list()])
      .then(([p, m, adm]) => {
        setPolicies(p); setMode(m as Mode); setAdmissionEvents(adm)
        hasLoaded.current = true
      })
      .catch(() => toast.error('Failed to load dashboard'))
      .finally(() => setLoading(false))
    Promise.all([vapApi.listPolicies(), vapApi.listBindings()])
      .then(([vp, vb]) => { setVapPolicies(vp); setVapBindings(vb) })
      .catch(() => {})
  }

  useEffect(() => {
    load(!hasLoaded.current)
    // Refresh all dashboard data on the same 30s cadence for consistency
    const timer = setInterval(() => load(false), 30_000)
    return () => clearInterval(timer)
  }, [])

  const protectCount = policies.filter((p) => p.mode === 'Protect').length
  const recent = policies.slice(0, 8)
  const secWarning = secEvents.filter(e => e.severity === 'warning').length
  const secCritical = secEvents.filter(e => e.severity === 'critical').length
  const admCritical = admissionEvents.filter(e => e.severity === 'critical').length
  const admWarning = admissionEvents.filter(e => e.severity === 'warning').length

  const modeAccent = mode === 'Protect' ? '#dc3545' : mode === 'Mixed' ? '#fd7e14' : '#28a745'

  if (loading) {
    return (
      <div className="flex flex-col gap-8">
        <Skeleton className="h-8 w-48" />
        <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-24 rounded-xl" />)}
        </div>
        <Skeleton className="h-72 rounded-xl" />
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-8">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">Overview</h2>
          <p className="mt-1 text-base text-muted-foreground">
            Kubernetes security management — Tetragon runtime monitoring &amp; Admission control
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => load(true)}>
          <IconRefresh className="mr-2 size-4" />
          Refresh
        </Button>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        <StatCard
          icon={<IconShieldLock size={26} />}
          label="Tracing Policy — Protect"
          value={protectCount}
          sub={`${policies.length - protectCount} monitoring`}
          accent="#dc3545"
        />
        <StatCard
          icon={<IconActivity size={26} />}
          label="Security Events"
          value={secEvents.length}
          sub={`Critical: ${secCritical} / Warning: ${secWarning}`}
          accent="#f59e0b"
        />
        <StatCard
          icon={<IconShieldX size={26} />}
          label="Admission Events"
          value={admissionEvents.length}
          sub={`Critical: ${admCritical} / Warning: ${admWarning}`}
          accent="#8b5cf6"
        />
        <StatCard
          icon={<IconLock size={26} />}
          label="Global Protect Mode"
          value={mode === 'Protect' ? 'ON' : mode === 'Mixed' ? 'MIXED' : 'OFF'}
          sub={mode === 'Protect' ? 'Actively blocking violations' : mode === 'Mixed' ? 'Policies have mixed modes' : 'Monitoring only'}
          accent={modeAccent}
        />
      </div>

      {/* Tracing Policy */}
      <Card>
        <div className="flex items-center justify-between border-b px-6 py-4">
          <div>
            <h3 className="text-base font-semibold">Tracing Policy</h3>
            <p className="text-sm text-muted-foreground">Latest {recent.length} of {policies.length} policies</p>
          </div>
          <Button variant="ghost" size="sm" className="gap-1 text-sm" onClick={() => navigate('/policies/tracing')}>
            View all <IconArrowRight size={14} />
          </Button>
        </div>
        <CardContent className="p-0">
          {policies.length === 0 ? (
            <div className="flex flex-col items-center justify-center gap-3 py-16 text-muted-foreground">
              <IconShieldCheck size={40} strokeWidth={1.5} />
              <p className="text-base">No policies yet</p>
              {isAdmin && (
                <Button size="sm" onClick={() => navigate('/policies/tracing/new')}>
                  Create your first policy
                </Button>
              )}
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Scope</TableHead>
                  <TableHead>Mode</TableHead>
                  <TableHead>Namespace</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {recent.map((p) => (
                  <TableRow key={`${p.scope}-${p.namespace ?? ''}-${p.name}`}>
                    <TableCell className="font-medium">{p.name}</TableCell>
                    <TableCell>
                      <Badge variant={p.scope === 'cluster' ? 'destructive' : 'secondary'}>{p.scope}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant={p.mode === 'Protect' ? 'destructive' : p.mode === 'Mixed' ? 'outline' : 'secondary'}>{p.mode}</Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">{p.namespace ?? '-'}</TableCell>
                    <TableCell className="text-muted-foreground"><RelativeTime iso={p.createdAt} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Admission Policy */}
      <Card>
        <div className="flex items-center justify-between border-b px-6 py-4">
          <div>
            <h3 className="text-base font-semibold">Admission Policy</h3>
            <p className="text-sm text-muted-foreground">
              {vapPolicies.length} polic{vapPolicies.length !== 1 ? 'ies' : 'y'}, {vapBindings.length} binding{vapBindings.length !== 1 ? 's' : ''}
            </p>
          </div>
          <Button variant="ghost" size="sm" className="gap-1 text-sm" onClick={() => navigate('/policies/admission')}>
            View all <IconArrowRight size={14} />
          </Button>
        </div>
        <CardContent className="p-0">
          {vapPolicies.length === 0 ? (
            <div className="flex flex-col items-center justify-center gap-3 py-10 text-muted-foreground">
              <IconShieldCheck size={36} strokeWidth={1.5} />
              <p className="text-sm">No admission policies</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Policy</TableHead>
                  <TableHead>Failure Policy</TableHead>
                  <TableHead>Validations</TableHead>
                  <TableHead>Created By</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {vapPolicies.slice(0, 8).map((p) => (
                  <TableRow key={p.name}>
                    <TableCell className="font-medium">{p.name}</TableCell>
                    <TableCell>
                      <Badge variant={p.failurePolicy === 'Fail' ? 'destructive' : 'secondary'}>{p.failurePolicy || '—'}</Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">{p.validationCount}</TableCell>
                    <TableCell className="text-muted-foreground text-xs">{p.createdBy}</TableCell>
                    <TableCell className="text-muted-foreground"><RelativeTime iso={p.createdAt} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
