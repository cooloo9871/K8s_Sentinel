import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  IconShieldCheck,
  IconShieldX,
  IconActivity,
  IconLock,
  IconArrowRight,
  IconRefresh,
  IconServer,
} from '@tabler/icons-react'
import { Card, CardContent } from '@/components/ui/card'
import {
  Table, TableHeader, TableBody, TableRow, TableHead, TableCell,
} from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { policyApi, modeApi, vapApi, cnpApi, type VAPRecord, type VAPBindingRecord, type CNPRecord, quarantineApi,
  type QuarantinedPod,
} from '../api/client'
import { useToast } from '../layout/AppToaster'
import { useAuth } from '../layout/AuthContext'
import { useSecurityEvents } from '../layout/SecurityEventsProvider'
import { useAdmissionEvents } from '../layout/AdmissionEventsProvider'
import { RelativeTime } from '../components/RelativeTime'
import { isIngestProblem } from '../utils/ingestion'
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

// One ingestion source's health, from /api/ingestion/health. A source counts
// as a problem only once an attempt has actually failed, so a stream still
// coming up at startup does not raise a false alarm.
interface IngestSource {
  kind: string
  name: string
  connected: boolean
  consecutiveFailures: number
  lastError?: string
}

export function DashboardPage() {
  const navigate = useNavigate()
  const toast = useToast()
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const { events: secEvents } = useSecurityEvents()
  const { events: admissionEvents } = useAdmissionEvents()
  const [policies, setPolicies] = useState<PolicyRecord[]>([])
  const [vapPolicies, setVapPolicies] = useState<VAPRecord[]>([])
  const [vapBindings, setVapBindings] = useState<VAPBindingRecord[]>([])
  const [cnps, setCnps] = useState<CNPRecord[]>([])
  const [quarantined, setQuarantined] = useState<QuarantinedPod[]>([])
  // null until the first fetch; false on clusters without Cilium, where the
  // card is hidden rather than shown permanently empty.
  const [cnpAvailable, setCnpAvailable] = useState<boolean | null>(null)
  const [mode, setMode] = useState<Mode>('Monitoring')
  const [agentTotal, setAgentTotal] = useState<number | null>(null)
  const [agentReady, setAgentReady] = useState<number | null>(null)
  const [agentStreamDown, setAgentStreamDown] = useState(0)
  const [ingestProblems, setIngestProblems] = useState<IngestSource[]>([])
  const hasLoaded = useRef(false)
  const [loading, setLoading] = useState(!hasLoaded.current)

  const load = (showSpinner = false) => {
    if (showSpinner) setLoading(true)
    Promise.all([policyApi.list(), modeApi.get()])
      .then(([p, m]) => {
        setPolicies(p); setMode(m as Mode)
        hasLoaded.current = true
      })
      .catch(() => toast.error('Failed to load dashboard'))
      .finally(() => setLoading(false))
    Promise.all([vapApi.listPolicies(), vapApi.listBindings()])
      .then(([vp, vb]) => { setVapPolicies(vp); setVapBindings(vb) })
      .catch(() => {})
    cnpApi.list()
      .then(r => { setCnpAvailable(r.available); setCnps(r.policies ?? []) })
      .catch(() => setCnpAvailable(false))
    quarantineApi.list()
      .then(setQuarantined)
      .catch(() => {})
    fetch('/api/tetragon/agents')
      .then(r => r.json())
      .then((d: { agents: { ready: boolean; phase: string; ingestObserved: boolean; ingestConnected: boolean }[] }) => {
        const list = d.agents ?? []
        setAgentTotal(list.length)
        setAgentReady(list.filter(a => a.ready).length)
        setAgentStreamDown(list.filter(a => a.ready && a.phase === 'Running' && a.ingestObserved && !a.ingestConnected).length)
      })
      .catch(() => {})
    fetch('/api/ingestion/health')
      .then(r => r.json())
      .then((d: { sources: IngestSource[] }) => {
        setIngestProblems((d.sources ?? []).filter(isIngestProblem))
      })
      .catch(() => {})
  }

  useEffect(() => {
    load(!hasLoaded.current)
    // Refresh all dashboard data on the same 30s cadence for consistency
    const timer = setInterval(() => load(false), 30_000)
    return () => clearInterval(timer)
  }, [])

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
            Kubernetes security management
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => load(true)}>
          <IconRefresh className="mr-2 size-4" />
          Refresh
        </Button>
      </div>

      {/* Ingestion problems: surfaced only when a stream has actually failed,
          because a security console going silently blind is the worst failure. */}
      {ingestProblems.length > 0 && (
        <div className="rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-3 text-destructive">
          <p className="text-sm font-semibold">Ingestion problem detected. Sentinel may be missing events.</p>
          <ul className="mt-1.5 space-y-0.5 text-xs">
            {ingestProblems.map(s => (
              <li key={`${s.kind}:${s.name}`}>
                {s.kind === 'hubble' ? 'Hubble' : `Tetragon ${s.name}`}: {s.lastError || 'stream down'}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        <StatCard
          icon={<IconServer size={26} />}
          label="Tetragon Agents"
          value={agentTotal === null ? '—' : `${agentReady} / ${agentTotal}`}
          sub={
            agentTotal === null ? 'Loading…'
              : agentStreamDown > 0 ? `${agentStreamDown} stream${agentStreamDown > 1 ? 's' : ''} down`
              : agentReady === agentTotal && agentTotal > 0 ? 'All nodes ingesting'
              : agentTotal === 0 ? 'No agents found'
              : `${agentTotal - (agentReady ?? 0)} not ready`
          }
          accent={
            agentTotal === null ? '#6b7280'
              : agentStreamDown > 0 ? '#dc3545'
              : agentReady === agentTotal && agentTotal > 0 ? '#28a745'
              : '#dc3545'
          }
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

      {/* Network Policy — hidden entirely on clusters without Cilium, since the
          feature is unavailable there rather than merely empty */}
      {cnpAvailable && (
        <Card>
          <div className="flex items-center justify-between border-b px-6 py-4">
            <div>
              <h3 className="text-base font-semibold">Network Policy</h3>
              <p className="text-sm text-muted-foreground">
                {cnps.length} polic{cnps.length !== 1 ? 'ies' : 'y'}
                {cnps.filter(p => p.defaultDeny).length > 0 &&
                  ` · ${cnps.filter(p => p.defaultDeny).length} enforcing default deny`}
              </p>
            </div>
            <Button variant="ghost" size="sm" className="gap-1 text-sm" onClick={() => navigate('/policies/network')}>
              View all <IconArrowRight size={14} />
            </Button>
          </div>
          <CardContent className="p-0">
            {cnps.length === 0 ? (
              <div className="flex flex-col items-center justify-center gap-3 py-10 text-muted-foreground">
                <IconShieldCheck size={36} strokeWidth={1.5} />
                <p className="text-sm">No network policies</p>
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Policy</TableHead>
                    <TableHead>Scope</TableHead>
                    <TableHead>Applies to</TableHead>
                    <TableHead>Rules</TableHead>
                    <TableHead>Default Deny</TableHead>
                    <TableHead>Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {cnps.slice(0, 8).map((p) => (
                    <TableRow key={`${p.scope}-${p.namespace}-${p.name}`}>
                      <TableCell className="font-medium">
                        {p.name}
                        {p.hasL7 && (
                          <span className="ml-1.5 rounded bg-blue-500/10 px-1 py-0.5 text-[9px] font-medium text-blue-700">L7</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <Badge variant={p.scope === 'cluster' ? 'destructive' : 'secondary'}>
                          {p.scope === 'cluster' ? 'cluster-wide' : p.namespace}
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-[200px] truncate font-mono text-xs text-muted-foreground" title={p.selector}>
                        {p.selector}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {p.ingressRules === 0 && p.egressRules === 0
                          ? '—'
                          : [p.ingressRules > 0 && `in ${p.ingressRules}`, p.egressRules > 0 && `out ${p.egressRules}`]
                              .filter(Boolean).join(' · ')}
                      </TableCell>
                      <TableCell>
                        {p.defaultDeny
                          ? <Badge variant="destructive" className="text-[10px]">
                              {p.defaultDeny === 'both' ? 'Ingress + Egress' : p.defaultDeny === 'ingress' ? 'Ingress' : 'Egress'}
                            </Badge>
                          : <span className="text-muted-foreground text-xs">—</span>}
                      </TableCell>
                      <TableCell className="text-muted-foreground"><RelativeTime iso={p.createdAt} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}

      {/* Quarantine — always shown, unlike the Network Policy card above, because
          "nothing is contained" is a statement about the cluster worth making
          rather than an absence worth hiding. The count goes red when it is not
          zero: a contained pod is an incident in progress. */}
      <Card>
        <div className="flex items-center justify-between border-b px-6 py-4">
          <div>
            <h3 className="text-base font-semibold">Quarantine</h3>
            <p className={`text-sm ${quarantined.length > 0 ? 'font-medium text-red-600' : 'text-muted-foreground'}`}>
              {quarantined.length === 0
                ? 'No pods are contained'
                : `${quarantined.length} pod${quarantined.length !== 1 ? 's' : ''} cut off from the network`}
            </p>
          </div>
          <Button variant="ghost" size="sm" className="gap-1 text-sm" onClick={() => navigate('/policies/quarantine')}>
            View all <IconArrowRight size={14} />
          </Button>
        </div>
        <CardContent className="p-0">
          {quarantined.length === 0 ? (
            <div className="flex flex-col items-center justify-center gap-3 py-10 text-muted-foreground">
              <IconLock size={36} strokeWidth={1.5} />
              <p className="text-sm">Nothing is quarantined</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Namespace</TableHead>
                  <TableHead>Pod</TableHead>
                  <TableHead>Node</TableHead>
                  <TableHead>By</TableHead>
                  <TableHead>Quarantined</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {quarantined.slice(0, 8).map(p => (
                  <TableRow key={`${p.namespace}/${p.pod}`}>
                    <TableCell>{p.namespace}</TableCell>
                    <TableCell className="font-mono text-sm">
                      <IconLock size={11} className="mr-1 inline text-red-600" />
                      {p.pod}
                    </TableCell>
                    <TableCell className="text-muted-foreground">{p.node || '—'}</TableCell>
                    <TableCell className="text-muted-foreground">{p.by || '—'}</TableCell>
                    <TableCell className="text-muted-foreground">
                      {p.at ? <RelativeTime iso={p.at} /> : '—'}
                    </TableCell>
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
