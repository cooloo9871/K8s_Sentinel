import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  IconSearch,
  IconShieldCheck,
  IconPlayerPlay,
  IconPlayerStop,
} from '@tabler/icons-react'
import { Card, CardHeader, CardTitle, CardContent, CardAction } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import { useSecurityEvents } from '../layout/SecurityEventsProvider'
import { discoveryApi } from '../api/client'
import { useToast } from '../layout/AppToaster'
import type { PolicyFormInput } from '../api/types'

interface PodProfile {
  namespace: string
  pod: string
  binaries: string[]
  filePaths: string[]
  netDests: string[]
  eventCount: number
  lastSeen: string
}

function buildProfiles(events: ReturnType<typeof useSecurityEvents>['events']): PodProfile[] {
  const map = new Map<string, PodProfile>()

  for (const e of events) {
    if (!e.namespace && !e.pod) continue
    const key = `${e.namespace}/${e.pod}`
    if (!map.has(key)) {
      map.set(key, {
        namespace: e.namespace,
        pod: e.pod,
        binaries: [],
        filePaths: [],
        netDests: [],
        eventCount: 0,
        lastSeen: e.time,
      })
    }
    const p = map.get(key)!
    p.eventCount += e.count ?? 1
    if (e.time > p.lastSeen) p.lastSeen = e.time

    if (e.binary && !p.binaries.includes(e.binary)) p.binaries.push(e.binary)
    if (e.filePath && !p.filePaths.includes(e.filePath)) p.filePaths.push(e.filePath)
    if (e.netDest && !p.netDests.includes(e.netDest)) p.netDests.push(e.netDest)
  }

  return Array.from(map.values()).sort(
    (a, b) => `${a.namespace}/${a.pod}`.localeCompare(`${b.namespace}/${b.pod}`)
  )
}

function RelativeTime({ iso }: { iso: string }) {
  if (!iso) return null
  const d = new Date(iso)
  if (isNaN(d.getTime())) return null
  const diff = Math.floor((Date.now() - d.getTime()) / 1000)
  const label = diff < 60 ? `${diff}s ago`
    : diff < 3600 ? `${Math.floor(diff / 60)}m ago`
    : `${Math.floor(diff / 3600)}h ago`
  return <span className="text-xs text-muted-foreground">{label}</span>
}

export function DiscoveryPage() {
  const { events, connected } = useSecurityEvents()
  const navigate = useNavigate()
  const toast = useToast()
  const [nsFilter, setNsFilter] = useState('all')
  const [podSearch, setPodSearch] = useState('')
  const [discoveryEnabled, setDiscoveryEnabled] = useState(false)
  const [toggling, setToggling] = useState(false)

  useEffect(() => {
    discoveryApi.status().then(r => setDiscoveryEnabled(r.enabled)).catch(() => {})
  }, [])

  const handleToggleDiscovery = async () => {
    setToggling(true)
    try {
      const res = await discoveryApi.setEnabled(!discoveryEnabled)
      setDiscoveryEnabled(res.enabled)
      toast.success(res.enabled
        ? 'Discovery started — file and network behaviors will be captured.'
        : 'Discovery stopped.')
    } catch {
      toast.error('Failed to toggle discovery mode')
    } finally {
      setToggling(false)
    }
  }

  const profiles = useMemo(() => buildProfiles(events), [events])

  const namespaces = useMemo(
    () => Array.from(new Set(profiles.map(p => p.namespace))).filter(Boolean).sort(),
    [profiles]
  )

  const filtered = profiles.filter(p => {
    if (nsFilter !== 'all' && p.namespace !== nsFilter) return false
    if (podSearch.trim() && !p.pod.toLowerCase().includes(podSearch.trim().toLowerCase())) return false
    return true
  })

  const handleCreatePolicy = (profile: PodProfile) => {
    const prefill: PolicyFormInput = {
      name: `${profile.pod}-policy`,
      namespace: profile.namespace || 'default',
      process: profile.binaries.map(b => ({ binaries: [b] })),
      file: profile.filePaths.map(p => ({ paths: [p] })),
      network: profile.netDests.map(a => ({ address: a })),
      networkPorts: [],
      networkMode: profile.netDests.length > 0 ? 'whitelist' : undefined,
    }
    navigate('/policies/tracing/new', { state: { prefill } })
  }

  return (
    <>
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h4 className="text-xl font-semibold">Behavior Discovery</h4>
          <p className="text-sm text-muted-foreground">
            Observe pod behaviors and generate TracingPolicies from learned patterns.
          </p>
        </div>
        <div className="flex items-center gap-1.5 text-sm">
          <span className={`size-2 rounded-full ${connected ? 'bg-green-500' : 'bg-muted-foreground'}`} />
          <span className="text-muted-foreground">
            {events.filter(e => e.type === 'exec').length} exec ·{' '}
            {events.filter(e => e.type === 'kprobe').length} kprobe ·{' '}
            {profiles.length} pods
          </span>
        </div>
      </div>

      {/* Discovery control banner */}
      <div className={`mb-6 flex items-center justify-between rounded-xl border px-5 py-4 ${
        discoveryEnabled ? 'border-green-200 bg-green-50' : 'bg-card'
      }`}>
        <div>
          <div className="flex items-center gap-2">
            <span className={`size-2 rounded-full ${discoveryEnabled ? 'animate-pulse bg-green-500' : 'bg-muted-foreground'}`} />
            <p className="text-sm font-medium">
              {discoveryEnabled ? 'Discovery Active' : 'Discovery Inactive'}
            </p>
          </div>
          <p className="mt-0.5 text-xs text-muted-foreground">
            {discoveryEnabled
              ? 'Capturing all file access and network connections cluster-wide (Monitoring mode).'
              : 'Process behaviors are always collected. Start discovery to also capture file and network behaviors.'}
          </p>
        </div>
        <Button
          variant={discoveryEnabled ? 'outline' : 'default'}
          size="sm"
          onClick={handleToggleDiscovery}
          disabled={toggling}
          className="shrink-0"
        >
          {discoveryEnabled ? (
            <><IconPlayerStop size={14} className="mr-1.5" />Stop Discovery</>
          ) : (
            <><IconPlayerPlay size={14} className="mr-1.5" />Start Discovery</>
          )}
        </Button>
      </div>

      {profiles.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-3 py-24 text-muted-foreground">
          <IconShieldCheck size={48} strokeWidth={1.5} />
          <p className="text-base font-medium">No behavior data yet</p>
          <div className="max-w-md text-center text-sm space-y-2">
            <p>
              <strong>Process behaviors</strong> are captured automatically from all pods
              without any policy. They appear here as pods execute processes.
            </p>
            <p>
              Click <strong>Start Discovery</strong> above to also capture
              file access and network connections across the entire cluster.
            </p>
          </div>
        </div>
      ) : (
        <>
          {/* Filters */}
          <div className="mb-4 flex items-center gap-2">
            <Select value={nsFilter} onValueChange={setNsFilter}>
              <SelectTrigger className="h-9 w-44">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value="all">All Namespaces</SelectItem>
                  {namespaces.map(ns => (
                    <SelectItem key={ns} value={ns}>{ns}</SelectItem>
                  ))}
                </SelectGroup>
              </SelectContent>
            </Select>
            <div className="relative">
              <IconSearch size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search pod..."
                value={podSearch}
                onChange={e => setPodSearch(e.target.value)}
                className="h-9 w-44 pl-8"
              />
            </div>
            <span className="ml-auto text-sm text-muted-foreground">
              {filtered.length} pod{filtered.length !== 1 ? 's' : ''}
            </span>
          </div>

          {/* Pod cards */}
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {filtered.map(profile => (
              <Card key={`${profile.namespace}/${profile.pod}`}>
                <CardHeader className="border-b pb-3">
                  <div>
                    <CardTitle className="text-sm font-semibold">{profile.pod}</CardTitle>
                    <p className="text-xs text-muted-foreground">{profile.namespace}</p>
                  </div>
                  <CardAction>
                    <Button
                      size="sm"
                      variant="outline"
                      className="h-7 text-xs"
                      onClick={() => handleCreatePolicy(profile)}
                      disabled={
                        profile.binaries.length === 0 &&
                        profile.filePaths.length === 0 &&
                        profile.netDests.length === 0
                      }
                    >
                      Create Policy
                    </Button>
                  </CardAction>
                </CardHeader>
                <CardContent className="pt-3 text-xs">
                  {/* Process */}
                  <div className="mb-2">
                    <div className="mb-1 flex items-center justify-between">
                      <span className="font-medium text-foreground">Process</span>
                      <Badge variant="secondary" className="text-[10px]">{profile.binaries.length}</Badge>
                    </div>
                    {profile.binaries.length > 0 ? (
                      <div className="flex flex-wrap gap-1">
                        {profile.binaries.slice(0, 5).map(b => (
                          <span key={b} className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px]">
                            {b.split('/').pop()}
                          </span>
                        ))}
                        {profile.binaries.length > 5 && (
                          <span className="text-muted-foreground">+{profile.binaries.length - 5} more</span>
                        )}
                      </div>
                    ) : <span className="text-muted-foreground">—</span>}
                  </div>

                  {/* File */}
                  <div className="mb-2">
                    <div className="mb-1 flex items-center justify-between">
                      <span className="font-medium text-foreground">File</span>
                      <Badge variant="secondary" className="text-[10px]">{profile.filePaths.length}</Badge>
                    </div>
                    {profile.filePaths.length > 0 ? (
                      <div className="flex flex-col gap-0.5">
                        {profile.filePaths.slice(0, 3).map(f => (
                          <span key={f} className="truncate font-mono text-[10px] text-muted-foreground" title={f}>{f}</span>
                        ))}
                        {profile.filePaths.length > 3 && (
                          <span className="text-muted-foreground">+{profile.filePaths.length - 3} more</span>
                        )}
                      </div>
                    ) : (
                      <span className="text-muted-foreground">
                        {discoveryEnabled ? '—' : 'Start discovery to capture file behaviors'}
                      </span>
                    )}
                  </div>

                  {/* Network */}
                  <div>
                    <div className="mb-1 flex items-center justify-between">
                      <span className="font-medium text-foreground">Network</span>
                      <Badge variant="secondary" className="text-[10px]">{profile.netDests.length}</Badge>
                    </div>
                    {profile.netDests.length > 0 ? (
                      <div className="flex flex-col gap-0.5">
                        {profile.netDests.slice(0, 3).map(n => (
                          <span key={n} className="font-mono text-[10px] text-muted-foreground">{n}</span>
                        ))}
                        {profile.netDests.length > 3 && (
                          <span className="text-muted-foreground">+{profile.netDests.length - 3} more</span>
                        )}
                      </div>
                    ) : (
                      <span className="text-muted-foreground">
                        {discoveryEnabled ? '—' : 'Start discovery to capture network behaviors'}
                      </span>
                    )}
                  </div>

                  <div className="mt-3 flex items-center justify-between border-t pt-2">
                    <span className="text-muted-foreground">{profile.eventCount} events</span>
                    <RelativeTime iso={profile.lastSeen} />
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </>
      )}
    </>
  )
}
