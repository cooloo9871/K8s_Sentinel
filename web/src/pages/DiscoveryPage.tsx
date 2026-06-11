import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { IconFolder, IconSearch, IconShieldCheck, IconTrash } from '@tabler/icons-react'
import {
  Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import { Card, CardHeader, CardTitle, CardContent, CardAction } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { useDiscovery } from '../layout/DiscoveryProvider'
import type { PodProfile, WorkloadProfile } from '../layout/DiscoveryProvider'
import { useToast } from '../layout/AppToaster'
import { podApi } from '../api/client'
import { formatTWTime } from '../utils/time'
import type { PolicyFormInput } from '../api/types'

function RelativeTime({ iso }: { iso: string }) {
  if (!iso) return null
  const d = new Date(iso)
  if (isNaN(d.getTime())) return null
  const diff = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000))
  const label = diff < 60 ? 'just now'
    : diff < 3600 ? `${Math.floor(diff / 60)}m ago`
    : `${Math.floor(diff / 3600)}h ago`
  return <span className="text-xs text-muted-foreground" title={formatTWTime(iso)}>{label}</span>
}

function WorkloadCard({ wl, creatingFor, onCreatePolicy }: {
  wl: WorkloadProfile
  creatingFor: string | null
  onCreatePolicy: (wl: WorkloadProfile) => void
}) {
  const key = `${wl.namespace}/${wl.workloadKind}/${wl.workloadName}`
  const binaries = wl.binaries ?? []
  return (
    <Card>
      <CardHeader className="border-b pb-3">
        <div>
          <div className="flex items-center gap-1.5">
            <Badge variant="secondary" className="text-[10px] font-mono">{wl.workloadKind}</Badge>
            <CardTitle className="text-sm font-semibold">{wl.workloadName}</CardTitle>
          </div>
          <p className="text-xs text-muted-foreground">
            {wl.namespace} · {wl.pods.length} pod{wl.pods.length !== 1 ? 's' : ''}
          </p>
        </div>
        <CardAction>
          <Button
            size="sm" variant="outline" className="h-7 text-xs"
            disabled={binaries.length === 0 || creatingFor === key}
            onClick={() => onCreatePolicy(wl)}
          >
            {creatingFor === key ? 'Loading...' : 'Create Policy'}
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent className="pt-3 text-xs">
        <div className="mb-1 flex items-center justify-between">
          <span className="font-medium">Process</span>
          <Badge variant="secondary" className="text-[10px]">{binaries.length}</Badge>
        </div>
        {binaries.length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {binaries.slice(0, 8).map(b => (
              <span key={b} className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px]" title={b}>
                {b.split('/').pop()}
              </span>
            ))}
            {binaries.length > 8 && (
              <span className="text-muted-foreground">+{binaries.length - 8} more</span>
            )}
          </div>
        ) : <span className="text-muted-foreground">—</span>}
        <div className="mt-3 border-t pt-2 text-muted-foreground">
          since <RelativeTime iso={wl.firstSeen} />
        </div>
      </CardContent>
    </Card>
  )
}

/** Build WorkloadProfile list by merging pods with the same workload owner. */
function buildWorkloadGroups(profiles: PodProfile[]): WorkloadProfile[] {
  const map = new Map<string, WorkloadProfile>()
  for (const p of profiles) {
    const kind = p.workloadKind || ''
    const wname = p.workloadName || ''
    // Pods without a workload owner form their own group keyed by pod name.
    const key = kind && wname
      ? `${p.namespace}/${kind}/${wname}`
      : `${p.namespace}/pod/${p.pod}`
    const existing = map.get(key)
    if (existing) {
      if (!existing.pods.includes(p.pod)) existing.pods.push(p.pod)
      for (const b of p.binaries ?? []) {
        if (!existing.binaries.includes(b)) existing.binaries.push(b)
      }
      if (p.firstSeen < existing.firstSeen) existing.firstSeen = p.firstSeen
      if (p.lastSeen > existing.lastSeen) existing.lastSeen = p.lastSeen
    } else {
      map.set(key, {
        namespace: p.namespace,
        workloadKind: kind || 'Pod',
        workloadName: wname || p.pod,
        pods: [p.pod],
        binaries: [...(p.binaries ?? [])],
        firstSeen: p.firstSeen,
        lastSeen: p.lastSeen,
      })
    }
  }
  return [...map.values()].sort((a, b) =>
    (a.namespace + a.workloadName).localeCompare(b.namespace + b.workloadName)
  )
}

export function DiscoveryPage() {
  const { profiles, clearProfiles } = useDiscovery()
  const navigate = useNavigate()
  const toast = useToast()
  const [nsFilter, setNsFilter] = useState('all')
  const [podSearch, setPodSearch] = useState('')
  const [groupByNs, setGroupByNs] = useState(false)
  const [clearDialog, setClearDialog] = useState(false)
  const [creatingFor, setCreatingFor] = useState<string | null>(null)

  const namespaces = [...new Set(profiles.map(p => p.namespace))].sort()

  const filtered = profiles.filter(p => {
    if (nsFilter !== 'all' && p.namespace !== nsFilter) return false
    if (podSearch.trim() && !p.pod.toLowerCase().includes(podSearch.trim().toLowerCase())) return false
    return true
  })

  const workloadGroups = buildWorkloadGroups(filtered)

  const handleCreatePolicy = async (wl: WorkloadProfile) => {
    const key = `${wl.namespace}/${wl.workloadKind}/${wl.workloadName}`
    setCreatingFor(key)
    let podSelector: Record<string, string> | undefined
    // Try each pod until labels are found (some may have restarted)
    for (const pod of wl.pods) {
      try {
        const res = await podApi.labels(wl.namespace, pod)
        if (Object.keys(res.labels).length > 0) { podSelector = res.labels; break }
      } catch { /* continue */ }
    }
    setCreatingFor(null)
    const binaries = wl.binaries ?? []
    const prefill: PolicyFormInput = {
      name: `${wl.workloadName}-policy`,
      namespace: wl.namespace || 'default',
      podSelector,
      processMode: 'whitelist',
      process: binaries.length > 0 ? binaries.map(b => ({ binaries: [b] })) : undefined,
    }
    navigate('/policies/tracing/new', { state: { prefill } })
    toast.success('Policy pre-filled.')
  }

  return (
    <>
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h4 className="text-xl font-semibold">Behavior Discovery</h4>
          <p className="text-sm text-muted-foreground">
            Process behaviors learned from the Tetragon base sensor. No policy required.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => setClearDialog(true)}>
          <IconTrash size={14} className="mr-1.5" />
          Clear All
        </Button>
      </div>

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
        <Button
          variant={groupByNs ? 'default' : 'outline'}
          size="sm"
          className="h-9 w-9 p-0"
          title={groupByNs ? 'Grouped by namespace' : 'Group by namespace'}
          onClick={() => setGroupByNs(v => !v)}
        >
          <IconFolder size={16} />
        </Button>
        <span className="ml-auto text-sm text-muted-foreground">
          {workloadGroups.length} workload{workloadGroups.length !== 1 ? 's' : ''} · {profiles.length} pods total
        </span>
      </div>

      {profiles.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-3 py-24 text-muted-foreground">
          <IconShieldCheck size={48} strokeWidth={1.5} />
          <p className="text-base font-medium">Listening for process activity...</p>
          <p className="max-w-sm text-center text-sm">
            Pod behaviors appear automatically as processes run across the cluster.
          </p>
        </div>
      ) : groupByNs ? (
        // ── Namespace-grouped view ──────────────────────────────────────────
        (() => {
          const byNs = workloadGroups.reduce<Record<string, typeof workloadGroups>>((acc, wl) => {
            ;(acc[wl.namespace] ??= []).push(wl)
            return acc
          }, {})
          // Soft color palette — derived from namespace name so the same ns
          // always gets the same color across renders.
          const PALETTES = [
            { box: 'bg-blue-50/60 border-blue-200',    header: 'bg-blue-100 border-blue-200 text-blue-900' },
            { box: 'bg-emerald-50/60 border-emerald-200', header: 'bg-emerald-100 border-emerald-200 text-emerald-900' },
            { box: 'bg-violet-50/60 border-violet-200', header: 'bg-violet-100 border-violet-200 text-violet-900' },
            { box: 'bg-amber-50/60 border-amber-200',  header: 'bg-amber-100 border-amber-200 text-amber-900' },
            { box: 'bg-rose-50/60 border-rose-200',    header: 'bg-rose-100 border-rose-200 text-rose-900' },
            { box: 'bg-cyan-50/60 border-cyan-200',    header: 'bg-cyan-100 border-cyan-200 text-cyan-900' },
            { box: 'bg-orange-50/60 border-orange-200',header: 'bg-orange-100 border-orange-200 text-orange-900' },
            { box: 'bg-teal-50/60 border-teal-200',    header: 'bg-teal-100 border-teal-200 text-teal-900' },
          ]
          const pickColor = (ns: string) => {
            let h = 0
            for (let i = 0; i < ns.length; i++) h = (h * 31 + ns.charCodeAt(i)) & 0xffff
            return PALETTES[h % PALETTES.length]
          }
          return (
            <div className="flex flex-col gap-6">
              {Object.entries(byNs).sort(([a], [b]) => a.localeCompare(b)).map(([ns, items]) => {
                const c = pickColor(ns)
                return (
                  <div key={ns} className={`rounded-lg border shadow-sm ${c.box}`}>
                    <div className={`flex items-center justify-between rounded-t-lg border-b px-4 py-2.5 ${c.header}`}>
                      <span className="text-sm font-semibold">
                        Namespace: <span className="font-bold">{ns}</span>
                      </span>
                      <span className="text-xs opacity-70">{items.length} workload{items.length !== 1 ? 's' : ''}</span>
                    </div>
                    <div className="grid gap-4 p-4 md:grid-cols-2 xl:grid-cols-3">
                      {items.map(wl => <WorkloadCard key={`${wl.namespace}/${wl.workloadKind}/${wl.workloadName}`} wl={wl} creatingFor={creatingFor} onCreatePolicy={handleCreatePolicy} />)}
                    </div>
                  </div>
                )
              })}
            </div>
          )
        })()
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {workloadGroups.map(wl => (
            <WorkloadCard
              key={`${wl.namespace}/${wl.workloadName}`}
              wl={wl}
              creatingFor={creatingFor}
              onCreatePolicy={handleCreatePolicy}
            />
          ))}
        </div>
      )}

      <AlertDialog open={clearDialog} onOpenChange={setClearDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Clear Discovery Data</AlertDialogTitle>
            <AlertDialogDescription>
              Delete all learned process behaviors for all pods. Cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              onClick={() => { clearProfiles(); setClearDialog(false) }}
            >
              Clear All
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
