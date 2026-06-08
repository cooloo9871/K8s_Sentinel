import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { IconSearch, IconShieldCheck, IconTrash, IconWifi } from '@tabler/icons-react'
import { Card, CardHeader, CardTitle, CardContent, CardAction } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { useDiscovery } from '../layout/DiscoveryProvider'
import { discoveryApi, namespaceApi } from '../api/client'
import type { PolicyFormInput } from '../api/types'

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
  const { profiles, clearProfiles } = useDiscovery()
  const navigate = useNavigate()
  const [nsFilter, setNsFilter] = useState('all')
  const [podSearch, setPodSearch] = useState('')
  const [allNamespaces, setAllNamespaces] = useState<string[]>([])
  const [nsLoading, setNsLoading] = useState(true)
  const [clearDialog, setClearDialog] = useState(false)

  useEffect(() => {
    namespaceApi.list()
      .then(ns => setAllNamespaces(ns.sort()))
      .catch(() => {})
      .finally(() => setNsLoading(false))
  }, [])

  // Auto-enable the catch-all discovery policy
  useEffect(() => {
    discoveryApi.setEnabled(true).catch(() => {})
  }, [])

  const filtered = profiles.filter(p => {
    if (nsFilter !== 'all' && p.namespace !== nsFilter) return false
    if (podSearch.trim() && !p.pod.toLowerCase().includes(podSearch.trim().toLowerCase())) return false
    return true
  })

  const handleCreatePolicy = (profile: typeof profiles[0]) => {
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
            Continuously learning pod behaviors. Use patterns to generate TracingPolicies.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-sm">
            <IconWifi size={16} className="text-green-500" />
            <span className="text-green-600">Discovering</span>
          </div>
          <Button variant="outline" size="sm" onClick={() => setClearDialog(true)}>
            <IconTrash size={14} className="mr-1.5" />
            Clear
          </Button>
        </div>
      </div>

      {/* Filters */}
      <div className="mb-4 flex items-center gap-2">
        {nsLoading ? (
          <Skeleton className="h-9 w-44 rounded-md" />
        ) : (
          <Select value={nsFilter} onValueChange={setNsFilter}>
            <SelectTrigger className="h-9 w-44">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="all">All Namespaces</SelectItem>
                {allNamespaces.map(ns => (
                  <SelectItem key={ns} value={ns}>{ns}</SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
        )}
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
          {filtered.length} pod{filtered.length !== 1 ? 's' : ''} · {profiles.length} total learned
        </span>
      </div>

      {profiles.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-3 py-24 text-muted-foreground">
          <IconShieldCheck size={48} strokeWidth={1.5} />
          <p className="text-base font-medium">Learning in progress...</p>
          <p className="max-w-sm text-center text-sm">
            Behaviors appear here as pods execute processes, access files, and make
            network connections. Data is persisted — come back anytime to see what's been learned.
          </p>
        </div>
      ) : (
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
                    <span className="font-medium">Process</span>
                    <Badge variant="secondary" className="text-[10px]">{profile.binaries.length}</Badge>
                  </div>
                  {profile.binaries.length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {profile.binaries.slice(0, 6).map(b => (
                        <span key={b} className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px]" title={b}>
                          {b.split('/').pop()}
                        </span>
                      ))}
                      {profile.binaries.length > 6 && (
                        <span className="text-muted-foreground">+{profile.binaries.length - 6} more</span>
                      )}
                    </div>
                  ) : <span className="text-muted-foreground">—</span>}
                </div>

                {/* File */}
                <div className="mb-2">
                  <div className="mb-1 flex items-center justify-between">
                    <span className="font-medium">File</span>
                    <Badge variant="secondary" className="text-[10px]">{profile.filePaths.length}</Badge>
                  </div>
                  {profile.filePaths.length > 0 ? (
                    <div className="flex flex-col gap-0.5">
                      {profile.filePaths.slice(0, 4).map(f => (
                        <span key={f} className="truncate font-mono text-[10px] text-muted-foreground" title={f}>{f}</span>
                      ))}
                      {profile.filePaths.length > 4 && (
                        <span className="text-muted-foreground">+{profile.filePaths.length - 4} more</span>
                      )}
                    </div>
                  ) : <span className="text-muted-foreground">—</span>}
                </div>

                {/* Network */}
                <div>
                  <div className="mb-1 flex items-center justify-between">
                    <span className="font-medium">Network</span>
                    <Badge variant="secondary" className="text-[10px]">{profile.netDests.length}</Badge>
                  </div>
                  {profile.netDests.length > 0 ? (
                    <div className="flex flex-col gap-0.5">
                      {profile.netDests.slice(0, 4).map(n => (
                        <span key={n} className="font-mono text-[10px] text-muted-foreground">{n}</span>
                      ))}
                      {profile.netDests.length > 4 && (
                        <span className="text-muted-foreground">+{profile.netDests.length - 4} more</span>
                      )}
                    </div>
                  ) : <span className="text-muted-foreground">—</span>}
                </div>

                <div className="mt-3 flex items-center justify-between border-t pt-2">
                  <span className="text-muted-foreground">
                    since <RelativeTime iso={profile.firstSeen} />
                  </span>
                  <RelativeTime iso={profile.lastSeen} />
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Clear confirmation */}
      <AlertDialog open={clearDialog} onOpenChange={setClearDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Clear Discovery Data</AlertDialogTitle>
            <AlertDialogDescription>
              This will delete all learned behaviors for all pods. Discovery will start fresh.
              This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction variant="destructive" onClick={() => { clearProfiles(); setClearDialog(false) }}>
              Clear All
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
