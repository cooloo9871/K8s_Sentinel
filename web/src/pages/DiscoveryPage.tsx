import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { IconSearch, IconShieldCheck, IconTrash } from '@tabler/icons-react'
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

export function DiscoveryPage() {
  const { profiles, clearProfiles } = useDiscovery()
  const navigate = useNavigate()
  const toast = useToast()
  const [nsFilter, setNsFilter] = useState('all')
  const [podSearch, setPodSearch] = useState('')
  const [clearDialog, setClearDialog] = useState(false)
  const [creatingFor, setCreatingFor] = useState<string | null>(null)

  const namespaces = [...new Set(profiles.map(p => p.namespace))].sort()

  const filtered = profiles.filter(p => {
    if (nsFilter !== 'all' && p.namespace !== nsFilter) return false
    if (podSearch.trim() && !p.pod.toLowerCase().includes(podSearch.trim().toLowerCase())) return false
    return true
  })

  const handleCreatePolicy = async (profile: typeof profiles[0]) => {
    const key = `${profile.namespace}/${profile.pod}`
    setCreatingFor(key)
    let podSelector: Record<string, string> | undefined
    try {
      const res = await podApi.labels(profile.namespace, profile.pod)
      if (Object.keys(res.labels).length > 0) podSelector = res.labels
    } catch {
      // Pod may no longer exist — proceed without selector
    } finally {
      setCreatingFor(null)
    }
    const binaries = profile.binaries ?? []
    const prefill: PolicyFormInput = {
      name: `${profile.pod}-policy`,
      namespace: profile.namespace || 'default',
      podSelector,
      processMode: 'whitelist',
      process: binaries.length > 0 ? binaries.map(b => ({ binaries: [b] })) : undefined,
    }
    navigate('/policies/tracing/new', { state: { prefill } })
    toast.success('Policy form pre-filled with discovered processes and pod labels.')
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
        <span className="ml-auto text-sm text-muted-foreground">
          {filtered.length} pod{filtered.length !== 1 ? 's' : ''} · {profiles.length} total
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
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {filtered.map(profile => {
            const key = `${profile.namespace}/${profile.pod}`
            const binaries = profile.binaries ?? []
            return (
              <Card key={key}>
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
                      disabled={binaries.length === 0 || creatingFor === key}
                      onClick={() => handleCreatePolicy(profile)}
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
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                  <div className="mt-3 flex items-center justify-between border-t pt-2">
                    <span className="text-muted-foreground">since <RelativeTime iso={profile.firstSeen} /></span>
                    <RelativeTime iso={profile.lastSeen} />
                  </div>
                </CardContent>
              </Card>
            )
          })}
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
