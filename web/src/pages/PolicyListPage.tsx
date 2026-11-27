import { useEffect, useRef, useState } from 'react'
import { IconRefresh } from '@tabler/icons-react'
import { ScopeFilter, matchesScopeFilter } from '../components/ScopeFilter'
import { useNavigate } from 'react-router-dom'
import { formatTWTime } from '../utils/time'
import {
  Table, TableHeader, TableBody, TableRow, TableHead, TableCell,
} from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Label } from '@/components/ui/label'
import { NamespaceSelect } from '../components/NamespaceSelect'
import { policyApi, modeApi, namespaceApi } from '../api/client'
import { useToast } from '../layout/AppToaster'
import { useAuth } from '../layout/AuthContext'
import type { PolicyRecord } from '../api/types'

const MODE_VARIANT: Record<string, 'destructive' | 'secondary' | 'outline'> = {
  Protect: 'destructive',
  Monitoring: 'secondary',
  Mixed: 'outline',
}

export function PolicyListPage() {
  const navigate = useNavigate()
  const { limited, can } = useAuth()
  const isAdmin = can('tracing', 'manage')
  const toast = useToast()
  const hasLoaded = useRef(false)
  const [policies, setPolicies] = useState<PolicyRecord[]>([])
  const [loading, setLoading] = useState(!hasLoaded.current)
  const [search, setSearch] = useState('')
  const [nsFilter, setNsFilter] = useState<string[]>([])
  const [deleteTarget, setDeleteTarget] = useState<PolicyRecord | null>(null)
  const [pendingModeChange, setPendingModeChange] = useState<{
    policy: PolicyRecord
    mode: 'Monitoring' | 'Protect'
  } | null>(null)

  const [modeModal, setModeModal] = useState(false)

  // Image Lockdown
  const [lockOpen, setLockOpen] = useState(false)
  const [lockNamespaces, setLockNamespaces] = useState<string[]>([])
  const [lockNs, setLockNs] = useState('')
  const [lockWorkloads, setLockWorkloads] = useState<{ kind: string; name: string }[]>([])
  const [lockWorkload, setLockWorkload] = useState('')
  const [lockMode, setLockMode] = useState<'Monitoring' | 'Protect'>('Monitoring')
  const [locking, setLocking] = useState(false)

  const openLock = () => {
    setLockNs('')
    setLockWorkloads([])
    setLockWorkload('')
    setLockMode('Monitoring')
    setLockOpen(true)
    namespaceApi.list().then(setLockNamespaces).catch(() => setLockNamespaces([]))
  }

  const chooseLockNs = (ns: string) => {
    setLockNs(ns)
    setLockWorkload('')
    setLockWorkloads([])
    policyApi.workloads(ns).then(setLockWorkloads).catch(() => toast.error('Failed to load workloads'))
  }

  const handleLock = async () => {
    const [kind, name] = lockWorkload.split('/')
    setLocking(true)
    try {
      const r = await policyApi.lockToImage(lockNs, kind, name, lockMode)
      toast.success(r.blocksOutside
        ? `${name} locked to its image`
        : `${name} locked to its image. kubectl exec is not stopped for this workload.`)
      setLockOpen(false)
      fetchPolicies()
    } catch (e) {
      toast.error(e instanceof Error && e.message ? e.message : 'Failed to lock the workload')
    } finally {
      setLocking(false)
    }
  }

  const fetchPolicies = async (showSpinner = false) => {
    if (showSpinner) setLoading(true)
    try {
      setPolicies(await policyApi.list())
      hasLoaded.current = true
    } catch {
      toast.error('Failed to load policies')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchPolicies(!hasLoaded.current)
  }, [])

  const enforcing = policies.filter(p => p.mode !== 'Monitoring').length

  const handleStopEnforcing = async () => {
    try {
      await modeApi.stop()
      toast.success('All policies set to Monitoring')
    } catch {
      toast.error('Failed to set all policies to Monitoring')
    }
    fetchPolicies()
  }

  const handleDelete = async () => {
    if (!deleteTarget) return
    try {
      await policyApi.delete(deleteTarget.name, deleteTarget.namespace)
      toast.success('Policy deleted')
      fetchPolicies()
    } catch {
      toast.error('Failed to delete policy')
    }
  }

  const handleModeChange = async (p: PolicyRecord, mode: 'Monitoring' | 'Protect') => {
    setPolicies((prev) =>
      prev.map((x) =>
        x.name === p.name && x.namespace === p.namespace ? { ...x, mode } : x
      )
    )
    try {
      await policyApi.setMode(p.name, p.namespace, mode)
      toast.success(`${p.name}: mode set to ${mode}`)
    } catch (e) {
      const msg = (e as { response?: { data?: { error?: string } } })?.response?.data?.error
      toast.error(msg || `Failed to update mode for ${p.name}`)
      fetchPolicies()
    }
  }

  const namespaces = [...new Set(policies.map(p => p.namespace).filter(Boolean))].sort() as string[]

  const filtered = policies.filter((p) => {
    const matchName = p.name.toLowerCase().includes(search.toLowerCase())
    const matchNs = matchesScopeFilter(p.scope, p.namespace, nsFilter)
    return matchName && matchNs
  })

  return (
    <>
      {/* Page header */}
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h4 className="text-xl font-semibold">Tracing Policy</h4>
        </div>
      </div>

      <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Input
            placeholder="Search by name..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="h-8 w-56 text-sm"
          />
          <ScopeFilter value={nsFilter} onChange={setNsFilter} namespaces={namespaces} />
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" size="sm" onClick={() => fetchPolicies(true)} disabled={loading}>
            <IconRefresh size={14} className="mr-1.5" />
            Refresh
          </Button>
          {isAdmin && !limited && enforcing > 0 && (
            <Button variant="outline" size="sm" onClick={() => setModeModal(true)}>
              Set all to Monitoring
            </Button>
          )}
          {isAdmin && (
            <>
              <Button size="sm" onClick={() => navigate('/policies/tracing/new')}>+ New Policy</Button>
              <Button size="sm" variant="outline" onClick={() => navigate('/policies/tracing/new?mode=yaml')}>
                + New YAML
              </Button>
              <Button size="sm" variant="outline" onClick={openLock}>
                + Image Lockdown
              </Button>
            </>
          )}
        </div>
      </div>

      <Card>
        <CardContent className="p-0">
          {loading ? (
            <div className="flex flex-col gap-2 p-4">
              {Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Scope</TableHead>
                  <TableHead>Mode</TableHead>
                  <TableHead>Namespace</TableHead>
                  <TableHead>Created By</TableHead>
                  <TableHead>Created Time</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="py-10 text-center text-muted-foreground">
                      No policies found
                    </TableCell>
                  </TableRow>
                ) : (
                  filtered.map((p) => (
                    <TableRow key={`${p.scope}-${p.namespace ?? ''}-${p.name}`}>
                      <TableCell className="w-full max-w-0 min-w-56 font-medium">
                        <div className="flex items-center gap-2">
                          <span className="truncate" title={p.name}>{p.name}</span>
                          {p.inactive && (
                            <Badge variant="destructive" className="shrink-0" title={p.inactive}>Not active</Badge>
                          )}
                        </div>
                        {p.imageBlocked && (
                          <Badge variant="destructive" className="mt-1" title={p.imageBlocked}>New image blocked, set to Monitoring</Badge>
                        )}
                      </TableCell>
                      <TableCell>
                        <Badge variant={p.scope === 'cluster' ? 'destructive' : 'secondary'}>
                          {p.scope}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {isAdmin ? (
                          <Select
                            value={p.mode === 'Mixed' ? 'Mixed' : p.mode}
                            onValueChange={(v) =>
                              setPendingModeChange({ policy: p, mode: v as 'Monitoring' | 'Protect' })
                            }
                          >
                            <SelectTrigger className="h-7 w-32 text-xs">
                              <SelectValue>
                                <Badge variant={MODE_VARIANT[p.mode] ?? 'outline'}>
                                  {p.mode}
                                </Badge>
                              </SelectValue>
                            </SelectTrigger>
                            <SelectContent>
                              <SelectGroup>
                                <SelectItem value="Monitoring">Monitoring</SelectItem>
                                <SelectItem value="Protect">Protect</SelectItem>
                              </SelectGroup>
                            </SelectContent>
                          </Select>
                        ) : (
                          <Badge variant={MODE_VARIANT[p.mode] ?? 'outline'}>{p.mode}</Badge>
                        )}
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {p.namespace ?? '-'}
                      </TableCell>
                      <TableCell className="text-muted-foreground text-xs">{p.createdBy}</TableCell>
                      <TableCell className="text-muted-foreground">{formatTWTime(p.createdAt)}</TableCell>
                      <TableCell className="text-right">
                        {isAdmin ? (
                          <div className="flex justify-end gap-2">
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() =>
                                navigate(`/policies/tracing/${p.name}/edit?namespace=${p.namespace ?? ''}`)
                              }
                            >
                              {p.imageLock ? 'View' : 'Edit'}
                            </Button>
                            <Button
                              variant="destructive"
                              size="sm"
                              onClick={() => setDeleteTarget(p)}
                            >
                              Delete
                            </Button>
                          </div>
                        ) : (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() =>
                              navigate(`/policies/tracing/${p.name}/edit?namespace=${p.namespace ?? ''}`)
                            }
                          >
                            View YAML
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <AlertDialog open={lockOpen} onOpenChange={(open) => { if (!locking) setLockOpen(open) }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Image Lockdown</AlertDialogTitle>
          </AlertDialogHeader>
          <div className="flex min-w-0 flex-col gap-3">
            <div className="flex flex-col gap-1.5">
              <Label className="text-xs">Namespace</Label>
              <NamespaceSelect value={lockNs} onChange={chooseLockNs} namespaces={lockNamespaces} />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label className="text-xs">Workload</Label>
              <Select value={lockWorkload} onValueChange={setLockWorkload} disabled={!lockNs}>
                <SelectTrigger className="h-9 w-full *:data-[slot=select-value]:block *:data-[slot=select-value]:min-w-0 *:data-[slot=select-value]:truncate">
                  <SelectValue placeholder={lockNs && lockWorkloads.length === 0 ? 'No workloads' : 'Select a workload'} />
                </SelectTrigger>
                <SelectContent className="max-w-[calc(100vw-2rem)]">
                  <SelectGroup>
                    {lockWorkloads.map(w => (
                      <SelectItem key={`${w.kind}/${w.name}`} value={`${w.kind}/${w.name}`}>
                        {w.name} <span className="text-muted-foreground">{w.kind}</span>
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
            </div>
            <div className="flex flex-col gap-1.5">
              <Label className="text-xs">Mode</Label>
              <Select value={lockMode} onValueChange={(v) => setLockMode(v as 'Monitoring' | 'Protect')}>
                <SelectTrigger className="h-9 w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectItem value="Monitoring">Monitoring</SelectItem>
                    <SelectItem value="Protect">Protect</SelectItem>
                  </SelectGroup>
                </SelectContent>
              </Select>
            </div>
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={locking}>Cancel</AlertDialogCancel>
            <Button onClick={handleLock} disabled={!lockWorkload || locking}>
              {locking ? 'Reading the image...' : 'Lock'}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Every policy back to Monitoring */}
      <AlertDialog open={modeModal} onOpenChange={setModeModal}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Set all policies to Monitoring?</AlertDialogTitle>
            <AlertDialogDescription>
              {enforcing} polic{enforcing === 1 ? 'y stops' : 'ies stop'} blocking. Violations are still recorded.
              Protect is turned back on one policy at a time.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleStopEnforcing}>Set all to Monitoring</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog
        open={!!pendingModeChange}
        onOpenChange={(open) => { if (!open) setPendingModeChange(null) }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Change Policy Mode</AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div>
                Switch <strong>{pendingModeChange?.policy.name}</strong> to{' '}
                <strong>{pendingModeChange?.mode.toUpperCase()}</strong>?
                {pendingModeChange?.mode === 'Protect' && (
                  <p className="mt-2 text-destructive">
                    ⚠ Protect mode will actively kill violating processes for this policy.
                  </p>
                )}
              </div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              variant={pendingModeChange?.mode === 'Protect' ? 'destructive' : 'default'}
              onClick={() => {
                if (pendingModeChange) {
                  handleModeChange(pendingModeChange.policy, pendingModeChange.mode)
                }
              }}
            >
              Switch to {pendingModeChange?.mode}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Delete dialog */}
      <AlertDialog
        open={!!deleteTarget}
        onOpenChange={(open) => { if (!open) setDeleteTarget(null) }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Policy</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete <strong>{deleteTarget?.name}</strong>?
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction variant="destructive" onClick={handleDelete}>
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
