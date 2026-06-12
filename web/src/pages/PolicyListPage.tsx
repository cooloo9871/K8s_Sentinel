import { useEffect, useState } from 'react'
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
import { policyApi, modeApi } from '../api/client'
import { useToast } from '../layout/AppToaster'
import { useAuth } from '../layout/AuthContext'
import type { PolicyRecord, Mode } from '../api/types'

const MODE_VARIANT: Record<string, 'destructive' | 'secondary' | 'outline'> = {
  Protect: 'destructive',
  Monitoring: 'secondary',
  Mixed: 'outline',
}

export function PolicyListPage() {
  const navigate = useNavigate()
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const toast = useToast()
  const [policies, setPolicies] = useState<PolicyRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [scopeFilter, setScopeFilter] = useState('all')
  const [nsFilter, setNsFilter] = useState('all')
  const [deleteTarget, setDeleteTarget] = useState<PolicyRecord | null>(null)
  const [pendingModeChange, setPendingModeChange] = useState<{
    policy: PolicyRecord
    mode: 'Monitoring' | 'Protect'
  } | null>(null)

  // Global mode state
  const [globalMode, setGlobalMode] = useState<Mode>('Monitoring')
  const [modeModal, setModeModal] = useState(false)
  const nextGlobalMode: 'Monitoring' | 'Protect' =
    globalMode === 'Protect' ? 'Monitoring' : 'Protect'

  const fetchPolicies = async () => {
    setLoading(true)
    try {
      setPolicies(await policyApi.list())
    } catch {
      toast.error('Failed to load policies')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchPolicies()
    modeApi.get().then(setGlobalMode).catch(() => {})
  }, [])

  const handleGlobalModeSwitch = async () => {
    try {
      await modeApi.set(nextGlobalMode)
      setGlobalMode(nextGlobalMode)
      toast.success(`Global mode switched to ${nextGlobalMode}`)
      fetchPolicies() // refresh per-policy modes
    } catch {
      toast.error('Failed to switch global mode')
    }
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
    } catch {
      toast.error(`Failed to update mode for ${p.name}`)
      fetchPolicies()
    }
  }

  const namespaces = [...new Set(policies.map(p => p.namespace).filter(Boolean))].sort() as string[]

  const filtered = policies.filter((p) => {
    const matchName = p.name.toLowerCase().includes(search.toLowerCase())
    const matchScope = scopeFilter === 'all' || p.scope === scopeFilter
    const matchNs = nsFilter === 'all' || (p.namespace ?? '') === nsFilter
    return matchName && matchScope && matchNs
  })

  return (
    <>
      {/* Global Protect Mode banner */}
      <div className="mb-6 flex items-center justify-between rounded-xl border bg-card px-5 py-4">
        <div className="flex items-center gap-4">
          <div>
            <p className="text-sm font-medium text-muted-foreground">Global Protect Mode</p>
            <p className="text-xs text-muted-foreground/70">Turn on to enforce all policies; turn off to monitor only</p>
            <div className="mt-1 flex items-center gap-2">
              <Badge
                variant={globalMode === 'Protect' ? 'destructive' : globalMode === 'Mixed' ? 'outline' : 'secondary'}
                className="text-sm px-3 py-0.5"
              >
                {globalMode === 'Protect' ? 'ON' : globalMode === 'Mixed' ? 'MIXED' : 'OFF'}
              </Badge>
              <span className="text-sm text-muted-foreground">
                {globalMode === 'Protect'
                  ? 'Protect mode is on — actively blocking violations on all policies'
                  : globalMode === 'Mixed'
                  ? 'Policies have mixed modes'
                  : 'Protect mode is off — monitoring only, no blocking'}
              </span>
            </div>
          </div>
        </div>
        {isAdmin && (
          <Button
            variant={nextGlobalMode === 'Protect' ? 'destructive' : 'outline'}
            onClick={() => setModeModal(true)}
          >
            {nextGlobalMode === 'Protect' ? 'Turn On' : 'Turn Off'}
          </Button>
        )}
      </div>

      {/* Page header */}
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h4 className="text-xl font-semibold">TracingPolicy</h4>
          <p className="text-sm text-muted-foreground">Manage Cilium tracing policies</p>
        </div>
        {isAdmin && <Button onClick={() => navigate('/policies/tracing/new')}>+ New Policy</Button>}
      </div>

      <Card>
        <CardContent className="p-0">
          <div className="flex items-center gap-2 border-b px-4 py-3">
            <Input
              placeholder="Search policy name..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-56"
            />
            <Select value={scopeFilter} onValueChange={setScopeFilter}>
              <SelectTrigger className="w-36">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value="all">All Scopes</SelectItem>
                  <SelectItem value="namespaced">namespace</SelectItem>
                  <SelectItem value="cluster">cluster</SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>
            <Select value={nsFilter} onValueChange={setNsFilter}>
              <SelectTrigger className="w-40">
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
            <span className="ml-auto text-sm text-muted-foreground">
              {filtered.length} result{filtered.length !== 1 ? 's' : ''}
            </span>
          </div>

          {loading ? (
            <div className="flex flex-col gap-2 p-4">
              {Array.from({ length: 5 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full rounded-lg" />
              ))}
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
                      <TableCell className="font-medium">{p.name}</TableCell>
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
                              Edit
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

      {/* Global mode switch dialog */}
      <AlertDialog open={modeModal} onOpenChange={setModeModal}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {nextGlobalMode === 'Protect' ? 'Turn On Global Protect Mode' : 'Turn Off Global Protect Mode'}
            </AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div>
                {nextGlobalMode === 'Protect'
                  ? 'Apply Protect mode to all TracingPolicies? Violations will be actively blocked (Sigkill).'
                  : 'Apply Monitoring mode to all TracingPolicies? Violations will be logged but not blocked.'}
                {nextGlobalMode === 'Protect' && (
                  <p className="mt-2 text-destructive">
                    ⚠ Warning: This will actively kill violating processes on all policies.
                  </p>
                )}
              </div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              variant={nextGlobalMode === 'Protect' ? 'destructive' : 'default'}
              onClick={handleGlobalModeSwitch}
            >
              {nextGlobalMode === 'Protect' ? 'Turn On' : 'Turn Off'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Per-policy mode change confirmation */}
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
              This action cannot be undone.
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
