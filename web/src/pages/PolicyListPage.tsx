import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
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
import type { PolicyRecord, Mode } from '../api/types'

const MODE_VARIANT: Record<string, 'destructive' | 'secondary' | 'outline'> = {
  Protect: 'destructive',
  Monitoring: 'secondary',
  Mixed: 'outline',
}

export function PolicyListPage() {
  const navigate = useNavigate()
  const toast = useToast()
  const [policies, setPolicies] = useState<PolicyRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [scopeFilter, setScopeFilter] = useState('all')
  const [deleteTarget, setDeleteTarget] = useState<PolicyRecord | null>(null)

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

  const filtered = policies.filter((p) => {
    const matchName = p.name.toLowerCase().includes(search.toLowerCase())
    const matchScope = scopeFilter === 'all' || p.scope === scopeFilter
    return matchName && matchScope
  })

  return (
    <>
      {/* Global mode control banner */}
      <div className="mb-6 flex items-center justify-between rounded-xl border bg-card px-5 py-4">
        <div className="flex items-center gap-4">
          <div>
            <p className="text-sm font-medium text-muted-foreground">Global Enforcement Mode</p>
            <div className="mt-1 flex items-center gap-2">
              <Badge
                variant={globalMode === 'Protect' ? 'destructive' : globalMode === 'Mixed' ? 'outline' : 'secondary'}
                className="text-sm px-3 py-0.5"
              >
                {globalMode.toUpperCase()}
              </Badge>
              <span className="text-sm text-muted-foreground">
                {globalMode === 'Protect'
                  ? 'Actively blocking violations on all policies'
                  : globalMode === 'Mixed'
                  ? 'Policies have mixed enforcement modes'
                  : 'Monitoring only — no blocking on all policies'}
              </span>
            </div>
          </div>
        </div>
        <Button
          variant={nextGlobalMode === 'Protect' ? 'destructive' : 'outline'}
          onClick={() => setModeModal(true)}
        >
          Switch to {nextGlobalMode}
        </Button>
      </div>

      {/* Page header */}
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h4 className="text-xl font-semibold">TracingPolicy</h4>
          <p className="text-sm text-muted-foreground">Manage Cilium tracing policies</p>
        </div>
        <Button onClick={() => navigate('/policies/tracing/new')}>+ New Policy</Button>
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
                  <TableHead>Created</TableHead>
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
                        <Select
                          value={p.mode === 'Mixed' ? 'Mixed' : p.mode}
                          onValueChange={(v) => handleModeChange(p, v as 'Monitoring' | 'Protect')}
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
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {p.namespace ?? '-'}
                      </TableCell>
                      <TableCell className="text-muted-foreground">{p.createdAt}</TableCell>
                      <TableCell className="text-right">
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
            <AlertDialogTitle>Switch Global Mode</AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div>
                Apply <strong>{nextGlobalMode.toUpperCase()}</strong> to all TracingPolicies?
                {nextGlobalMode === 'Protect' && (
                  <p className="mt-2 text-destructive">
                    ⚠ Warning: Protect mode will actively kill violating processes on all policies.
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
              Switch to {nextGlobalMode}
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
