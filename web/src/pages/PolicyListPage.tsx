import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { policyApi } from '../api/client'
import { useToast } from '../layout/AppToaster'
import type { PolicyRecord } from '../api/types'

export function PolicyListPage() {
  const navigate = useNavigate()
  const toast = useToast()
  const [policies, setPolicies] = useState<PolicyRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [scopeFilter, setScopeFilter] = useState('all')
  const [deleteTarget, setDeleteTarget] = useState<PolicyRecord | null>(null)

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

  useEffect(() => { fetchPolicies() }, [])

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

  const filtered = policies.filter((p) => {
    const matchName = p.name.toLowerCase().includes(search.toLowerCase())
    const matchScope = scopeFilter === 'all' || p.scope === scopeFilter
    return matchName && matchScope
  })

  return (
    <>
      {/* Page header */}
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h4 className="text-lg font-semibold">TracingPolicy</h4>
          <p className="text-sm text-muted-foreground">Cilium 追蹤策略管理</p>
        </div>
        <Button onClick={() => navigate('/policies/tracing/new')}>
          + New Policy
        </Button>
      </div>

      <Card>
        <CardContent className="p-0">
          {/* Toolbar */}
          <div className="flex items-center gap-2 border-b px-4 py-3">
            <Input
              placeholder="搜尋 Policy 名稱…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-52"
            />
            <Select value={scopeFilter} onValueChange={setScopeFilter}>
              <SelectTrigger className="w-36">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value="all">所有 Scope</SelectItem>
                  <SelectItem value="namespaced">namespace</SelectItem>
                  <SelectItem value="cluster">cluster</SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>
            <span className="ml-auto text-sm text-muted-foreground">
              共 {filtered.length} 筆
            </span>
          </div>

          {/* Table */}
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
                  <TableHead>Namespace</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.length === 0 ? (
                  <TableRow>
                    <TableCell
                      colSpan={5}
                      className="py-8 text-center text-muted-foreground"
                    >
                      No policies found
                    </TableCell>
                  </TableRow>
                ) : (
                  filtered.map((p) => (
                    <TableRow key={`${p.scope}-${p.namespace ?? ''}-${p.name}`}>
                      <TableCell
                        className="cursor-pointer font-medium text-primary"
                        onClick={() =>
                          navigate(
                            `/policies/tracing/${p.name}/edit?namespace=${p.namespace ?? ''}`
                          )
                        }
                      >
                        {p.name}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={p.scope === 'cluster' ? 'destructive' : 'secondary'}
                        >
                          {p.scope}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {p.namespace ?? '—'}
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {p.createdAt}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() =>
                              navigate(
                                `/policies/tracing/${p.name}/edit?namespace=${p.namespace ?? ''}`
                              )
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

      {/* Delete confirmation */}
      <AlertDialog
        open={!!deleteTarget}
        onOpenChange={(open) => { if (!open) setDeleteTarget(null) }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>刪除 Policy</AlertDialogTitle>
            <AlertDialogDescription>
              確定要刪除 <strong>{deleteTarget?.name}</strong> 嗎？此操作無法復原。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>取消</AlertDialogCancel>
            <AlertDialogAction variant="destructive" onClick={handleDelete}>
              確認刪除
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
