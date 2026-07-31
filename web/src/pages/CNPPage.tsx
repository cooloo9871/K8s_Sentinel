import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  IconAlertTriangle, IconNetwork, IconPlus, IconRefresh, IconSearch, IconTrash, IconPencil,
} from '@tabler/icons-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { YamlEditor } from '../components/YamlEditor'
import { RelativeTime } from '../components/RelativeTime'
import { cnpApi, type CNPRecord } from '../api/client'
import { cnpTemplates, type CNPTemplate } from '../data/cnpTemplates'
import { useToast } from '../layout/AppToaster'
import { useAuth } from '../layout/AuthContext'

function DenyBadge({ deny }: { deny: CNPRecord['defaultDeny'] }) {
  if (!deny) return <span className="text-muted-foreground text-xs">—</span>
  const label = deny === 'both' ? 'Ingress + Egress' : deny === 'ingress' ? 'Ingress' : 'Egress'
  return <Badge variant="destructive" className="text-[10px]">{label}</Badge>
}

export function CNPPage() {
  const toast = useToast()
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'

  const [policies, setPolicies] = useState<CNPRecord[]>([])
  const [available, setAvailable] = useState<boolean | null>(null)
  const [unavailableMsg, setUnavailableMsg] = useState('')
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [scopeFilter, setScopeFilter] = useState('all')

  // Editor state — open for create (editing=null) or edit (editing=record)
  const [editorOpen, setEditorOpen] = useState(false)
  const [editing, setEditing] = useState<CNPRecord | null>(null)
  const [yamlText, setYamlText] = useState('')
  const [yamlValid, setYamlValid] = useState(true)
  const [templateId, setTemplateId] = useState('')
  const [saving, setSaving] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<CNPRecord | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await cnpApi.list()
      setAvailable(res.available)
      setUnavailableMsg(res.message ?? '')
      setPolicies(res.policies ?? [])
    } catch {
      setAvailable(false)
      setUnavailableMsg('Failed to reach the Sentinel API.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const selectedTemplate: CNPTemplate | undefined = useMemo(
    () => cnpTemplates.find(t => t.id === templateId), [templateId]
  )

  const openCreate = () => {
    setEditing(null)
    setTemplateId('')
    setYamlText('')
    setYamlValid(true)
    setEditorOpen(true)
  }

  const openEdit = (p: CNPRecord) => {
    setEditing(p)
    setTemplateId('')
    setYamlText(p.rawYaml)
    setYamlValid(true)
    setEditorOpen(true)
  }

  const applyTemplate = (id: string) => {
    setTemplateId(id)
    const t = cnpTemplates.find(x => x.id === id)
    if (t) {
      setYamlText(t.yaml)
      setYamlValid(true)
    }
  }

  const save = async () => {
    if (!yamlText.trim() || !yamlValid) return
    setSaving(true)
    try {
      await cnpApi.apply(yamlText)
      toast.success(editing ? 'Network policy updated.' : 'Network policy created.')
      setEditorOpen(false)
      load()
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { error?: string } } })?.response?.data?.error
      toast.error(msg || 'Failed to apply network policy.')
    } finally {
      setSaving(false)
    }
  }

  const confirmDelete = async () => {
    if (!deleteTarget) return
    try {
      await cnpApi.delete(deleteTarget.name, deleteTarget.scope, deleteTarget.namespace)
      toast.success(`Deleted ${deleteTarget.name}.`)
      load()
    } catch {
      toast.error('Failed to delete network policy.')
    } finally {
      setDeleteTarget(null)
    }
  }

  const filtered = policies.filter(p => {
    if (scopeFilter !== 'all' && p.scope !== scopeFilter) return false
    if (search) {
      const q = search.toLowerCase()
      if (!p.name.toLowerCase().includes(q) &&
          !p.namespace.toLowerCase().includes(q) &&
          !p.selector.toLowerCase().includes(q)) return false
    }
    return true
  })

  // ── Cilium CRDs missing ──────────────────────────────────────────────────
  if (available === false && !editorOpen) {
    return (
      <>
        <div className="mb-6">
          <h4 className="text-xl font-semibold">Network Policy</h4>
          <p className="text-sm text-muted-foreground">Cilium network policies — identity-based network access control.</p>
        </div>
        <Card className="border-amber-500/30 bg-amber-500/5">
          <CardContent className="flex items-start gap-3 p-5">
            <IconAlertTriangle size={20} className="mt-0.5 shrink-0 text-amber-600" />
            <div className="flex flex-col gap-1.5">
              <p className="text-sm font-medium text-amber-700">Cilium network policy CRDs not available</p>
              <p className="text-xs text-amber-600">
                This page manages <code className="font-mono">CiliumNetworkPolicy</code> and{' '}
                <code className="font-mono">CiliumClusterwideNetworkPolicy</code>, which require Cilium as the cluster CNI.
              </p>
              {unavailableMsg && (
                <p className="mt-1 font-mono text-[11px] text-amber-600/80">{unavailableMsg}</p>
              )}
              <p className="mt-1 text-xs text-amber-600">
                On a Cilium cluster, also confirm K8s Sentinel&apos;s RBAC grants access to{' '}
                <code className="font-mono">ciliumnetworkpolicies</code>.
              </p>
            </div>
          </CardContent>
        </Card>
      </>
    )
  }

  // ── Editor view ──────────────────────────────────────────────────────────
  if (editorOpen) {
    return (
      <>
        <div className="mb-4 flex items-start justify-between">
          <div>
            <h4 className="text-xl font-semibold">
              {editing ? `Edit ${editing.name}` : 'New Network Policy'}
            </h4>
            <p className="text-sm text-muted-foreground">
              {editing
                ? `${editing.scope === 'cluster' ? 'Cluster-wide' : editing.namespace} · applied on save`
                : 'Scope is determined by the manifest kind — CiliumNetworkPolicy is namespaced, CiliumClusterwideNetworkPolicy is not.'}
            </p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => setEditorOpen(false)}>Cancel</Button>
            <Button size="sm" onClick={save} disabled={saving || !yamlValid || !yamlText.trim()}>
              {saving ? 'Applying...' : 'Apply'}
            </Button>
          </div>
        </div>

        {!editing && (
          <div className="mb-4 flex flex-col gap-2">
            <div className="flex items-center gap-2">
              <Label className="text-xs">Start from a template</Label>
              <Select value={templateId} onValueChange={applyTemplate}>
                <SelectTrigger className="h-8 w-72 text-sm">
                  <SelectValue placeholder="Blank — write your own" />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    {cnpTemplates.map(t => (
                      <SelectItem key={t.id} value={t.id}>{t.name}</SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
            </div>
            {selectedTemplate && (
              <Card className="border-muted">
                <CardContent className="flex flex-col gap-1.5 p-3">
                  <p className="text-xs text-muted-foreground">{selectedTemplate.description}</p>
                  {selectedTemplate.caution && (
                    <p className="flex items-start gap-1.5 text-xs font-medium text-amber-700">
                      <IconAlertTriangle size={13} className="mt-0.5 shrink-0" />
                      {selectedTemplate.caution}
                    </p>
                  )}
                </CardContent>
              </Card>
            )}
          </div>
        )}

        <YamlEditor
          initialValue={yamlText}
          onValueChange={(v, valid) => { setYamlText(v); setYamlValid(valid) }}
        />
      </>
    )
  }

  // ── List view ────────────────────────────────────────────────────────────
  return (
    <>
      <div className="mb-4 flex items-start justify-between">
        <div>
          <h4 className="text-xl font-semibold">Network Policy</h4>
          <p className="text-sm text-muted-foreground">Cilium network policies — identity-based network access control.</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            <IconRefresh size={14} className="mr-1.5" />
            Refresh
          </Button>
          {isAdmin && (
            <Button size="sm" onClick={openCreate}>
              <IconPlus size={14} className="mr-1.5" />
              New Policy
            </Button>
          )}
        </div>
      </div>

      <div className="mb-4 flex items-center gap-2">
        <div className="relative">
          <IconSearch size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Name / namespace / selector..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="h-8 w-56 pl-8 text-sm"
          />
        </div>
        <Select value={scopeFilter} onValueChange={setScopeFilter}>
          <SelectTrigger className="h-8 w-40 text-sm">
            <SelectValue placeholder="All scopes" />
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              <SelectItem value="all">All scopes</SelectItem>
              <SelectItem value="namespace">Namespaced</SelectItem>
              <SelectItem value="cluster">Cluster-wide</SelectItem>
            </SelectGroup>
          </SelectContent>
        </Select>
        <span className="ml-auto text-xs text-muted-foreground">
          {filtered.length} polic{filtered.length !== 1 ? 'ies' : 'y'}
        </span>
      </div>

      <Card>
        <CardHeader className="border-b pb-3">
          <CardTitle className="text-sm font-medium">Policies</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="py-16 text-center text-sm text-muted-foreground">Loading...</div>
          ) : filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center gap-3 py-16 text-muted-foreground">
              <IconNetwork size={36} strokeWidth={1.5} />
              <p className="text-sm">
                {policies.length === 0 ? 'No Cilium network policies yet' : 'No policies match the filter'}
              </p>
              {policies.length === 0 && isAdmin && (
                <Button size="sm" onClick={openCreate}>Create your first policy</Button>
              )}
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Scope</TableHead>
                  <TableHead>Applies to</TableHead>
                  <TableHead className="w-24">Rules</TableHead>
                  <TableHead className="w-32">Default Deny</TableHead>
                  <TableHead>Created By</TableHead>
                  <TableHead className="w-24">Created</TableHead>
                  {isAdmin && <TableHead className="w-20"></TableHead>}
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map(p => (
                  <TableRow key={`${p.scope}-${p.namespace}-${p.name}`}>
                    <TableCell className="font-medium">
                      {p.name}
                      {p.hasL7 && (
                        <span className="ml-1.5 rounded bg-blue-500/10 px-1 py-0.5 text-[9px] font-medium text-blue-700">L7</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge variant={p.scope === 'cluster' ? 'destructive' : 'secondary'} className="text-[10px]">
                        {p.scope === 'cluster' ? 'cluster-wide' : p.namespace}
                      </Badge>
                    </TableCell>
                    <TableCell className="max-w-[220px] truncate font-mono text-xs text-muted-foreground" title={p.selector}>
                      {p.selector}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {p.ingressRules > 0 && <span>in {p.ingressRules}</span>}
                      {p.ingressRules > 0 && p.egressRules > 0 && <span> · </span>}
                      {p.egressRules > 0 && <span>out {p.egressRules}</span>}
                      {p.ingressRules === 0 && p.egressRules === 0 && <span>—</span>}
                    </TableCell>
                    <TableCell><DenyBadge deny={p.defaultDeny} /></TableCell>
                    <TableCell className="text-xs text-muted-foreground">{p.createdBy}</TableCell>
                    <TableCell className="text-muted-foreground"><RelativeTime iso={p.createdAt} /></TableCell>
                    {isAdmin && (
                      <TableCell>
                        <div className="flex gap-1">
                          <Button variant="ghost" size="icon" className="size-7" onClick={() => openEdit(p)}>
                            <IconPencil size={14} />
                          </Button>
                          <Button variant="ghost" size="icon" className="size-7 text-destructive"
                            onClick={() => setDeleteTarget(p)}>
                            <IconTrash size={14} />
                          </Button>
                        </div>
                      </TableCell>
                    )}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <AlertDialog open={!!deleteTarget} onOpenChange={open => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete network policy?</AlertDialogTitle>
            <AlertDialogDescription>
              <span className="font-mono">{deleteTarget?.name}</span>
              {deleteTarget?.scope === 'cluster' ? ' (cluster-wide)' : ` in ${deleteTarget?.namespace}`} will be removed.
              {deleteTarget?.defaultDeny
                ? ' Traffic it was restricting becomes allowed again.'
                : ''}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={confirmDelete}>Delete</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
