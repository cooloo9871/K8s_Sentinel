import React, { useCallback, useEffect, useMemo, useState } from 'react'
import {
  IconAlertTriangle, IconRefresh,
} from '@tabler/icons-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
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
import { formatTWTime } from '../utils/time'
import { cnpApi, type CNPRecord } from '../api/client'
import {
  cnpFormToYaml, validateCNPForm, tryParseCNPForm, HTTP_METHODS,
  type CNPFormInput, type CNPDirection, type CNPMode,
} from '../utils/cnpForm'
import { useToast } from '../layout/AppToaster'
import { useAuth } from '../layout/AuthContext'

function DenyBadge({ deny }: { deny: CNPRecord['defaultDeny'] }) {
  if (!deny) return <span className="text-muted-foreground text-xs">—</span>
  const label = deny === 'both' ? 'Ingress + Egress' : deny === 'ingress' ? 'Ingress' : 'Egress'
  return <Badge variant="destructive" className="text-[10px]">{label}</Badge>
}

function Field({ label, required, hint, className, children }: {
  label: string
  required?: boolean
  hint?: string
  className?: string
  children: React.ReactNode
}) {
  return (
    <div className={`flex flex-col gap-1.5 ${className ?? ''}`}>
      <Label className="text-xs">
        {label}
        {required && <span className="text-destructive">*</span>}
      </Label>
      {children}
      {hint && <p className="text-[11px] text-muted-foreground">{hint}</p>}
    </div>
  )
}

const EMPTY_FORM: CNPFormInput = {
  name: '', namespace: '', comment: '', from: '', to: '',
  direction: 'ingress', ports: '', mode: 'whitelist', httpMethod: '', httpPath: '',
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
  // Create flow only: build a simple rule in the form, or write YAML directly.
  const [mode, setMode] = useState<'form' | 'yaml'>('form')
  const [form, setForm] = useState<CNPFormInput>(EMPTY_FORM)
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

  const formErrors = useMemo(() => validateCNPForm(form), [form])
  const formYaml = useMemo(() => cnpFormToYaml(form), [form])
  const setField = <K extends keyof CNPFormInput>(key: K, value: CNPFormInput[K]) =>
    setForm(prev => ({ ...prev, [key]: value }))

  const openCreate = (as: 'form' | 'yaml') => {
    setEditing(null)
    setMode(as)
    setForm(EMPTY_FORM)
    setYamlText('')
    setYamlValid(true)
    setEditorOpen(true)
  }

  // A policy this form generated reopens in the form; anything else opens in the
  // YAML editor, because arbitrary rules can hold what these fields cannot show
  // and saving would silently drop the rest.
  const openEdit = (p: CNPRecord) => {
    setEditing(p)
    const parsed = tryParseCNPForm(p.rawYaml)
    if (parsed) {
      setForm(parsed)
      setMode('form')
    } else {
      setForm(EMPTY_FORM)
      setMode('yaml')
    }
    setYamlText(p.rawYaml)
    setYamlValid(true)
    setEditorOpen(true)
  }

  const usingForm = mode === 'form'
  const outgoingYaml = usingForm ? formYaml : yamlText
  const canApply = usingForm
    ? formErrors.length === 0 && !!formYaml
    : !!yamlText.trim() && yamlValid

  const save = async () => {
    if (!canApply) return
    setSaving(true)
    try {
      await cnpApi.apply(outgoingYaml)
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
            {(editing || !usingForm) && (
              <p className="text-sm text-muted-foreground">
                {editing
                  ? `${editing.scope === 'cluster' ? 'Cluster-wide' : editing.namespace} · applied on save`
                  : 'Scope is determined by the manifest kind — CiliumNetworkPolicy is namespaced, CiliumClusterwideNetworkPolicy is not.'}
              </p>
            )}
          </div>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => setEditorOpen(false)}>Cancel</Button>
            <Button size="sm" onClick={save} disabled={saving || !canApply}>
              {saving ? 'Applying...' : 'Apply'}
            </Button>
          </div>
        </div>

        {usingForm ? (
          <div className="grid grid-cols-2 gap-6">
            {/* Left: form */}
            <Card>
              <CardContent className="flex flex-col gap-5 p-6">
                <div className="grid grid-cols-2 gap-4">
                  <Field label="Name" required>
                    <Input value={form.name} onChange={e => setField('name', e.target.value)}
                      readOnly={!!editing}
                      className={`h-9 ${editing ? 'cursor-default opacity-60' : ''}`} />
                  </Field>
                  <Field label="Namespace" required>
                    <Input value={form.namespace} onChange={e => setField('namespace', e.target.value)}
                      readOnly={!!editing}
                      className={`h-9 ${editing ? 'cursor-default opacity-60' : ''}`} />
                  </Field>
                </div>

                <Field label="Comment">
                  <Input value={form.comment} onChange={e => setField('comment', e.target.value)} className="h-9" />
                </Field>

                <div className="grid grid-cols-2 gap-4">
                  <Field label="From" required hint="key=value, or world / cluster / host">
                    <Input value={form.from} onChange={e => setField('from', e.target.value)} className="h-9 font-mono text-sm" />
                  </Field>
                  <Field label="To" required hint="ns=other-namespace also works">
                    <Input value={form.to} onChange={e => setField('to', e.target.value)} className="h-9 font-mono text-sm" />
                  </Field>
                </div>

                <Field
                  label="Enforce on"
                  hint={form.direction === 'ingress'
                    ? 'The policy is attached to To — nothing else reaching it is affected.'
                    : 'The policy is attached to From — other sources can still reach To.'}
                >
                  <Select value={form.direction}
                    onValueChange={v => setField('direction', v as CNPDirection)}>
                    <SelectTrigger className="h-9 w-full"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        <SelectItem value="ingress">Ingress on To</SelectItem>
                        <SelectItem value="egress">Egress from From</SelectItem>
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                </Field>

                <Field label="Ports" hint="Blank means every port">
                  <Input value={form.ports} onChange={e => setField('ports', e.target.value)} className="h-9 font-mono text-sm" />
                </Field>

                {/* Not an Allow/Deny action: the two options write different
                    policy models, and "Allow" would hide that it also drops
                    everything it does not name. */}
                <Field
                  label="Mode"
                  hint={form.mode === 'blacklist'
                    ? 'Blacklist: only this traffic is blocked. Everything else is allowed.'
                    : 'Whitelist: only this traffic is allowed. Everything else reaching the endpoint is blocked.'}
                >
                  <Select value={form.mode} onValueChange={v => setField('mode', v as CNPMode)}>
                    <SelectTrigger className="h-9 w-full"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        <SelectItem value="blacklist">Blacklist — deny this traffic</SelectItem>
                        <SelectItem value="whitelist">Whitelist — allow only this traffic</SelectItem>
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                </Field>

                {/* Cilium deny rules match on L3/L4 only, so this is unusable
                    with Deny and there is no point rendering it enabled. */}
                <div className="flex flex-col gap-3 border-t pt-4">
                  <div className="flex items-center gap-2">
                    <Label className="text-xs">HTTP rule</Label>
                    <span className="text-xs text-muted-foreground">
                      {form.mode === 'blacklist'
                        ? 'Whitelist only — Cilium deny rules are L3/L4'
                        : 'Optional, needs a port and the Cilium proxy'}
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <Select value={form.httpMethod || 'any'}
                      onValueChange={v => setField('httpMethod', v === 'any' ? '' : v)}
                      disabled={form.mode === 'blacklist'}>
                      <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectGroup>
                          <SelectItem value="any">Any method</SelectItem>
                          {HTTP_METHODS.map(m => <SelectItem key={m} value={m}>{m}</SelectItem>)}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                    <Input value={form.httpPath} onChange={e => setField('httpPath', e.target.value)} disabled={form.mode === 'blacklist'}
                      className="h-9 font-mono text-sm" />
                  </div>
                </div>

                {formErrors.length > 0 && (
                  <ul className="flex flex-col gap-1 border-t pt-4">
                    {formErrors.map(err => (
                      <li key={err} className="flex items-start gap-1.5 text-xs text-destructive">
                        <IconAlertTriangle size={13} className="mt-0.5 shrink-0" />
                        {err}
                      </li>
                    ))}
                  </ul>
                )}
              </CardContent>
            </Card>

            {/* Right: YAML preview */}
            <Card className="overflow-hidden">
              <div className="flex items-center justify-between border-b px-4 py-3">
                <span className="text-sm font-medium">Generated YAML</span>
                <Badge variant="secondary" className="font-mono text-[10px]">CiliumNetworkPolicy</Badge>
              </div>
              <CardContent className="p-0">
                <pre className="min-h-[420px] overflow-auto rounded-b-lg bg-[#1e1e1e] p-4 font-mono text-xs leading-relaxed text-[#d4d4d4]">
                  {formYaml}
                </pre>
              </CardContent>
            </Card>
          </div>
        ) : (
          <YamlEditor
            key={editing?.name ?? 'new'}
            initialValue={yamlText}
            onValueChange={(v, valid) => { setYamlText(v); setYamlValid(valid) }}
          />
        )}
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
      </div>

      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Input
            placeholder="Search by name..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="h-8 w-56 text-sm"
          />
          <Select value={scopeFilter} onValueChange={setScopeFilter}>
            <SelectTrigger className="h-8 w-40 text-sm">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="all">All scopes</SelectItem>
                <SelectItem value="namespace">Namespaced</SelectItem>
                <SelectItem value="cluster">Cluster-wide</SelectItem>
                </SelectGroup>
            </SelectContent>
          </Select>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            <IconRefresh size={14} className="mr-1.5" />
            Refresh
          </Button>
          {isAdmin && (
            <>
              <Button size="sm" onClick={() => openCreate('form')}>+ New Policy</Button>
              <Button size="sm" variant="outline" onClick={() => openCreate('yaml')}>+ New YAML</Button>
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
                  <TableHead>Applies to</TableHead>
                  <TableHead className="w-24">Rules</TableHead>
                  <TableHead className="w-32">Default Deny</TableHead>
                  <TableHead>Created By</TableHead>
                  <TableHead>Created Time</TableHead>
                  {isAdmin && <TableHead className="text-right">Actions</TableHead>}
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={isAdmin ? 8 : 7} className="py-10 text-center text-muted-foreground">
                      No policies found
                    </TableCell>
                  </TableRow>
                ) : filtered.map(p => (
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
                    <TableCell className="text-muted-foreground">{formatTWTime(p.createdAt)}</TableCell>
                    {isAdmin && (
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-2">
                          <Button variant="outline" size="sm" onClick={() => openEdit(p)}>Edit</Button>
                          <Button variant="destructive" size="sm" onClick={() => setDeleteTarget(p)}>Delete</Button>
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
