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
import { ScopeFilter, matchesScopeFilter } from '../components/ScopeFilter'
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
import { cnpApi, namespaceApi, type CNPRecord } from '../api/client'
import { NamespaceSelect } from '../components/NamespaceSelect'
import {
  cnpFormToYaml, validateCNPForm, tryParseCNPForm, peerLabel,
  emptyForm, emptyRule, emptyLabel, emptyPort, emptyHttp,
  HTTP_METHODS, PROTOCOLS, ENTITIES,
  type CNPFormInput, type CNPRule, type CNPDirection, type CNPMode, type CNPScope,
  type PeerKind, type LabelPair,
} from '../utils/cnpForm'
import { useToast } from '../layout/AppToaster'
import { useAuth } from '../layout/AuthContext'

function DenyBadge({ deny }: { deny: CNPRecord['defaultDeny'] }) {
  if (!deny) return <span className="text-muted-foreground text-xs">—</span>
  const label = deny === 'both' ? 'Ingress + Egress' : deny === 'ingress' ? 'Ingress' : 'Egress'
  return <Badge variant="destructive" className="text-[10px]">{label}</Badge>
}

function LabelRows({ title, required, hint, pairs, onChange }: {
  title: string
  required?: boolean
  hint?: string
  pairs: LabelPair[]
  onChange: (pairs: LabelPair[]) => void
}) {
  const set = (i: number, key: keyof LabelPair, value: string) =>
    onChange(pairs.map((p, pi) => (pi === i ? { ...p, [key]: value } : p)))

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <Label className="text-xs">
          {title}
          {required && <span className="text-destructive">*</span>}
        </Label>
        <Button variant="outline" size="sm" className="h-7 text-xs"
          onClick={() => onChange([...pairs, emptyLabel()])}>
          + Add label
        </Button>
      </div>
      {pairs.map((p, i) => (
        <div key={i} className="flex items-end gap-2">
          <div className="flex flex-1 flex-col gap-1">
            <span className="text-[11px] text-muted-foreground">Key</span>
            <Input value={p.key} onChange={e => set(i, 'key', e.target.value)}
              className="h-8 font-mono text-sm" />
          </div>
          <div className="flex flex-1 flex-col gap-1">
            <span className="text-[11px] text-muted-foreground">Value</span>
            <Input value={p.value} onChange={e => set(i, 'value', e.target.value)}
              className="h-8 font-mono text-sm" />
          </div>
          {pairs.length > 1 && (
            <Button variant="ghost" size="sm" className="h-8 px-2 text-xs text-destructive hover:text-destructive"
              onClick={() => onChange(pairs.filter((_, pi) => pi !== i))}>
              Remove
            </Button>
          )}
        </div>
      ))}
      {hint && <p className="text-[11px] text-muted-foreground">{hint}</p>}
    </div>
  )
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

export function CNPPage() {
  const toast = useToast()
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'

  const [policies, setPolicies] = useState<CNPRecord[]>([])
  const [available, setAvailable] = useState<boolean | null>(null)
  const [unavailableMsg, setUnavailableMsg] = useState('')
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [nsFilter, setNsFilter] = useState<string[]>([])
  // Every namespace in the cluster, for the form. The filter's list comes from
  // the loaded policies instead, since filtering to an empty one is a dead end —
  // but creating a policy in a namespace that has none yet is the normal case.
  const [clusterNamespaces, setClusterNamespaces] = useState<string[]>([])

  // Editor state — open for create (editing=null) or edit (editing=record)
  const [editorOpen, setEditorOpen] = useState(false)
  const [editing, setEditing] = useState<CNPRecord | null>(null)
  const [yamlText, setYamlText] = useState('')
  const [yamlValid, setYamlValid] = useState(true)
  // Create flow only: build a simple rule in the form, or write YAML directly.
  const [mode, setMode] = useState<'form' | 'yaml'>('form')
  const [form, setForm] = useState<CNPFormInput>(emptyForm)
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
  useEffect(() => { namespaceApi.list().then(setClusterNamespaces).catch(() => {}) }, [])

  const formErrors = useMemo(() => validateCNPForm(form), [form])
  const formYaml = useMemo(() => cnpFormToYaml(form), [form])
  const setField = <K extends keyof CNPFormInput>(key: K, value: CNPFormInput[K]) =>
    setForm(prev => ({ ...prev, [key]: value }))

  const setRule = <K extends keyof CNPRule>(index: number, key: K, value: CNPRule[K]) =>
    setForm(prev => ({
      ...prev,
      rules: prev.rules.map((r, i) => (i === index ? { ...r, [key]: value } : r)),
    }))

  // Takes an updater rather than a value: computing the next array from the `r`
  // captured at render means two edits landing in one batch would each start
  // from the same stale snapshot, and the later one would drop the earlier.
  const updateRule = (index: number, next: (r: CNPRule) => CNPRule) =>
    setForm(prev => ({
      ...prev,
      rules: prev.rules.map((r, i) => (i === index ? next(r) : r)),
    }))

  const addRule = () => setForm(prev => ({ ...prev, rules: [...prev.rules, emptyRule()] }))
  const removeRule = (index: number) =>
    setForm(prev => ({ ...prev, rules: prev.rules.filter((_, i) => i !== index) }))

  const openCreate = (as: 'form' | 'yaml') => {
    setEditing(null)
    setMode(as)
    setForm(emptyForm())
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
      setForm(emptyForm())
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

  // Offer only namespaces that actually hold a policy — an empty option is a
  // dead end.
  const namespaces = [...new Set(policies.map(p => p.namespace).filter(Boolean))].sort()

  const filtered = policies.filter(p => {
    if (!matchesScopeFilter(p.scope, p.namespace, nsFilter)) return false
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
          <p className="text-sm text-muted-foreground">Manage Cilium Network Policy.</p>
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
                  <Field
                    label="Scope"
                    hint={form.scope === 'cluster'
                      ? 'The selector can reach pods in any namespace.'
                      : 'The selector only matches pods in this namespace.'}
                  >
                    <Select value={form.scope} onValueChange={v => setField('scope', v as CNPScope)}
                      disabled={!!editing}>
                      <SelectTrigger className="h-9 w-full"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectGroup>
                          <SelectItem value="namespaced">Namespaced</SelectItem>
                          <SelectItem value="cluster">Cluster-wide</SelectItem>
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  </Field>
                </div>

                {form.scope === 'namespaced' && (
                  <Field label="Namespace" required>
                    <NamespaceSelect
                      value={form.namespace}
                      onChange={v => setField('namespace', v)}
                      namespaces={clusterNamespaces}
                      disabled={!!editing}
                    />
                  </Field>
                )}

                <Field label="Comment">
                  <Input value={form.comment} onChange={e => setField('comment', e.target.value)} className="h-9" />
                </Field>

                {/* A Cilium policy has one endpointSelector, so the subject is
                    set once here and every rule below shares it. */}
                <LabelRows
                  title="Applies to"
                  required
                  hint={form.scope === 'cluster'
                    ? 'The endpoints this policy governs. Add namespace to reach another one.'
                    : 'The endpoints this policy governs, within this namespace.'}
                  pairs={form.subject}
                  onChange={pairs => setField('subject', pairs)}
                />

                <div className="grid grid-cols-2 gap-4">
                  <Field
                    label="Direction"
                    hint={form.direction === 'ingress'
                      ? 'Rules name who may reach it.'
                      : 'Rules name what it may reach.'}
                  >
                    <Select value={form.direction} onValueChange={v => setField('direction', v as CNPDirection)}>
                      <SelectTrigger className="h-9 w-full"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectGroup>
                          <SelectItem value="ingress">Ingress</SelectItem>
                          <SelectItem value="egress">Egress</SelectItem>
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  </Field>
                  <Field
                    label="Mode"
                    hint={form.mode === 'blacklist'
                      ? 'Only this traffic is blocked.'
                      : 'Only this traffic is allowed.'}
                  >
                    <Select value={form.mode} onValueChange={v => setField('mode', v as CNPMode)}>
                      <SelectTrigger className="h-9 w-full"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectGroup>
                          <SelectItem value="blacklist">Blacklist — deny</SelectItem>
                          <SelectItem value="whitelist">Whitelist — allow only</SelectItem>
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  </Field>
                </div>

                <div className="flex flex-col gap-3 border-t pt-4">
                  <div className="flex items-center justify-between">
                    <Label className="text-xs">Rules</Label>
                    <Button variant="outline" size="sm" onClick={addRule}>+ Add rule</Button>
                  </div>

                  {form.rules.map((r, i) => (
                    <div key={i} className="flex flex-col gap-3 rounded-md border p-3">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-medium text-muted-foreground">Rule {i + 1}</span>
                        {form.rules.length > 1 && (
                          <Button variant="ghost" size="sm" className="h-6 px-2 text-xs text-destructive hover:text-destructive"
                            onClick={() => removeRule(i)}>
                            Remove
                          </Button>
                        )}
                      </div>

                      <Field
                        label={`${peerLabel(form.direction)} — kind`}
                        hint={r.peerKind === 'entity'
                          ? 'A reserved Cilium identity, which has no labels to select.'
                          : undefined}
                      >
                        <Select value={r.peerKind}
                          onValueChange={v => setRule(i, 'peerKind', v as PeerKind)}>
                          <SelectTrigger className="h-9 w-full"><SelectValue /></SelectTrigger>
                          <SelectContent>
                            <SelectGroup>
                              <SelectItem value="labels">Labels</SelectItem>
                              <SelectItem value="entity">Entity</SelectItem>
                            </SelectGroup>
                          </SelectContent>
                        </Select>
                      </Field>

                      {r.peerKind === 'entity' ? (
                        <Field label={peerLabel(form.direction)} required>
                          <Select value={r.peerEntity}
                            onValueChange={v => setRule(i, 'peerEntity', v)}>
                            <SelectTrigger className="h-9 w-full"><SelectValue /></SelectTrigger>
                            <SelectContent>
                              <SelectGroup>
                                {ENTITIES.map(e => <SelectItem key={e} value={e}>{e}</SelectItem>)}
                              </SelectGroup>
                            </SelectContent>
                          </Select>
                        </Field>
                      ) : (
                        <LabelRows
                          title={peerLabel(form.direction)}
                          required
                          // The one thing about Cilium selectors that catches
                          // everyone: a namespaced policy matches peers in its
                          // own namespace unless the namespace is named. The
                          // form has always accepted a "namespace" row and
                          // rewritten it to io.kubernetes.pod.namespace; nothing
                          // said so, so the capability was unreachable in
                          // practice.
                          hint={form.scope === 'namespaced'
                            ? `A peer in another namespace needs a "namespace" row — without one this matches only peers in ${form.namespace || 'this policy\'s namespace'}.`
                            : 'Add a "namespace" row to restrict the peer to one namespace.'}
                          pairs={r.peerLabels}
                          onChange={pairs => updateRule(i, r => ({ ...r, peerLabels: pairs }))}
                        />
                      )}

                      <div className="flex flex-col gap-2">
                        <div className="flex items-center justify-between">
                          <Label className="text-xs">Ports</Label>
                          <Button variant="outline" size="sm" className="h-7 text-xs"
                            onClick={() => updateRule(i, r => ({ ...r, ports: [...r.ports, emptyPort()] }))}>
                            + Add port
                          </Button>
                        </div>
                        {r.ports.length === 0 ? (
                          <p className="text-[11px] text-muted-foreground">No port restriction — every port.</p>
                        ) : r.ports.map((p, pi) => (
                          <div key={pi} className="flex items-center gap-2">
                            <Input value={p.port} className="h-8 flex-1 font-mono text-sm"
                              onChange={e => updateRule(i, r => ({
                                ...r,
                                ports: r.ports.map((q, qi) => qi === pi ? { ...q, port: e.target.value } : q),
                              }))} />
                            <Select value={p.protocol}
                              onValueChange={v => updateRule(i, r => ({
                                ...r,
                                ports: r.ports.map((q, qi) => qi === pi ? { ...q, protocol: v } : q),
                              }))}>
                              <SelectTrigger className="h-8 w-24 text-sm"><SelectValue /></SelectTrigger>
                              <SelectContent>
                                <SelectGroup>
                                  {PROTOCOLS.map(pr => <SelectItem key={pr} value={pr}>{pr}</SelectItem>)}
                                </SelectGroup>
                              </SelectContent>
                            </Select>
                            <Button variant="ghost" size="sm" className="h-8 px-2 text-xs text-destructive hover:text-destructive"
                              onClick={() => updateRule(i, r => ({
                                ...r, ports: r.ports.filter((_, qi) => qi !== pi),
                              }))}>
                              Remove
                            </Button>
                          </div>
                        ))}
                      </div>

                      <div className="flex flex-col gap-2 border-t pt-3">
                        <div className="flex items-center justify-between">
                          <Label className="text-xs">
                            L7 — HTTP rules
                            {/* Kept only on a blacklist, where it says why the
                                controls below are disabled. */}
                            {form.mode === 'blacklist' && (
                              <span className="font-normal text-muted-foreground"> (whitelist only)</span>
                            )}
                          </Label>
                          <Button variant="outline" size="sm" className="h-7 text-xs"
                            disabled={form.mode === 'blacklist'}
                            onClick={() => updateRule(i, r => ({ ...r, http: [...r.http, emptyHttp()] }))}>
                            + Add HTTP rule
                          </Button>
                        </div>
                        {r.http.length === 0 ? (
                          <p className="text-[11px] text-muted-foreground">
                            No HTTP rule — every request on the ports above.
                          </p>
                        ) : r.http.map((h, hi) => (
                          <div key={hi} className="flex items-end gap-2">
                            <div className="flex flex-1 flex-col gap-1">
                              <span className="text-[11px] text-muted-foreground">Method</span>
                              <Select value={h.method || 'any'}
                                onValueChange={v => updateRule(i, r => ({
                                  ...r,
                                  http: r.http.map((q, qi) => qi === hi ? { ...q, method: v === 'any' ? '' : v } : q),
                                }))}
                                disabled={form.mode === 'blacklist'}>
                                <SelectTrigger className="h-8 text-sm"><SelectValue /></SelectTrigger>
                                <SelectContent>
                                  <SelectGroup>
                                    <SelectItem value="any">Any method</SelectItem>
                                    {HTTP_METHODS.map(m => <SelectItem key={m} value={m}>{m}</SelectItem>)}
                                  </SelectGroup>
                                </SelectContent>
                              </Select>
                            </div>
                            <div className="flex flex-1 flex-col gap-1">
                              <span className="text-[11px] text-muted-foreground">Path</span>
                              <Input value={h.path}
                                onChange={e => updateRule(i, r => ({
                                  ...r,
                                  http: r.http.map((q, qi) => qi === hi ? { ...q, path: e.target.value } : q),
                                }))}
                                disabled={form.mode === 'blacklist'}
                                className="h-8 font-mono text-sm" />
                            </div>
                            <Button variant="ghost" size="sm"
                              className="h-8 px-2 text-xs text-destructive hover:text-destructive"
                              onClick={() => updateRule(i, r => ({
                                ...r, http: r.http.filter((_, qi) => qi !== hi),
                              }))}>
                              Remove
                            </Button>
                          </div>
                        ))}
                        {r.http.length > 1 && (
                          <p className="text-[11px] text-muted-foreground">
                            Alternatives — a request matching any of them matches the rule.
                          </p>
                        )}
                      </div>
                    </div>
                  ))}

                  <p className="text-[11px] text-muted-foreground">
                    {form.mode === 'blacklist'
                      ? 'HTTP is whitelist-only — Cilium deny rules match on L3/L4.'
                      : 'HTTP is optional per rule, and needs a port and the Cilium proxy.'}
                  </p>
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

            {/* Right: YAML preview. gap-0 py-0 so the code surface meets the frame:
                Card adds py-4 and gap-4 otherwise, insetting it. */}
            <Card className="gap-0 overflow-hidden py-0">
              <div className="flex items-center justify-between border-b px-4 py-3">
                <span className="text-sm font-medium">Generated YAML</span>
                <Badge variant="secondary" className="font-mono text-[10px]">
                  {form.scope === 'cluster' ? 'CiliumClusterwideNetworkPolicy' : 'CiliumNetworkPolicy'}
                </Badge>
              </div>
              <CardContent className="min-h-0 flex-1 p-0">
                <pre className="h-full min-h-[420px] overflow-auto rounded-b-xl bg-[#1e1e1e] p-4 font-mono text-xs leading-relaxed text-[#d4d4d4]">
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
          <p className="text-sm text-muted-foreground">Manage Cilium Network Policy.</p>
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
          <ScopeFilter value={nsFilter} onChange={setNsFilter} namespaces={namespaces} />
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
            <AlertDialogTitle>Delete Policy</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete <strong>{deleteTarget?.name}</strong>?
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
