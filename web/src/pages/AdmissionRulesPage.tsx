import { useCallback, useEffect, useState } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { admissionRulesApi, type AdmissionRule } from '../api/client'
import { useAuth } from '../layout/AuthContext'
import { useToast } from '../layout/AppToaster'
import { formatTWTime } from '../utils/time'

const API_GROUPS = [
  { value: 'apps', label: 'apps' },
  { value: '', label: 'core ("")' },
  { value: 'batch', label: 'batch' },
  { value: 'networking.k8s.io', label: 'networking.k8s.io' },
  { value: 'rbac.authorization.k8s.io', label: 'rbac.authorization.k8s.io' },
  { value: '*', label: '* (all)' },
]

const RESOURCES: Record<string, string[]> = {
  apps: ['deployments', 'replicasets', 'daemonsets', 'statefulsets'],
  '': ['pods', 'services', 'configmaps', 'secrets', 'namespaces'],
  batch: ['jobs', 'cronjobs'],
  'networking.k8s.io': ['ingresses', 'networkpolicies'],
  'rbac.authorization.k8s.io': ['roles', 'clusterroles', 'rolebindings'],
  '*': ['*'],
}

const TEMPLATES = [
  { label: 'Max replicas', expression: 'object.spec.replicas <= 5', message: 'Replicas must be <= 5' },
  { label: 'Require label "app"', expression: '"app" in object.metadata.labels', message: 'Label "app" is required' },
  { label: 'No latest tag', expression: '!object.spec.containers.exists(c, c.image.endsWith(":latest"))', message: 'Image tag ":latest" is not allowed' },
  { label: 'Image registry whitelist', expression: 'object.spec.containers.all(c, c.image.startsWith("myregistry.io/"))', message: 'Images must come from myregistry.io' },
  { label: 'Require resource limits', expression: 'object.spec.containers.all(c, has(c.resources.limits))', message: 'All containers must have resource limits' },
]

interface ValidationRow { expression: string; message: string }
interface FormState {
  name: string; description: string
  apiGroup: string; resource: string
  operations: string[]
  validations: ValidationRow[]
}

const EMPTY_FORM: FormState = {
  name: '', description: '', apiGroup: 'apps', resource: 'deployments',
  operations: ['CREATE', 'UPDATE'], validations: [{ expression: '', message: '' }],
}

function RuleForm({ initial, title, onSave, onBack, saving }: {
  initial: FormState; title: string
  onSave: (f: FormState) => void; onBack: () => void; saving: boolean
}) {
  const [form, setForm] = useState<FormState>(initial)
  const setField = (k: string, v: unknown) => setForm(f => ({ ...f, [k]: v }))
  const toggleOp = (op: string) => setField('operations',
    form.operations.includes(op) ? form.operations.filter(x => x !== op) : [...form.operations, op])
  const setVal = (i: number, f2: string, v: string) => setField('validations',
    form.validations.map((row, idx) => idx === i ? { ...row, [f2]: v } : row))
  const addVal = () => setField('validations', [...form.validations, { expression: '', message: '' }])
  const removeVal = (i: number) => setField('validations', form.validations.filter((_, idx) => idx !== i))
  const applyTpl = (i: number, label: string) => {
    const tpl = TEMPLATES.find(t => t.label === label)
    if (!tpl) return
    setField('validations', form.validations.map((row, idx) =>
      idx === i ? { expression: tpl.expression, message: tpl.message } : row))
  }
  const resources = RESOURCES[form.apiGroup] ?? ['*']
  const isValid = form.name.trim().length > 0 && form.validations.some(v => v.expression.trim().length > 0)

  return (
    <>
      <div className="mb-6 flex items-center justify-between">
        <h4 className="text-xl font-semibold">{title}</h4>
        <div className="flex gap-2">
          <Button variant="outline" onClick={onBack}>← Back</Button>
          <Button onClick={() => onSave(form)} disabled={saving || !isValid}>
            {saving ? 'Saving...' : 'Save Rule'}
          </Button>
        </div>
      </div>

      <div className="flex flex-col gap-4 max-w-2xl">
        {/* Basic info */}
        <div className="grid grid-cols-2 gap-3">
          <div className="flex flex-col gap-1">
            <Label className="text-xs">Name <span className="text-destructive">*</span></Label>
            <Input className="h-8 text-sm" value={form.name}
              onChange={e => setField('name', e.target.value)} placeholder="no-over-replica" />
          </div>
          <div className="flex flex-col gap-1">
            <Label className="text-xs">Description</Label>
            <Input className="h-8 text-sm" value={form.description}
              onChange={e => setField('description', e.target.value)} placeholder="Optional description" />
          </div>
        </div>

        {/* Target resource */}
        <div className="rounded-md border p-4 flex flex-col gap-3">
          <p className="text-sm font-medium">Target Resource</p>
          <div className="grid grid-cols-2 gap-3">
            <div className="flex flex-col gap-1">
              <Label className="text-xs">API Group</Label>
              <Select value={form.apiGroup} onValueChange={v => {
                setField('apiGroup', v)
                setField('resource', RESOURCES[v]?.[0] ?? '*')
              }}>
                <SelectTrigger className="h-8 text-sm"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    {API_GROUPS.map(g => <SelectItem key={g.value} value={g.value}>{g.label}</SelectItem>)}
                  </SelectGroup>
                </SelectContent>
              </Select>
            </div>
            <div className="flex flex-col gap-1">
              <Label className="text-xs">Resource</Label>
              <Select value={form.resource} onValueChange={v => setField('resource', v)}>
                <SelectTrigger className="h-8 text-sm"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    {resources.map(r => <SelectItem key={r} value={r}>{r}</SelectItem>)}
                  </SelectGroup>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="flex flex-col gap-1">
            <Label className="text-xs">Operations</Label>
            <div className="flex gap-4">
              {['CREATE', 'UPDATE', 'DELETE'].map(op => (
                <label key={op} className="flex items-center gap-1.5 cursor-pointer text-sm">
                  <input type="checkbox" className="h-4 w-4 accent-primary"
                    checked={form.operations.includes(op)} onChange={() => toggleOp(op)} />
                  {op}
                </label>
              ))}
            </div>
          </div>
        </div>

        {/* Conditions */}
        <div className="rounded-md border p-4 flex flex-col gap-3">
          <p className="text-sm font-medium">Validation Conditions</p>
          {form.validations.map((v, i) => (
            <div key={i} className="rounded border p-3 flex flex-col gap-2">
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">Condition {i + 1}</span>
                <div className="flex gap-1">
                  <select
                    className="h-6 text-[10px] rounded border bg-background px-1 cursor-pointer"
                    value=""
                    onChange={e => { if (e.target.value) applyTpl(i, e.target.value) }}
                  >
                    <option value="">Use template...</option>
                    {TEMPLATES.map(t => <option key={t.label} value={t.label}>{t.label}</option>)}
                  </select>
                  {form.validations.length > 1 && (
                    <Button variant="ghost" size="sm" className="h-6 px-2 text-xs text-destructive"
                      onClick={() => removeVal(i)}>✕</Button>
                  )}
                </div>
              </div>
              <div className="flex flex-col gap-1">
                <Label className="text-xs">Expression (CEL) <span className="text-destructive">*</span></Label>
                <Input className="h-8 text-xs font-mono" value={v.expression}
                  onChange={e => setVal(i, 'expression', e.target.value)}
                  placeholder="object.spec.replicas <= 5" />
              </div>
              <div className="flex flex-col gap-1">
                <Label className="text-xs">Violation Message</Label>
                <Input className="h-8 text-xs" value={v.message}
                  onChange={e => setVal(i, 'message', e.target.value)}
                  placeholder="Replicas must be <= 5" />
              </div>
            </div>
          ))}
          <Button variant="outline" size="sm" className="h-7 text-xs self-start" onClick={addVal}>
            + Add Condition
          </Button>
        </div>
      </div>
    </>
  )
}

function formToPayload(f: FormState) {
  return {
    name: f.name.trim(), description: f.description.trim(),
    spec: {
      matchConstraints: {
        resourceRules: [{ apiGroups: [f.apiGroup], apiVersions: ['*'], operations: f.operations, resources: [f.resource] }],
      },
      validations: f.validations.filter(v => v.expression.trim()).map(v => ({ expression: v.expression.trim(), message: v.message.trim() })),
    },
  }
}

function ruleToForm(rule: AdmissionRule): FormState {
  const rr = rule.spec?.matchConstraints?.resourceRules?.[0]
  return {
    name: rule.name, description: rule.description ?? '',
    apiGroup: rr?.apiGroups?.[0] ?? 'apps',
    resource: rr?.resources?.[0] ?? '*',
    operations: rr?.operations ?? ['CREATE', 'UPDATE'],
    validations: rule.spec?.validations?.length
      ? rule.spec.validations.map(v => ({ expression: v.expression, message: v.message ?? '' }))
      : [{ expression: '', message: '' }],
  }
}

type View = { kind: 'list' } | { kind: 'new' } | { kind: 'edit'; rule: AdmissionRule }

export function AdmissionRulesPage() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const toast = useToast()

  const [rules, setRules] = useState<AdmissionRule[]>([])
  const [view, setView] = useState<View>({ kind: 'list' })
  const [deleteTarget, setDeleteTarget] = useState<AdmissionRule | null>(null)
  const [saving, setSaving] = useState(false)

  const load = useCallback(async () => {
    try { setRules(await admissionRulesApi.list()) } catch { }
  }, [])

  useEffect(() => { load() }, [load])

  const handleSave = async (form: FormState) => {
    setSaving(true)
    try {
      if (view.kind === 'edit') {
        await admissionRulesApi.update(view.rule.id, formToPayload(form))
        toast.success('Rule updated.')
      } else {
        await admissionRulesApi.create(formToPayload(form))
        toast.success('Rule created.')
      }
      setView({ kind: 'list' }); load()
    } catch (e: unknown) {
      toast.error((e as { response?: { data?: string } })?.response?.data || 'Failed to save')
    } finally { setSaving(false) }
  }

  if (view.kind === 'new') {
    return <RuleForm initial={EMPTY_FORM} title="New Admission Rule"
      onSave={handleSave} onBack={() => setView({ kind: 'list' })} saving={saving} />
  }

  if (view.kind === 'edit') {
    return <RuleForm initial={ruleToForm(view.rule)} title={`Edit — ${view.rule.name}`}
      onSave={handleSave} onBack={() => setView({ kind: 'list' })} saving={saving} />
  }

  return (
    <>
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h4 className="text-xl font-semibold">Admission Rules</h4>
          <p className="text-sm text-muted-foreground">
            Enforced via Sentinel webhook. Violations appear in Admission Events.
          </p>
        </div>
        {isAdmin && <Button onClick={() => setView({ kind: 'new' })}>+ New Rule</Button>}
      </div>

      {rules.length === 0 && (
        <p className="py-10 text-center text-sm text-muted-foreground">No admission rules configured.</p>
      )}

      <div className="flex flex-col gap-3">
        {rules.map(rule => (
          <Card key={rule.id} className={rule.enabled ? '' : 'opacity-60'}>
            <CardContent className="flex items-center justify-between py-3">
              <div className="flex items-center gap-3 min-w-0">
                <span className="font-medium text-sm truncate">{rule.name}</span>
                {rule.description && (
                  <span className="text-xs text-muted-foreground truncate hidden md:block">{rule.description}</span>
                )}
                <Badge variant={rule.enabled ? 'default' : 'secondary'} className="text-[10px] shrink-0">
                  {rule.enabled ? 'Enabled' : 'Disabled'}
                </Badge>
                <span className="text-xs text-muted-foreground shrink-0">{formatTWTime(rule.createdAt)}</span>
              </div>
              {isAdmin && (
                <div className="flex items-center gap-2 shrink-0">
                  <Button variant="ghost" size="sm" className="h-7 text-xs"
                    onClick={() => setView({ kind: 'edit', rule })}>Edit</Button>
                  <Button variant="ghost" size="sm" className="h-7 text-xs"
                    onClick={async () => {
                      await admissionRulesApi.toggle(rule.id, !rule.enabled).catch(() => {})
                      load()
                    }}>
                    {rule.enabled ? 'Disable' : 'Enable'}
                  </Button>
                  <Button variant="ghost" size="sm" className="h-7 text-xs text-destructive hover:text-destructive"
                    onClick={() => setDeleteTarget(rule)}>Delete</Button>
                </div>
              )}
            </CardContent>
          </Card>
        ))}
      </div>

      <AlertDialog open={!!deleteTarget} onOpenChange={open => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Rule</AlertDialogTitle>
            <AlertDialogDescription>Delete "{deleteTarget?.name}"? This cannot be undone.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction variant="destructive" onClick={async () => {
              if (!deleteTarget) return
              await admissionRulesApi.delete(deleteTarget.id).catch(() => {})
              toast.success('Rule deleted.')
              setDeleteTarget(null); load()
            }}>Delete</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
