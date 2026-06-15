import { useCallback, useEffect, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
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
  name: string
  description: string
  apiGroup: string
  resource: string
  operations: string[]
  validations: ValidationRow[]
}

const EMPTY_FORM: FormState = {
  name: '', description: '',
  apiGroup: 'apps', resource: 'deployments',
  operations: ['CREATE', 'UPDATE'],
  validations: [{ expression: '', message: '' }],
}

function RuleForm({ initial, onSave, onCancel, saving }: {
  initial: FormState
  onSave: (f: FormState) => void
  onCancel: () => void
  saving: boolean
}) {
  const [form, setForm] = useState(initial)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const set = (k: keyof FormState, v: any) => setForm(f => ({ ...f, [k]: v }))

  const toggleOp = (op: string) =>
    set('operations', form.operations.includes(op)
      ? form.operations.filter(x => x !== op)
      : [...form.operations, op])

  const setValidation = (i: number, field: keyof ValidationRow, val: string) =>
    set('validations', form.validations.map((v, idx) => idx === i ? { ...v, [field]: val } : v))

  const addValidation = () => set('validations', [...form.validations, { expression: '', message: '' }])
  const removeValidation = (i: number) => set('validations', form.validations.filter((_, idx) => idx !== i))

  const applyTemplate = (i: number, tpl: typeof TEMPLATES[0]) =>
    set('validations', form.validations.map((v, idx) => idx === i ? { expression: tpl.expression, message: tpl.message } : v))

  const resources = RESOURCES[form.apiGroup] ?? ['*']
  const valid = form.name.trim().length > 0 && form.validations.some(v => v.expression.trim().length > 0)

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-2 gap-3">
        <div className="flex flex-col gap-1">
          <Label className="text-xs">Name <span className="text-destructive">*</span></Label>
          <Input className="h-8 text-sm" value={form.name} onChange={e => set('name', e.target.value)} placeholder="no-over-replica" />
        </div>
        <div className="flex flex-col gap-1">
          <Label className="text-xs">Description</Label>
          <Input className="h-8 text-sm" value={form.description} onChange={e => set('description', e.target.value)} placeholder="Optional description" />
        </div>
      </div>

      <div className="rounded-md border p-3 flex flex-col gap-3">
        <p className="text-xs font-medium text-muted-foreground">Target Resource</p>
        <div className="grid grid-cols-2 gap-3">
          <div className="flex flex-col gap-1">
            <Label className="text-xs">API Group</Label>
            <Select value={form.apiGroup} onValueChange={v => { set('apiGroup', v); set('resource', RESOURCES[v]?.[0] ?? '*') }}>
              <SelectTrigger className="h-8 text-sm"><SelectValue /></SelectTrigger>
              <SelectContent><SelectGroup>{API_GROUPS.map(g => <SelectItem key={g.value} value={g.value}>{g.label}</SelectItem>)}</SelectGroup></SelectContent>
            </Select>
          </div>
          <div className="flex flex-col gap-1">
            <Label className="text-xs">Resource</Label>
            <Select value={form.resource} onValueChange={v => set('resource', v)}>
              <SelectTrigger className="h-8 text-sm"><SelectValue /></SelectTrigger>
              <SelectContent><SelectGroup>{resources.map(r => <SelectItem key={r} value={r}>{r}</SelectItem>)}</SelectGroup></SelectContent>
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

      <div className="rounded-md border p-3 flex flex-col gap-3">
        <p className="text-xs font-medium text-muted-foreground">Validation Conditions</p>
        {form.validations.map((v, i) => (
          <div key={i} className="flex flex-col gap-2 rounded border p-2">
            <div className="flex items-center justify-between">
              <span className="text-xs text-muted-foreground">Condition {i + 1}</span>
              <div className="flex items-center gap-1">
                <Select onValueChange={tpl => applyTemplate(i, TEMPLATES.find(t => t.label === tpl)!)}>
                  <SelectTrigger className="h-6 text-[10px] w-36 border-dashed"><SelectValue placeholder="Use template" /></SelectTrigger>
                  <SelectContent><SelectGroup>{TEMPLATES.map(t => <SelectItem key={t.label} value={t.label} className="text-xs">{t.label}</SelectItem>)}</SelectGroup></SelectContent>
                </Select>
                {form.validations.length > 1 && (
                  <Button variant="ghost" size="sm" className="h-6 text-xs text-destructive px-1"
                    onClick={() => removeValidation(i)}>✕</Button>
                )}
              </div>
            </div>
            <div className="flex flex-col gap-1">
              <Label className="text-xs">Expression (CEL) <span className="text-destructive">*</span></Label>
              <Input className="h-8 text-xs font-mono" value={v.expression}
                onChange={e => setValidation(i, 'expression', e.target.value)}
                placeholder='object.spec.replicas <= 5' />
            </div>
            <div className="flex flex-col gap-1">
              <Label className="text-xs">Violation Message</Label>
              <Input className="h-8 text-xs" value={v.message}
                onChange={e => setValidation(i, 'message', e.target.value)}
                placeholder='Replicas must be <= 5' />
            </div>
          </div>
        ))}
        <Button variant="outline" size="sm" className="h-7 text-xs self-start" onClick={addValidation}>
          + Add Condition
        </Button>
      </div>

      <div className="flex justify-end gap-2">
        <Button variant="outline" size="sm" onClick={onCancel}>Cancel</Button>
        <Button size="sm" onClick={() => onSave(form)} disabled={saving || !valid}>
          {saving ? 'Saving...' : 'Save Rule'}
        </Button>
      </div>
    </div>
  )
}

function formToPayload(f: FormState) {
  return {
    name: f.name.trim(),
    description: f.description.trim(),
    spec: {
      matchConstraints: {
        resourceRules: [{
          apiGroups: [f.apiGroup],
          apiVersions: ['*'],
          operations: f.operations,
          resources: [f.resource],
        }],
      },
      validations: f.validations.filter(v => v.expression.trim()).map(v => ({
        expression: v.expression.trim(),
        message: v.message.trim(),
      })),
    },
  }
}

function ruleToForm(rule: AdmissionRule): FormState {
  const rr = rule.spec?.matchConstraints?.resourceRules?.[0]
  return {
    name: rule.name,
    description: rule.description ?? '',
    apiGroup: rr?.apiGroups?.[0] ?? 'apps',
    resource: rr?.resources?.[0] ?? '*',
    operations: rr?.operations ?? ['CREATE', 'UPDATE'],
    validations: rule.spec?.validations?.length
      ? rule.spec.validations.map((v: { expression: string; message: string }) => ({ expression: v.expression, message: v.message ?? '' }))
      : [{ expression: '', message: '' }],
  }
}

export function AdmissionRulesPage() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const toast = useToast()

  const [rules, setRules] = useState<AdmissionRule[]>([])
  const [showForm, setShowForm] = useState(false)
  const [editTarget, setEditTarget] = useState<AdmissionRule | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<AdmissionRule | null>(null)
  const [saving, setSaving] = useState(false)

  const load = useCallback(async () => {
    try { setRules(await admissionRulesApi.list()) } catch { }
  }, [])

  useEffect(() => { load() }, [load])

  const handleSave = async (form: FormState) => {
    setSaving(true)
    try {
      const payload = formToPayload(form)
      if (editTarget) {
        await admissionRulesApi.update(editTarget.id, payload)
        toast.success('Rule updated.')
        setEditTarget(null)
      } else {
        await admissionRulesApi.create(payload)
        toast.success('Rule created.')
        setShowForm(false)
      }
      load()
    } catch (e: unknown) {
      toast.error((e as { response?: { data?: string } })?.response?.data || 'Failed to save rule')
    } finally { setSaving(false) }
  }

  const handleToggle = async (rule: AdmissionRule) => {
    try { await admissionRulesApi.toggle(rule.id, !rule.enabled); load() }
    catch { toast.error('Failed to toggle rule') }
  }

  const handleDelete = async () => {
    if (!deleteTarget) return
    try {
      await admissionRulesApi.delete(deleteTarget.id)
      toast.success('Rule deleted.')
      setDeleteTarget(null); load()
    } catch { toast.error('Failed to delete rule') }
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
        {isAdmin && !showForm && !editTarget && (
          <Button onClick={() => setShowForm(true)}>+ New Rule</Button>
        )}
      </div>

      {isAdmin && showForm && !editTarget && (
        <Card className="mb-6 border-primary/40">
          <CardHeader className="border-b pb-3">
            <CardTitle className="text-sm font-medium">New Admission Rule</CardTitle>
          </CardHeader>
          <CardContent className="pt-4">
            <RuleForm initial={EMPTY_FORM} onSave={handleSave}
              onCancel={() => setShowForm(false)} saving={saving} />
          </CardContent>
        </Card>
      )}

      {isAdmin && editTarget && (
        <Card className="mb-6 border-primary/40">
          <CardHeader className="border-b pb-3">
            <CardTitle className="text-sm font-medium">Edit — {editTarget.name}</CardTitle>
          </CardHeader>
          <CardContent className="pt-4">
            <RuleForm initial={ruleToForm(editTarget)} onSave={handleSave}
              onCancel={() => setEditTarget(null)} saving={saving} />
          </CardContent>
        </Card>
      )}

      {rules.length === 0 && !showForm && (
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
                    onClick={() => { setEditTarget(rule); setShowForm(false) }}>Edit</Button>
                  <Button variant="ghost" size="sm" className="h-7 text-xs"
                    onClick={() => handleToggle(rule)}>
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
            <AlertDialogAction variant="destructive" onClick={handleDelete}>Delete</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
