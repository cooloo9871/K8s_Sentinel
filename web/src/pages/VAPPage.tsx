import { useCallback, useEffect, useState } from 'react'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import {
  Table, TableHeader, TableBody, TableRow, TableHead, TableCell,
} from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Label } from '@/components/ui/label'
import { Checkbox } from '@/components/ui/checkbox'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import {
  Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import yaml from 'js-yaml'
import { vapApi, type VAPRecord, type VAPBindingRecord } from '../api/client'
import { YamlEditor } from '../components/YamlEditor'
import { useAuth } from '../layout/AuthContext'
import { useToast } from '../layout/AppToaster'
import { formatTWTime } from '../utils/time'
import { Input } from '@/components/ui/input'

type EditTarget = { kind: 'policy' | 'binding'; name?: string; yaml: string }
type LabelCondition = '==' | '!='
type ValidationAction = 'Deny' | 'Audit' | 'Warn'
type PolicyRuleType = 'label' | 'image' | 'replica'
type ImagePolicyType = 'no-latest' | 'required-registry'

interface LabelRule {
  key: string
  condition: LabelCondition
  value: string
  message: string
}

interface ImageRule {
  type: ImagePolicyType
  registry: string  // only for 'required-registry'
  message: string
}

interface ReplicaRule {
  maxReplicas: number
  message: string
}

const emptyRule = (): LabelRule => ({ key: '', condition: '==', value: '', message: '' })
const emptyImageRule = (): ImageRule => ({ type: 'no-latest', registry: '', message: '' })
const emptyReplicaRule = (): ReplicaRule => ({ maxReplicas: 5, message: '' })

// Policy builder ---------------------------------------------------------------

function escapeYaml(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
}

function autoMessage(key: string, cond: LabelCondition, value: string): string {
  if (!key.trim() || !value.trim()) return 'Label policy validation failed'
  return cond === '=='
    ? `Resources with label ${key}=${value} are not allowed`
    : `Resources must have label ${key}=${value}`
}

function ruleToYamlLines(rule: LabelRule): string[] {
  const k = rule.key.trim()   || 'app'
  const v = rule.value.trim() || 'value'
  const m = rule.message.trim() || autoMessage(rule.key, rule.condition, rule.value)
  const exprLines = rule.condition === '=='
    ? [
        '        !has(object.metadata.labels) ||',
        `        !('${k}' in object.metadata.labels) ||`,
        `        object.metadata.labels['${k}'] != '${v}'`,
      ]
    : [
        '        has(object.metadata.labels) &&',
        `        '${k}' in object.metadata.labels &&`,
        `        object.metadata.labels['${k}'] == '${v}'`,
      ]
  return [
    '    - expression: >-',
    ...exprLines,
    `      message: "${escapeYaml(m)}"`,
    '      reason: Forbidden',
  ]
}

function autoImageMessage(rule: ImageRule): string {
  if (rule.type === 'no-latest') return 'Container images must not use the :latest tag'
  const r = rule.registry.trim()
  return r ? `Container images must be from ${r}` : 'Container images must be from an allowed registry'
}

function imageRuleToYamlLines(rule: ImageRule): string[] {
  const m = escapeYaml(rule.message.trim() || autoImageMessage(rule))
  const reg = rule.registry.trim() || 'registry.example.com'
  // Check containers at all three workload paths using CEL optional chaining (?.)
  // so the same expression covers Pods, Deployments/StatefulSets/DaemonSets, and CronJobs.
  const check = rule.type === 'no-latest'
    ? `all(c, c.image.contains(':') && !c.image.endsWith(':latest'))`
    : `all(c, c.image.startsWith('${reg}'))`
  return [
    '    - expression: >-',
    `        object.spec.?containers.orValue([]).${check} &&`,
    `        object.spec.?template.?spec.?containers.orValue([]).${check} &&`,
    `        object.spec.?jobTemplate.?spec.?template.?spec.?containers.orValue([]).${check}`,
    `      message: "${m}"`,
    '      reason: Forbidden',
  ]
}

function autoReplicaMessage(rule: ReplicaRule): string {
  const max = rule.maxReplicas > 0 ? rule.maxReplicas : 5
  return `Deployment replicas must not exceed ${max}`
}

function replicaRuleToYamlLines(rule: ReplicaRule): string[] {
  const max = rule.maxReplicas > 0 ? rule.maxReplicas : 5
  const m = escapeYaml(rule.message.trim() || autoReplicaMessage(rule))
  return [
    `    - expression: "object.spec.replicas <= ${max}"`,
    `      message: "${m}"`,
    '      reason: Forbidden',
  ]
}

function generatePolicyYaml(
  name: string, ruleType: PolicyRuleType, labelRules: LabelRule[], imageRules: ImageRule[],
  replicaRules: ReplicaRule[],
): string {
  const safeName = name.trim() || 'my-policy'
  let validationLines: string[]
  if (ruleType === 'label') {
    const active = labelRules.filter(r => r.key.trim() && r.value.trim())
    validationLines = active.length ? active.flatMap(ruleToYamlLines) : ruleToYamlLines(emptyRule())
  } else if (ruleType === 'image') {
    const active = imageRules.filter(r => r.type === 'no-latest' || r.registry.trim())
    validationLines = active.length ? active.flatMap(imageRuleToYamlLines) : imageRuleToYamlLines(emptyImageRule())
  } else {
    const active = replicaRules.filter(r => r.maxReplicas > 0)
    validationLines = active.length ? active.flatMap(replicaRuleToYamlLines) : replicaRuleToYamlLines(emptyReplicaRule())
  }

  const resourceRuleLines = ruleType === 'replica'
    ? [
        '    resourceRules:',
        '    - apiGroups: ["apps"]',
        '      apiVersions: ["v1"]',
        '      operations: [CREATE, UPDATE]',
        '      resources: ["deployments"]',
        '    - apiGroups: ["apps"]',
        '      apiVersions: ["v1"]',
        '      operations: [UPDATE]',
        '      resources: ["deployments/scale"]',
      ]
    : ruleType === 'image'
    ? [
        '    resourceRules:',
        '      - apiGroups: [""]',
        '        apiVersions: ["v1"]',
        '        operations: [CREATE, UPDATE]',
        '        resources: ["pods"]',
        '      - apiGroups: ["apps"]',
        '        apiVersions: ["v1"]',
        '        operations: [CREATE, UPDATE]',
        '        resources: ["deployments", "statefulsets", "daemonsets", "replicasets"]',
        '      - apiGroups: ["batch"]',
        '        apiVersions: ["v1"]',
        '        operations: [CREATE, UPDATE]',
        '        resources: ["jobs", "cronjobs"]',
      ]
    : [
        '    resourceRules:',
        '      - apiGroups: ["*"]',
        '        apiVersions: ["*"]',
        '        operations: [CREATE, UPDATE]',
        '        resources: ["*"]',
      ]

  return [
    'apiVersion: admissionregistration.k8s.io/v1',
    'kind: ValidatingAdmissionPolicy',
    'metadata:',
    `  name: "${safeName}"`,
    '  annotations:',
    '    sentinel.io/builder: "true"',
    'spec:',
    '  failurePolicy: Fail',
    '  matchConstraints:',
    ...resourceRuleLines,
    '  validations:',
    ...validationLines,
  ].join('\n')
}

// Binding builder --------------------------------------------------------------

function generateBindingYaml(
  name: string, policyName: string, namespace: string, actions: ValidationAction[],
): string {
  const safeName   = name.trim()       || 'my-binding'
  const safePolicy = policyName.trim() || 'my-policy'
  const safeNs     = namespace.trim()
  const actStr     = actions.length ? actions.join(', ') : 'Deny'

  const lines = [
    'apiVersion: admissionregistration.k8s.io/v1',
    'kind: ValidatingAdmissionPolicyBinding',
    'metadata:',
    `  name: "${safeName}"`,
    '  annotations:',
    '    sentinel.io/builder: "true"',
    'spec:',
    `  policyName: "${safePolicy}"`,
    `  validationActions: [${actStr}]`,
  ]
  if (safeNs) {
    lines.push(
      '  matchResources:',
      '    namespaceSelector:',
      '      matchLabels:',
      `        kubernetes.io/metadata.name: ${safeNs}`,
    )
  }
  return lines.join('\n')
}

// YAML → builder state parsers -------------------------------------------------

function parseExpressionToRule(expr: string, msg: string): LabelRule | null {
  const e = expr.replace(/\s+/g, ' ').trim()
  // == pattern: deny when key==value
  let m = e.match(/!\('([^']+)' in object\.metadata\.labels\).*object\.metadata\.labels\['[^']+'\] != '([^']+)'/)
  if (m) return { key: m[1], condition: '==', value: m[2], message: msg }
  // != pattern: deny when key!=value / missing
  m = e.match(/'([^']+)' in object\.metadata\.labels.*object\.metadata\.labels\['[^']+'\] == '([^']+)'/)
  if (m) return { key: m[1], condition: '!=', value: m[2], message: msg }
  return null
}

function parseExpressionToImageRule(expr: string, msg: string): ImageRule | null {
  const e = expr.replace(/\s+/g, ' ').trim()
  if (e.includes("!c.image.endsWith(':latest')"))
    return { type: 'no-latest', registry: '', message: msg }
  const m = e.match(/c\.image\.startsWith\('([^']+)'\)/)
  if (m) return { type: 'required-registry', registry: m[1], message: msg }
  return null
}

function parseExpressionToReplicaRule(expr: string, msg: string): ReplicaRule | null {
  const m = expr.trim().match(/^object\.spec\.replicas\s*<=\s*(\d+)$/)
  if (m) return { maxReplicas: parseInt(m[1], 10), message: msg }
  return null
}

function tryParseBuilderPolicy(rawYaml: string): {
  name: string; ruleType: PolicyRuleType
  labelRules: LabelRule[]; imageRules: ImageRule[]; replicaRules: ReplicaRule[]
} | null {
  try {
    const doc = yaml.load(rawYaml) as Record<string, unknown>
    if (doc?.kind !== 'ValidatingAdmissionPolicy') return null
    const meta = doc.metadata as { name?: string; annotations?: Record<string, unknown> }
    if (String(meta?.annotations?.['sentinel.io/builder']) !== 'true') return null
    const spec = doc.spec as { validations?: Array<{ expression?: string; message?: string }> }
    if (!spec?.validations?.length) return null

    const labelRules: LabelRule[] = []
    const imageRules: ImageRule[] = []
    const replicaRules: ReplicaRule[] = []
    for (const v of spec.validations) {
      const lr = parseExpressionToRule(v.expression ?? '', v.message ?? '')
      if (lr) { labelRules.push(lr); continue }
      const ir = parseExpressionToImageRule(v.expression ?? '', v.message ?? '')
      if (ir) { imageRules.push(ir); continue }
      const rr = parseExpressionToReplicaRule(v.expression ?? '', v.message ?? '')
      if (rr) { replicaRules.push(rr); continue }
      return null  // unknown expression type — fall through to YAML editor
    }
    // All rules must be the same type
    const typesUsed = [labelRules.length > 0, imageRules.length > 0, replicaRules.length > 0].filter(Boolean).length
    if (typesUsed > 1) return null
    const ruleType: PolicyRuleType = replicaRules.length > 0 ? 'replica' : imageRules.length > 0 ? 'image' : 'label'
    return { name: meta?.name ?? '', ruleType, labelRules, imageRules, replicaRules }
  } catch { return null }
}

function tryParseBuilderBinding(rawYaml: string): {
  name: string; policyName: string; namespace: string; actions: ValidationAction[]
} | null {
  try {
    const doc = yaml.load(rawYaml) as Record<string, unknown>
    if (doc?.kind !== 'ValidatingAdmissionPolicyBinding') return null
    const meta = doc.metadata as { name?: string; annotations?: Record<string, unknown> }
    // Use String() to handle both string 'true' and boolean true — K8s YAML
    // serialization may omit quotes, causing js-yaml to parse the value as boolean.
    if (String(meta?.annotations?.['sentinel.io/builder']) !== 'true') return null
    const spec = doc.spec as {
      policyName?: string
      validationActions?: string[]
      matchResources?: { namespaceSelector?: { matchLabels?: Record<string, string> } }
    }
    const ns = spec?.matchResources?.namespaceSelector?.matchLabels?.['kubernetes.io/metadata.name'] ?? ''
    return {
      name: meta?.name ?? '',
      policyName: spec?.policyName ?? '',
      actions: (spec?.validationActions ?? ['Deny']) as ValidationAction[],
      namespace: ns,
    }
  } catch { return null }
}

// Page -------------------------------------------------------------------------

export function VAPPage() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const toast = useToast()

  const [policies, setPolicies] = useState<VAPRecord[]>([])
  const [bindings, setBindings] = useState<VAPBindingRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [editor, setEditor] = useState<EditTarget | null>(null)
  const [editorYaml, setEditorYaml] = useState('')
  const [editorValid, setEditorValid] = useState(true)
  const [editorKey, setEditorKey] = useState(0)
  const [saving, setSaving] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<{ kind: 'policy' | 'binding'; name: string } | null>(null)
  const [search, setSearch] = useState('')
  const [activeTab, setActiveTab] = useState<'policies' | 'bindings'>('policies')

  // Policy builder state
  const [showBuilder, setShowBuilder] = useState(false)
  const [builderEditName, setBuilderEditName] = useState<string | undefined>()
  const [builderName, setBuilderName] = useState('')
  const [builderRuleType, setBuilderRuleType] = useState<PolicyRuleType>('label')
  const [labelRules, setLabelRules] = useState<LabelRule[]>([emptyRule()])
  const [imageRules, setImageRules] = useState<ImageRule[]>([emptyImageRule()])
  const [replicaRules, setReplicaRules] = useState<ReplicaRule[]>([emptyReplicaRule()])
  const [builderSaving, setBuilderSaving] = useState(false)

  const updateRule = (i: number, field: keyof LabelRule, val: string) =>
    setLabelRules(prev => prev.map((r, idx) => idx === i ? { ...r, [field]: val } : r))
  const addRule = () => setLabelRules(prev => [...prev, emptyRule()])
  const removeRule = (i: number) => setLabelRules(prev => prev.filter((_, idx) => idx !== i))

  const updateImageRule = (i: number, field: keyof ImageRule, val: string) =>
    setImageRules(prev => prev.map((r, idx) => idx === i ? { ...r, [field]: val } : r))
  const addImageRule = () => setImageRules(prev => [...prev, emptyImageRule()])
  const removeImageRule = (i: number) => setImageRules(prev => prev.filter((_, idx) => idx !== i))

  const updateReplicaRule = (i: number, field: keyof ReplicaRule, val: string | number) =>
    setReplicaRules(prev => prev.map((r, idx) => idx === i ? { ...r, [field]: val } : r))
  const addReplicaRule = () => setReplicaRules(prev => [...prev, emptyReplicaRule()])
  const removeReplicaRule = (i: number) => setReplicaRules(prev => prev.filter((_, idx) => idx !== i))

  const resetBuilderForm = () => {
    setBuilderEditName(undefined)
    setBuilderName('')
    setBuilderRuleType('label')
    setLabelRules([emptyRule()])
    setImageRules([emptyImageRule()])
    setReplicaRules([emptyReplicaRule()])
  }

  // Binding builder state
  const [showBindingBuilder, setShowBindingBuilder] = useState(false)
  const [bindingEditName, setBindingEditName] = useState<string | undefined>()
  const [bindingName, setBindingName] = useState('')
  const [bindingPolicy, setBindingPolicy] = useState('')
  const [bindingNamespace, setBindingNamespace] = useState('')
  const [bindingActions, setBindingActions] = useState<Set<ValidationAction>>(new Set(['Deny']))
  const [bindingBuilderSaving, setBindingBuilderSaving] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [p, b] = await Promise.all([vapApi.listPolicies(), vapApi.listBindings()])
      setPolicies(p)
      setBindings(b)
    } catch { /* ignore */ }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  const openNew = (kind: 'policy' | 'binding') => {
    setEditorYaml('')
    setEditorValid(true)
    setEditorKey(k => k + 1)
    setEditor({ kind, yaml: '' })
  }

  const openEdit = (kind: 'policy' | 'binding', name: string, rawYaml: string) => {
    if (kind === 'policy') {
      const parsed = tryParseBuilderPolicy(rawYaml)
      if (parsed) {
        setBuilderEditName(name)
        setBuilderName(parsed.name)
        setBuilderRuleType(parsed.ruleType)
        setLabelRules(parsed.labelRules.length ? parsed.labelRules : [emptyRule()])
        setImageRules(parsed.imageRules.length ? parsed.imageRules : [emptyImageRule()])
        setReplicaRules(parsed.replicaRules.length ? parsed.replicaRules : [emptyReplicaRule()])
        setShowBuilder(true)
        return
      }
    }
    if (kind === 'binding') {
      const parsed = tryParseBuilderBinding(rawYaml)
      if (parsed) {
        setBindingEditName(name)
        setBindingName(parsed.name)
        setBindingPolicy(parsed.policyName)
        setBindingNamespace(parsed.namespace)
        setBindingActions(new Set(parsed.actions))
        setShowBindingBuilder(true)
        return
      }
    }
    setEditorYaml(rawYaml)
    setEditorValid(true)
    setEditorKey(k => k + 1)
    setEditor({ kind, name, yaml: rawYaml })
  }

  const handleSave = async () => {
    if (!editor || !editorValid) return
    setSaving(true)
    try {
      if (editor.kind === 'policy') {
        if (editor.name) await vapApi.updatePolicy(editor.name, editorYaml)
        else await vapApi.applyPolicy(editorYaml)
      } else {
        if (editor.name) await vapApi.updateBinding(editor.name, editorYaml)
        else await vapApi.applyBinding(editorYaml)
      }
      toast.success(`${editor.kind === 'policy' ? 'Policy' : 'Binding'} applied.`)
      setActiveTab(editor.kind === 'policy' ? 'policies' : 'bindings')
      setEditor(null)
      load()
    } catch (e: unknown) {
      toast.error((e as { response?: { data?: string } })?.response?.data || 'Failed to apply')
    } finally { setSaving(false) }
  }

  const handleDelete = async () => {
    if (!deleteTarget) return
    try {
      if (deleteTarget.kind === 'policy') await vapApi.deletePolicy(deleteTarget.name)
      else await vapApi.deleteBinding(deleteTarget.name)
      toast.success(`${deleteTarget.kind === 'policy' ? 'Policy' : 'Binding'} deleted.`)
      setDeleteTarget(null)
      load()
    } catch { toast.error('Failed to delete') }
  }

  const handleBuilderApply = async () => {
    const nameOk = builderName.trim()
    const rulesOk = builderRuleType === 'label'
      ? labelRules.some(r => r.key.trim() && r.value.trim())
      : builderRuleType === 'image'
      ? imageRules.some(r => r.type === 'no-latest' || r.registry.trim())
      : replicaRules.some(r => r.maxReplicas > 0)
    if (!nameOk || !rulesOk) return
    setBuilderSaving(true)
    try {
      const y = generatePolicyYaml(builderName, builderRuleType, labelRules, imageRules, replicaRules)
      if (builderEditName) await vapApi.updatePolicy(builderEditName, y)
      else await vapApi.applyPolicy(y)
      toast.success('Policy applied.')
      setShowBuilder(false)
      resetBuilderForm()
      load()
    } catch (e: unknown) {
      toast.error((e as { response?: { data?: string } })?.response?.data || 'Failed to apply')
    } finally { setBuilderSaving(false) }
  }

  const handleBindingBuilderApply = async () => {
    if (!bindingName.trim() || !bindingPolicy.trim() || bindingActions.size === 0) return
    setBindingBuilderSaving(true)
    try {
      const y = generateBindingYaml(bindingName, bindingPolicy, bindingNamespace, [...bindingActions])
      if (bindingEditName) await vapApi.updateBinding(bindingEditName, y)
      else await vapApi.applyBinding(y)
      toast.success('Binding applied.')
      setShowBindingBuilder(false)
      setBindingEditName(undefined)
      setBindingName(''); setBindingPolicy(''); setBindingNamespace(''); setBindingActions(new Set(['Deny']))
      load()
    } catch (e: unknown) {
      toast.error((e as { response?: { data?: string } })?.response?.data || 'Failed to apply')
    } finally { setBindingBuilderSaving(false) }
  }

  const toggleAction = (a: ValidationAction) =>
    setBindingActions(prev => {
      const next = new Set(prev)
      next.has(a) ? next.delete(a) : next.add(a)
      return next
    })

  // ── Policy builder view ────────────────────────────────────────────────────
  if (showBuilder) {
    const previewYaml = generatePolicyYaml(builderName, builderRuleType, labelRules, imageRules, replicaRules)
    const rulesOk = builderRuleType === 'label'
      ? labelRules.some(r => r.key.trim() && r.value.trim())
      : builderRuleType === 'image'
      ? imageRules.some(r => r.type === 'no-latest' || r.registry.trim())
      : replicaRules.some(r => r.maxReplicas > 0)
    const canApply = builderName.trim() !== '' && rulesOk
    return (
      <>
        <div className="mb-6 flex items-center justify-between">
          <div>
            <h4 className="text-xl font-semibold">{builderEditName ? 'Edit Policy' : 'New Policy'}</h4>
            <p className="text-sm text-muted-foreground">Configure the policy rules below, then click Apply.</p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => { setShowBuilder(false); resetBuilderForm() }}>← Back</Button>
            {isAdmin && (
              <Button onClick={handleBuilderApply} disabled={!canApply || builderSaving}>
                {builderSaving ? 'Applying...' : 'Apply'}
              </Button>
            )}
          </div>
        </div>

        <div className="grid grid-cols-2 gap-6">
          {/* Left: form */}
          <Card>
            <CardContent className="flex flex-col gap-5 p-6">
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="builder-name">Policy Name</Label>
                <Input id="builder-name" value={builderName} onChange={e => setBuilderName(e.target.value)}
                  readOnly={!!builderEditName} className={builderEditName ? 'opacity-60 cursor-default' : ''} />
              </div>

              <div className="flex flex-col gap-1.5">
                <Label>Rule Type</Label>
                <Select
                  value={builderRuleType}
                  onValueChange={v => {
                    setBuilderRuleType(v as PolicyRuleType)
                    setLabelRules([emptyRule()])
                    setImageRules([emptyImageRule()])
                  }}
                  disabled={!!builderEditName}
                >
                  <SelectTrigger className={builderEditName ? 'opacity-60 cursor-default' : ''}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      <SelectItem value="label">Label Check</SelectItem>
                      <SelectItem value="image">Image Policy</SelectItem>
                      <SelectItem value="replica">Replica Limit</SelectItem>
                    </SelectGroup>
                  </SelectContent>
                </Select>
              </div>

              {/* ── Label Check rules ── */}
              {builderRuleType === 'label' && (
                <div className="flex flex-col gap-3">
                  <div className="flex items-center justify-between">
                    <Label>Label Rules</Label>
                    <Button variant="outline" size="sm" onClick={addRule}>+ Add Rule</Button>
                  </div>

                  {labelRules.map((rule, i) => (
                    <div key={i} className="flex flex-col gap-3 rounded-lg border p-4">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-medium text-muted-foreground">Rule {i + 1}</span>
                        {labelRules.length > 1 && (
                          <Button variant="ghost" size="sm" className="h-6 px-2 text-xs text-destructive hover:text-destructive"
                            onClick={() => removeRule(i)}>
                            Remove
                          </Button>
                        )}
                      </div>

                      <div className="grid grid-cols-2 gap-2">
                        <div className="flex flex-col gap-1">
                          <span className="text-xs text-muted-foreground">Key</span>
                          <Input value={rule.key} onChange={e => updateRule(i, 'key', e.target.value)} placeholder="e.g. app" className="h-8 text-sm" />
                        </div>
                        <div className="flex flex-col gap-1">
                          <span className="text-xs text-muted-foreground">Value</span>
                          <Input value={rule.value} onChange={e => updateRule(i, 'value', e.target.value)} placeholder="e.g. test" className="h-8 text-sm" />
                        </div>
                      </div>

                      <div className="flex flex-col gap-1">
                        <span className="text-xs text-muted-foreground">Condition</span>
                        <Select value={rule.condition} onValueChange={v => updateRule(i, 'condition', v)}>
                          <SelectTrigger className="text-sm"><SelectValue /></SelectTrigger>
                          <SelectContent>
                            <SelectGroup>
                              <SelectItem value="==">Deny when label key matches the value</SelectItem>
                              <SelectItem value="!=">Deny when label key is missing or does not match the value</SelectItem>
                            </SelectGroup>
                          </SelectContent>
                        </Select>
                      </div>

                      <div className="flex flex-col gap-1">
                        <span className="text-xs text-muted-foreground">Violation Message (optional)</span>
                        <Input value={rule.message} onChange={e => updateRule(i, 'message', e.target.value)}
                          placeholder={autoMessage(rule.key || 'key', rule.condition, rule.value || 'value')}
                          className="h-8 text-sm" />
                      </div>

                    </div>
                  ))}

                  {labelRules.length > 1 && (
                    <p className="text-xs text-muted-foreground">
                      Each rule is evaluated independently — a request is denied if any rule fails.
                    </p>
                  )}
                </div>
              )}

              {/* ── Image Policy rules ── */}
              {builderRuleType === 'image' && (
                <div className="flex flex-col gap-3">
                  <div className="flex items-center justify-between">
                    <Label>Image Rules</Label>
                    <Button variant="outline" size="sm" onClick={addImageRule}>+ Add Rule</Button>
                  </div>

                  {imageRules.map((rule, i) => (
                    <div key={i} className="flex flex-col gap-3 rounded-lg border p-4">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-medium text-muted-foreground">Rule {i + 1}</span>
                        {imageRules.length > 1 && (
                          <Button variant="ghost" size="sm" className="h-6 px-2 text-xs text-destructive hover:text-destructive"
                            onClick={() => removeImageRule(i)}>
                            Remove
                          </Button>
                        )}
                      </div>

                      <div className="flex flex-col gap-1">
                        <span className="text-xs text-muted-foreground">Image Check</span>
                        <Select value={rule.type} onValueChange={v => updateImageRule(i, 'type', v)}>
                          <SelectTrigger className="text-sm"><SelectValue /></SelectTrigger>
                          <SelectContent>
                            <SelectGroup>
                              <SelectItem value="no-latest">No Latest Tag — deny images using :latest or no tag</SelectItem>
                              <SelectItem value="required-registry">Required Registry — deny images not from the specified registry</SelectItem>
                            </SelectGroup>
                          </SelectContent>
                        </Select>
                      </div>

                      {rule.type === 'required-registry' && (
                        <div className="flex flex-col gap-1">
                          <span className="text-xs text-muted-foreground">Registry</span>
                          <Input value={rule.registry} onChange={e => updateImageRule(i, 'registry', e.target.value)}
                            placeholder="e.g. registry.example.com" className="h-8 text-sm" />
                        </div>
                      )}

                      <div className="flex flex-col gap-1">
                        <span className="text-xs text-muted-foreground">Violation Message (optional)</span>
                        <Input value={rule.message} onChange={e => updateImageRule(i, 'message', e.target.value)}
                          placeholder={autoImageMessage(rule)} className="h-8 text-sm" />
                      </div>

                    </div>
                  ))}

                  {imageRules.length > 1 && (
                    <p className="text-xs text-muted-foreground">
                      Each rule is evaluated independently — a request is denied if any rule fails.
                    </p>
                  )}
                </div>
              )}

              {/* ── Replica Limit rules ── */}
              {builderRuleType === 'replica' && (
                <div className="flex flex-col gap-3">
                  <div className="flex items-center justify-between">
                    <Label>Replica Rules</Label>
                    <Button variant="outline" size="sm" onClick={addReplicaRule}>+ Add Rule</Button>
                  </div>

                  {replicaRules.map((rule, i) => (
                    <div key={i} className="flex flex-col gap-3 rounded-lg border p-4">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-medium text-muted-foreground">Rule {i + 1}</span>
                        {replicaRules.length > 1 && (
                          <Button variant="ghost" size="sm" className="h-6 px-2 text-xs text-destructive hover:text-destructive"
                            onClick={() => removeReplicaRule(i)}>
                            Remove
                          </Button>
                        )}
                      </div>

                      <div className="flex flex-col gap-1">
                        <span className="text-xs text-muted-foreground">Max Replicas</span>
                        <Input
                          type="number" min={1}
                          value={rule.maxReplicas}
                          onChange={e => updateReplicaRule(i, 'maxReplicas', Math.max(1, parseInt(e.target.value) || 1))}
                          className="h-8 text-sm w-32"
                        />
                      </div>

                      <div className="flex flex-col gap-1">
                        <span className="text-xs text-muted-foreground">Violation Message (optional)</span>
                        <Input value={rule.message} onChange={e => updateReplicaRule(i, 'message', e.target.value)}
                          placeholder={autoReplicaMessage(rule)} className="h-8 text-sm" />
                      </div>

                    </div>
                  ))}

                  {replicaRules.length > 1 && (
                    <p className="text-xs text-muted-foreground">
                      Each rule is evaluated independently — a request is denied if any rule fails.
                    </p>
                  )}

                  <p className="text-xs text-muted-foreground">
                    Applies to <span className="font-medium">apps/v1 Deployments</span> (CREATE/UPDATE) and <span className="font-medium">deployments/scale</span> (UPDATE).
                  </p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Right: YAML preview */}
          <Card className="overflow-hidden">
            <div className="flex items-center justify-between border-b px-4 py-3">
              <span className="text-sm font-medium">Generated YAML</span>
              <Badge variant="secondary" className="font-mono text-[10px]">ValidatingAdmissionPolicy</Badge>
            </div>
            <CardContent className="p-0">
              <pre className="min-h-[420px] overflow-auto rounded-b-lg bg-[#1e1e1e] p-4 font-mono text-xs leading-relaxed text-[#d4d4d4]">
                {previewYaml}
              </pre>
            </CardContent>
          </Card>
        </div>
      </>
    )
  }

  // ── Binding builder view ───────────────────────────────────────────────────
  if (showBindingBuilder) {
    const previewYaml = generateBindingYaml(bindingName, bindingPolicy, bindingNamespace, [...bindingActions])
    const canApply = bindingName.trim() !== '' && bindingPolicy.trim() !== '' && bindingActions.size > 0
    return (
      <>
        <div className="mb-6 flex items-center justify-between">
          <div>
            <h4 className="text-xl font-semibold">{bindingEditName ? 'Edit Binding' : 'New Binding'}</h4>
            <p className="text-sm text-muted-foreground">Bind a policy to a scope and choose validation actions.</p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => { setShowBindingBuilder(false); setBindingEditName(undefined); setBindingName(''); setBindingPolicy(''); setBindingNamespace(''); setBindingActions(new Set(['Deny'])) }}>← Back</Button>
            {isAdmin && (
              <Button onClick={handleBindingBuilderApply} disabled={!canApply || bindingBuilderSaving}>
                {bindingBuilderSaving ? 'Applying...' : 'Apply'}
              </Button>
            )}
          </div>
        </div>

        <div className="grid grid-cols-2 gap-6">
          {/* Left: form */}
          <Card>
            <CardContent className="flex flex-col gap-5 p-6">
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="binding-name">Binding Name</Label>
                <Input id="binding-name" value={bindingName} onChange={e => setBindingName(e.target.value)}
                  readOnly={!!bindingEditName} className={bindingEditName ? 'opacity-60 cursor-default' : ''} />
              </div>

              <div className="flex flex-col gap-1.5">
                <Label>Policy</Label>
                <Select value={bindingPolicy} onValueChange={setBindingPolicy} disabled={loading}>
                  <SelectTrigger>
                    <SelectValue placeholder={loading ? 'Loading...' : 'Select a policy...'} />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      {policies.map(p => (
                        <SelectItem key={p.name} value={p.name}>{p.name}</SelectItem>
                      ))}
                    </SelectGroup>
                  </SelectContent>
                </Select>
              </div>

              <div className="flex flex-col gap-1.5">
                <Label htmlFor="binding-ns">Namespace</Label>
                <Input id="binding-ns" value={bindingNamespace} onChange={e => setBindingNamespace(e.target.value)} placeholder="Leave empty to match all namespaces" />
                <p className="text-xs text-muted-foreground">
                  {bindingNamespace.trim()
                    ? `Applies to namespace: ${bindingNamespace.trim()}`
                    : 'No namespace filter — applies cluster-wide.'}
                </p>
              </div>

              <div className="flex flex-col gap-2">
                <Label>Validation Actions</Label>
                <div className="flex flex-col gap-2 rounded-lg border p-3">
                  {(['Deny', 'Audit', 'Warn'] as ValidationAction[]).map(a => (
                    <div key={a} className="flex items-center gap-2">
                      <Checkbox
                        id={`action-${a}`}
                        checked={bindingActions.has(a)}
                        onCheckedChange={() => toggleAction(a)}
                      />
                      <label htmlFor={`action-${a}`} className="cursor-pointer text-sm">
                        <span className="font-medium">{a}</span>
                        <span className="ml-2 text-xs text-muted-foreground">
                          {a === 'Deny'  && '— block the request'}
                          {a === 'Audit' && '— allow but record in audit log'}
                          {a === 'Warn'  && '— allow but return a warning'}
                        </span>
                      </label>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Right: YAML preview */}
          <Card className="overflow-hidden">
            <div className="flex items-center justify-between border-b px-4 py-3">
              <span className="text-sm font-medium">Generated YAML</span>
              <Badge variant="secondary" className="font-mono text-[10px]">ValidatingAdmissionPolicyBinding</Badge>
            </div>
            <CardContent className="p-0">
              <pre className="min-h-[420px] overflow-auto rounded-b-lg bg-[#1e1e1e] p-4 font-mono text-xs leading-relaxed text-[#d4d4d4]">
                {previewYaml}
              </pre>
            </CardContent>
          </Card>
        </div>
      </>
    )
  }

  // ── YAML editor view ───────────────────────────────────────────────────────
  if (editor) {
    const title = editor.name
      ? `${isAdmin ? 'Edit' : 'View'} ${editor.kind === 'policy' ? 'Policy' : 'Binding'}`
      : `New ${editor.kind === 'policy' ? 'Policy' : 'Binding'}`
    return (
      <>
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h4 className="text-xl font-semibold">{title}</h4>
            {editor.name && <p className="text-sm text-muted-foreground">{editor.name}</p>}
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" onClick={() => setEditor(null)}>← Back</Button>
            {isAdmin && (
              <Button onClick={handleSave} disabled={!editorValid || saving}>
                {saving ? 'Applying...' : 'Apply'}
              </Button>
            )}
          </div>
        </div>
        <YamlEditor
          key={editorKey}
          initialValue={editorYaml}
          readOnly={!isAdmin}
          onValueChange={(v, valid) => { setEditorYaml(v); setEditorValid(valid) }}
        />
      </>
    )
  }

  // ── List view ──────────────────────────────────────────────────────────────
  return (
    <>
      <div className="mb-6">
        <h4 className="text-xl font-semibold">Admission Policy</h4>
        <p className="text-sm text-muted-foreground">Manage Kubernetes ValidatingAdmissionPolicies and Bindings.</p>
      </div>

      <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as 'policies' | 'bindings')}>
        <TabsList variant="line" className="mb-4 w-full justify-start rounded-none border-b bg-transparent p-0">
          <TabsTrigger value="policies"
            className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent data-[state=active]:shadow-none">
            Policies
          </TabsTrigger>
          <TabsTrigger value="bindings"
            className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent data-[state=active]:shadow-none">
            Bindings
          </TabsTrigger>
        </TabsList>

        {/* Policies Tab */}
        <TabsContent value="policies">
          <div className="mb-4 flex items-center justify-between">
            <Input placeholder="Search by name..." value={search} onChange={e => setSearch(e.target.value)} className="h-8 w-56 text-sm" />
            {isAdmin && (
              <div className="flex gap-2">
                <Button size="sm" onClick={() => setShowBuilder(true)}>+ New Policy</Button>
                <Button size="sm" variant="outline" onClick={() => openNew('policy')}>+ New YAML</Button>
              </div>
            )}
          </div>
          <Card>
            <CardContent className="p-0">
              {loading ? (
                <div className="flex flex-col gap-2 p-4">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Failure Policy</TableHead>
                      <TableHead>Validations</TableHead>
                      <TableHead>Created By</TableHead>
                      <TableHead>Created Time</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {policies.filter(p => !search || p.name.toLowerCase().includes(search.toLowerCase())).length === 0 ? (
                      <TableRow><TableCell colSpan={7} className="py-10 text-center text-muted-foreground">No policies found</TableCell></TableRow>
                    ) : policies.filter(p => !search || p.name.toLowerCase().includes(search.toLowerCase())).map(p => (
                      <TableRow key={p.name}>
                        <TableCell className="font-medium">{p.name}</TableCell>
                        <TableCell>
                          <Badge variant={p.failurePolicy === 'Fail' ? 'destructive' : 'secondary'}>{p.failurePolicy || '—'}</Badge>
                        </TableCell>
                        <TableCell className="text-muted-foreground">{p.validationCount}</TableCell>
                        <TableCell className="text-muted-foreground text-xs">{p.createdBy}</TableCell>
                        <TableCell className="text-muted-foreground">{formatTWTime(p.createdAt)}</TableCell>
                        <TableCell className="text-right">
                          <div className="flex justify-end gap-2">
                            <Button variant="outline" size="sm" onClick={() => openEdit('policy', p.name, p.rawYaml)}>{isAdmin ? 'Edit' : 'View YAML'}</Button>
                            {isAdmin && <Button variant="destructive" size="sm" onClick={() => setDeleteTarget({ kind: 'policy', name: p.name })}>Delete</Button>}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Bindings Tab */}
        <TabsContent value="bindings">
          <div className="mb-4 flex items-center justify-between">
            <Input placeholder="Search by name..." value={search} onChange={e => setSearch(e.target.value)} className="h-8 w-56 text-sm" />
            {isAdmin && (
              <div className="flex gap-2">
                <Button size="sm" onClick={() => setShowBindingBuilder(true)}>+ New Binding</Button>
                <Button size="sm" variant="outline" onClick={() => openNew('binding')}>+ New YAML</Button>
              </div>
            )}
          </div>
          <Card>
            <CardContent className="p-0">
              {loading ? (
                <div className="flex flex-col gap-2 p-4">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Policy</TableHead>
                      <TableHead>Validation Actions</TableHead>
                      <TableHead>Created By</TableHead>
                      <TableHead>Created Time</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {bindings.filter(b => !search || b.name.toLowerCase().includes(search.toLowerCase())).length === 0 ? (
                      <TableRow><TableCell colSpan={7} className="py-10 text-center text-muted-foreground">No bindings found</TableCell></TableRow>
                    ) : bindings.filter(b => !search || b.name.toLowerCase().includes(search.toLowerCase())).map(b => (
                      <TableRow key={b.name}>
                        <TableCell className="font-medium">{b.name}</TableCell>
                        <TableCell className="text-muted-foreground">{b.policyName}</TableCell>
                        <TableCell>
                          <div className="flex gap-1 flex-wrap">
                            {b.validationActions.map(a => (
                              <Badge key={a} variant={a === 'Deny' ? 'destructive' : 'secondary'} className="text-[10px]">{a}</Badge>
                            ))}
                          </div>
                        </TableCell>
                        <TableCell className="text-muted-foreground text-xs">{b.createdBy}</TableCell>
                        <TableCell className="text-muted-foreground">{formatTWTime(b.createdAt)}</TableCell>
                        <TableCell className="text-right">
                          <div className="flex justify-end gap-2">
                            <Button variant="outline" size="sm" onClick={() => openEdit('binding', b.name, b.rawYaml)}>{isAdmin ? 'Edit' : 'View YAML'}</Button>
                            {isAdmin && <Button variant="destructive" size="sm" onClick={() => setDeleteTarget({ kind: 'binding', name: b.name })}>Delete</Button>}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <AlertDialog open={!!deleteTarget} onOpenChange={open => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete {deleteTarget?.kind === 'policy' ? 'Policy' : 'Binding'}</AlertDialogTitle>
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
