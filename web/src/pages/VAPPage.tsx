import { useCallback, useEffect, useState } from 'react'
import {
  IconTag, IconNotes, IconBrandDocker, IconCopy, IconCpu,
  IconShieldLock, IconServer,
} from '@tabler/icons-react'
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
type PolicyRuleType = 'label' | 'annotation' | 'image' | 'replica' | 'resource-limits' | 'security-context' | 'host-access'
type ImagePolicyType = 'no-latest' | 'required-registry'
type ResourceLimitType = 'cpu' | 'memory' | 'both'
type LabelApplyTo =
  | 'all' | 'workloads'
  | 'pods' | 'deployments' | 'statefulsets' | 'daemonsets' | 'jobs' | 'cronjobs'
  | 'configmaps' | 'secrets' | 'persistentvolumeclaims' | 'services'
  | 'ingresses' | 'networkpolicies' | 'serviceaccounts'
  | 'namespaces'

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

type ReplicaResourceType = 'deployments' | 'statefulsets' | 'both'

interface ReplicaRule {
  maxReplicas: number
  resourceType: ReplicaResourceType
  message: string
}

interface ResourceLimitRule {
  limitType: ResourceLimitType
  message: string
}

type SecurityContextCheckType = 'no-privileged' | 'run-as-non-root' | 'both'

interface SecurityContextRule {
  checkType: SecurityContextCheckType
  message: string
}

const emptyRule = (): LabelRule => ({ key: '', condition: '==', value: '', message: '' })
const emptyImageRule = (): ImageRule => ({ type: 'no-latest', registry: '', message: '' })
const emptyReplicaRule = (): ReplicaRule => ({ maxReplicas: 5, resourceType: 'deployments', message: '' })
const emptyResourceLimitRule = (): ResourceLimitRule => ({ limitType: 'both', message: '' })
const emptySecurityContextRule = (): SecurityContextRule => ({ checkType: 'no-privileged', message: '' })

type HostAccessCheckType = 'no-host-network' | 'no-host-pid' | 'no-host-ipc' | 'all'

interface HostAccessRule {
  checkType: HostAccessCheckType
  message: string
}

const emptyHostAccessRule = (): HostAccessRule => ({ checkType: 'all', message: '' })

// Policy builder ---------------------------------------------------------------

function applyToResourceRuleLines(applyTo: LabelApplyTo): string[] {
  const core = (resources: string) => [
    '      - apiGroups: [""]', '        apiVersions: ["v1"]',
    '        operations: [CREATE, UPDATE]', `        resources: ["${resources}"]`,
  ]
  const apps = (resources: string) => [
    '      - apiGroups: ["apps"]', '        apiVersions: ["v1"]',
    '        operations: [CREATE, UPDATE]', `        resources: [${resources}]`,
  ]
  const batch = (resources: string) => [
    '      - apiGroups: ["batch"]', '        apiVersions: ["v1"]',
    '        operations: [CREATE, UPDATE]', `        resources: [${resources}]`,
  ]
  const networking = (resources: string) => [
    '      - apiGroups: ["networking.k8s.io"]', '        apiVersions: ["v1"]',
    '        operations: [CREATE, UPDATE]', `        resources: ["${resources}"]`,
  ]
  const prefix = '    resourceRules:'
  switch (applyTo) {
    case 'workloads': return [prefix, ...core('pods'), ...apps('"deployments", "statefulsets", "daemonsets", "replicasets"'), ...batch('"jobs", "cronjobs"')]
    case 'pods':                    return [prefix, ...core('pods')]
    case 'deployments':             return [prefix, ...apps('"deployments"')]
    case 'statefulsets':            return [prefix, ...apps('"statefulsets"')]
    case 'daemonsets':              return [prefix, ...apps('"daemonsets"')]
    case 'jobs':                    return [prefix, ...batch('"jobs"')]
    case 'cronjobs':                return [prefix, ...batch('"cronjobs"')]
    case 'configmaps':              return [prefix, ...core('configmaps')]
    case 'secrets':                 return [prefix, ...core('secrets')]
    case 'persistentvolumeclaims':  return [prefix, ...core('persistentvolumeclaims')]
    case 'services':                return [prefix, ...core('services')]
    case 'serviceaccounts':         return [prefix, ...core('serviceaccounts')]
    case 'ingresses':               return [prefix, ...networking('ingresses')]
    case 'networkpolicies':         return [prefix, ...networking('networkpolicies')]
    case 'namespaces':              return [prefix, ...core('namespaces')]
    default: return [prefix, '      - apiGroups: ["*"]', '        apiVersions: ["*"]', '        operations: [CREATE, UPDATE]', '        resources: ["*"]']
  }
}

function escapeYaml(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r').replace(/\t/g, '\\t')
}

function escapeCel(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/'/g, "\\'")
}

function buildAutoMessage(kind: 'label' | 'annotation', key: string, cond: LabelCondition, value: string): string {
  if (!key.trim() || !value.trim()) return `${kind === 'label' ? 'Label' : 'Annotation'} policy validation failed`
  return cond === '=='
    ? `Resources with ${kind} ${key}=${value} are not allowed`
    : `Resources must have ${kind} ${key}=${value}`
}

function autoMessage(key: string, cond: LabelCondition, value: string): string {
  return buildAutoMessage('label', key, cond, value)
}

function ruleToYamlLines(rule: LabelRule): string[] {
  const k = escapeCel(rule.key.trim()   || 'app')
  const v = escapeCel(rule.value.trim() || 'value')
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

function autoAnnotationMessage(key: string, cond: LabelCondition, value: string): string {
  return buildAutoMessage('annotation', key, cond, value)
}

function annotationRuleToYamlLines(rule: LabelRule): string[] {
  const k = escapeCel(rule.key.trim()   || 'app')
  const v = escapeCel(rule.value.trim() || 'value')
  const m = rule.message.trim() || autoAnnotationMessage(rule.key, rule.condition, rule.value)
  const exprLines = rule.condition === '=='
    ? [
        '        !has(object.metadata.annotations) ||',
        `        !('${k}' in object.metadata.annotations) ||`,
        `        object.metadata.annotations['${k}'] != '${v}'`,
      ]
    : [
        '        has(object.metadata.annotations) &&',
        `        '${k}' in object.metadata.annotations &&`,
        `        object.metadata.annotations['${k}'] == '${v}'`,
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
  const regRaw = rule.registry.trim() || 'registry.example.com'
  // Ensure trailing slash to prevent subdomain bypass (registry.example.com.evil.io would
  // pass a startsWith('registry.example.com') check without the slash).
  const reg = escapeCel(regRaw.endsWith('/') ? regRaw : `${regRaw}/`)
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

function autoHostAccessMessage(rule: HostAccessRule): string {
  if (rule.checkType === 'no-host-network') return 'hostNetwork is not allowed'
  if (rule.checkType === 'no-host-pid') return 'hostPID is not allowed'
  if (rule.checkType === 'no-host-ipc') return 'hostIPC is not allowed'
  return 'hostNetwork, hostPID, and hostIPC are not allowed'
}

function hostAccessRuleToYamlLines(rule: HostAccessRule): string[] {
  const m = escapeYaml(rule.message.trim() || autoHostAccessMessage(rule))
  const noNet = rule.checkType === 'no-host-network' || rule.checkType === 'all'
  const noPid = rule.checkType === 'no-host-pid'     || rule.checkType === 'all'
  const noIpc = rule.checkType === 'no-host-ipc'     || rule.checkType === 'all'

  // Check all three nesting paths: Pod (spec), template-based (spec.template.spec),
  // and CronJob (spec.jobTemplate.spec.template.spec).
  function pathCheck(field: string): string {
    return [
      `!object.spec.?${field}.orValue(false)`,
      `!object.spec.?template.?spec.?${field}.orValue(false)`,
      `!object.spec.?jobTemplate.?spec.?template.?spec.?${field}.orValue(false)`,
    ].join(' && ')
  }

  const parts: string[] = []
  if (noNet) parts.push(pathCheck('hostNetwork'))
  if (noPid) parts.push(pathCheck('hostPID'))
  if (noIpc) parts.push(pathCheck('hostIPC'))
  const expr = parts.join(' && ')
  return [
    '    - expression: >-',
    `        ${expr}`,
    `      message: "${m}"`,
    '      reason: Forbidden',
  ]
}

function autoSecurityContextMessage(rule: SecurityContextRule): string {
  if (rule.checkType === 'no-privileged') return 'Privileged containers are not allowed'
  if (rule.checkType === 'run-as-non-root') return 'Workloads must set runAsNonRoot: true in pod securityContext'
  return 'Containers must not be privileged and must run as non-root'
}

function securityContextRuleToYamlLines(rule: SecurityContextRule): string[] {
  const lines: string[] = []
  const m = escapeYaml(rule.message.trim() || autoSecurityContextMessage(rule))
  const noPriv = rule.checkType === 'no-privileged' || rule.checkType === 'both'
  const nonRoot = rule.checkType === 'run-as-non-root' || rule.checkType === 'both'
  if (noPriv) {
    const check = `all(c, !has(c.securityContext) || !has(c.securityContext.privileged) || c.securityContext.privileged == false)`
    lines.push(
      '    - expression: >-',
      `        object.spec.?containers.orValue([]).${check} &&`,
      `        object.spec.?initContainers.orValue([]).${check} &&`,
      `        object.spec.?template.?spec.?containers.orValue([]).${check} &&`,
      `        object.spec.?template.?spec.?initContainers.orValue([]).${check} &&`,
      `        object.spec.?jobTemplate.?spec.?template.?spec.?containers.orValue([]).${check} &&`,
      `        object.spec.?jobTemplate.?spec.?template.?spec.?initContainers.orValue([]).${check}`,
      `      message: "${m}"`,
      '      reason: Forbidden',
    )
  }
  if (nonRoot) {
    // Use nested orValue to model K8s inheritance: container-level overrides pod-level.
    // c.?securityContext.?runAsNonRoot.orValue(podDefault) — if container sets the field,
    // use it; otherwise fall back to the pod/template securityContext value.
    const podCheck   = `all(c, c.?securityContext.?runAsNonRoot.orValue(object.spec.?securityContext.?runAsNonRoot.orValue(false)) == true)`
    const tmplCheck  = `all(c, c.?securityContext.?runAsNonRoot.orValue(object.spec.?template.?spec.?securityContext.?runAsNonRoot.orValue(false)) == true)`
    const jobCheck   = `all(c, c.?securityContext.?runAsNonRoot.orValue(object.spec.?jobTemplate.?spec.?template.?spec.?securityContext.?runAsNonRoot.orValue(false)) == true)`
    lines.push(
      '    - expression: >-',
      `        object.spec.?containers.orValue([]).${podCheck} &&`,
      `        object.spec.?initContainers.orValue([]).${podCheck} &&`,
      `        object.spec.?template.?spec.?containers.orValue([]).${tmplCheck} &&`,
      `        object.spec.?template.?spec.?initContainers.orValue([]).${tmplCheck} &&`,
      `        object.spec.?jobTemplate.?spec.?template.?spec.?containers.orValue([]).${jobCheck} &&`,
      `        object.spec.?jobTemplate.?spec.?template.?spec.?initContainers.orValue([]).${jobCheck}`,
      `      message: "${m}"`,
      '      reason: Forbidden',
    )
  }
  return lines
}

function autoResourceLimitMessage(rule: ResourceLimitRule): string {
  return rule.limitType === 'cpu'
    ? 'All containers must set CPU limits'
    : rule.limitType === 'memory'
    ? 'All containers must set memory limits'
    : 'All containers must set CPU and memory limits'
}

function resourceLimitRuleToYamlLines(rule: ResourceLimitRule): string[] {
  const m = escapeYaml(rule.message.trim() || autoResourceLimitMessage(rule))
  const check = rule.limitType === 'cpu'
    ? `all(c, has(c.resources) && has(c.resources.limits) && has(c.resources.limits.cpu))`
    : rule.limitType === 'memory'
    ? `all(c, has(c.resources) && has(c.resources.limits) && has(c.resources.limits.memory))`
    : `all(c, has(c.resources) && has(c.resources.limits) && has(c.resources.limits.cpu) && has(c.resources.limits.memory))`
  return [
    '    - expression: >-',
    `        object.spec.?containers.orValue([]).${check} &&`,
    `        object.spec.?initContainers.orValue([]).${check} &&`,
    `        object.spec.?template.?spec.?containers.orValue([]).${check} &&`,
    `        object.spec.?template.?spec.?initContainers.orValue([]).${check} &&`,
    `        object.spec.?jobTemplate.?spec.?template.?spec.?containers.orValue([]).${check} &&`,
    `        object.spec.?jobTemplate.?spec.?template.?spec.?initContainers.orValue([]).${check}`,
    `      message: "${m}"`,
    '      reason: Forbidden',
  ]
}

function autoReplicaMessage(rule: ReplicaRule): string {
  const max = rule.maxReplicas > 0 ? rule.maxReplicas : 5
  const label = rule.resourceType === 'statefulsets' ? 'StatefulSet'
    : rule.resourceType === 'both' ? 'Workload'
    : 'Deployment'
  return `${label} replicas must not exceed ${max}`
}

function replicaRuleToYamlLines(rule: ReplicaRule): string[] {
  const max = rule.maxReplicas > 0 ? rule.maxReplicas : 5
  const m = escapeYaml(rule.message.trim() || autoReplicaMessage(rule))
  // Use kind guard so multiple rules with different types can coexist
  // in the same policy with shared matchConstraints.
  const expr = rule.resourceType === 'deployments'
    ? `object.kind != 'Deployment' || object.spec.replicas <= ${max}`
    : rule.resourceType === 'statefulsets'
    ? `object.kind != 'StatefulSet' || object.spec.replicas <= ${max}`
    : `object.spec.replicas <= ${max}`
  return [
    `    - expression: "${expr}"`,
    `      message: "${m}"`,
    '      reason: Forbidden',
  ]
}

function generatePolicyYaml(
  name: string, ruleType: PolicyRuleType, labelRules: LabelRule[], imageRules: ImageRule[],
  replicaRules: ReplicaRule[], applyTo: LabelApplyTo = 'all',
  resourceLimitRules: ResourceLimitRule[] = [],
  securityContextRule: SecurityContextRule = emptySecurityContextRule(),
  hostAccessRule: HostAccessRule = emptyHostAccessRule(),
): string {
  const safeName = name.trim() || 'my-policy'
  let validationLines: string[]
  if (ruleType === 'label') {
    const active = labelRules.filter(r => r.key.trim() && r.value.trim())
    validationLines = active.length ? active.flatMap(ruleToYamlLines) : ruleToYamlLines(emptyRule())
  } else if (ruleType === 'annotation') {
    const active = labelRules.filter(r => r.key.trim() && r.value.trim())
    validationLines = active.length ? active.flatMap(annotationRuleToYamlLines) : annotationRuleToYamlLines(emptyRule())
  } else if (ruleType === 'image') {
    const active = imageRules.filter(r => r.type === 'no-latest' || r.registry.trim())
    validationLines = active.length ? active.flatMap(imageRuleToYamlLines) : imageRuleToYamlLines(emptyImageRule())
  } else if (ruleType === 'resource-limits') {
    validationLines = resourceLimitRules.length ? resourceLimitRules.flatMap(resourceLimitRuleToYamlLines) : resourceLimitRuleToYamlLines(emptyResourceLimitRule())
  } else if (ruleType === 'security-context') {
    validationLines = securityContextRuleToYamlLines(securityContextRule)
  } else if (ruleType === 'host-access') {
    validationLines = hostAccessRuleToYamlLines(hostAccessRule)
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
        '      resources: ["deployments", "statefulsets"]',
        '    - apiGroups: ["apps"]',
        '      apiVersions: ["v1"]',
        '      operations: [UPDATE]',
        '      resources: ["deployments/scale", "statefulsets/scale"]',
      ]
    : (ruleType === 'image' || ruleType === 'resource-limits' || ruleType === 'security-context' || ruleType === 'host-access')
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
    : applyToResourceRuleLines(applyTo)

  const applyToAnnotation = (ruleType === 'label' || ruleType === 'annotation')
    ? [`    sentinel.io/apply-to: "${applyTo}"`]
    : []

  return [
    'apiVersion: admissionregistration.k8s.io/v1',
    'kind: ValidatingAdmissionPolicy',
    'metadata:',
    `  name: "${safeName}"`,
    '  annotations:',
    '    sentinel.io/builder: "true"',
    ...applyToAnnotation,
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
  const e = expr.replace(/\s+/g, ' ').trim()
  let m = e.match(/^object\.kind != 'Deployment' \|\| object\.spec\.replicas <= (\d+)$/)
  if (m) return { maxReplicas: parseInt(m[1], 10), resourceType: 'deployments', message: msg }
  m = e.match(/^object\.kind != 'StatefulSet' \|\| object\.spec\.replicas <= (\d+)$/)
  if (m) return { maxReplicas: parseInt(m[1], 10), resourceType: 'statefulsets', message: msg }
  m = e.match(/^object\.spec\.replicas\s*<=\s*(\d+)$/)
  if (m) return { maxReplicas: parseInt(m[1], 10), resourceType: 'both', message: msg }
  return null
}

function parseExpressionToAnnotationRule(expr: string, msg: string): LabelRule | null {
  const e = expr.replace(/\s+/g, ' ').trim()
  let m = e.match(/!\('([^']+)' in object\.metadata\.annotations\).*object\.metadata\.annotations\['[^']+'\] != '([^']+)'/)
  if (m) return { key: m[1], condition: '==', value: m[2], message: msg }
  m = e.match(/'([^']+)' in object\.metadata\.annotations.*object\.metadata\.annotations\['[^']+'\] == '([^']+)'/)
  if (m) return { key: m[1], condition: '!=', value: m[2], message: msg }
  return null
}

function parseExpressionToResourceLimitRule(expr: string, msg: string): ResourceLimitRule | null {
  const e = expr.replace(/\s+/g, ' ').trim()
  if (!e.includes('has(c.resources.limits')) return null
  const hasCpu = e.includes('has(c.resources.limits.cpu)')
  const hasMem = e.includes('has(c.resources.limits.memory)')
  if (hasCpu && hasMem) return { limitType: 'both', message: msg }
  if (hasCpu) return { limitType: 'cpu', message: msg }
  if (hasMem) return { limitType: 'memory', message: msg }
  return null
}

type SecurityContextPart = 'no-privileged' | 'run-as-non-root'
function parseExpressionToSecurityContextPart(expr: string): SecurityContextPart | null {
  const e = expr.replace(/\s+/g, ' ').trim()
  if (e.includes('c.securityContext.privileged == false')) return 'no-privileged'
  if (e.includes('c.?securityContext.?runAsNonRoot.orValue(')) return 'run-as-non-root'
  return null
}

function parseExpressionToHostAccessPart(expr: string): HostAccessCheckType | null {
  const e = expr.replace(/\s+/g, ' ').trim()
  const hasNet = e.includes('hostNetwork')
  const hasPid = e.includes('hostPID')
  const hasIpc = e.includes('hostIPC')
  // Only accept expressions that match exactly one of the four generated shapes.
  // Partial combinations (e.g. hasNet && hasPid && !hasIpc) come from hand-edited
  // YAML — silently losing those constraints would corrupt the policy on re-save,
  // so fall through to the YAML editor instead.
  if (hasNet && hasPid && hasIpc) return 'all'
  if (hasNet && !hasPid && !hasIpc) return 'no-host-network'
  if (!hasNet && hasPid && !hasIpc) return 'no-host-pid'
  if (!hasNet && !hasPid && hasIpc) return 'no-host-ipc'
  return null
}

function tryParseBuilderPolicy(rawYaml: string): {
  name: string; ruleType: PolicyRuleType; applyTo: LabelApplyTo
  labelRules: LabelRule[]; imageRules: ImageRule[]; replicaRules: ReplicaRule[]
  resourceLimitRules: ResourceLimitRule[]; securityContextRule: SecurityContextRule
  hostAccessRule: HostAccessRule
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
    const annotationRules: LabelRule[] = []
    const resourceLimitRules: ResourceLimitRule[] = []
    const scParts: { part: SecurityContextPart; message: string }[] = []
    let hostAccessParsed: HostAccessRule | null = null
    for (const v of spec.validations) {
      const lr = parseExpressionToRule(v.expression ?? '', v.message ?? '')
      if (lr) { labelRules.push(lr); continue }
      const ar = parseExpressionToAnnotationRule(v.expression ?? '', v.message ?? '')
      if (ar) { annotationRules.push(ar); continue }
      const ir = parseExpressionToImageRule(v.expression ?? '', v.message ?? '')
      if (ir) { imageRules.push(ir); continue }
      const rr = parseExpressionToReplicaRule(v.expression ?? '', v.message ?? '')
      if (rr) { replicaRules.push(rr); continue }
      const rlr = parseExpressionToResourceLimitRule(v.expression ?? '', v.message ?? '')
      if (rlr) { resourceLimitRules.push(rlr); continue }
      const scp = parseExpressionToSecurityContextPart(v.expression ?? '')
      if (scp) { scParts.push({ part: scp, message: v.message ?? '' }); continue }
      const hap = parseExpressionToHostAccessPart(v.expression ?? '')
      if (hap) { hostAccessParsed = { checkType: hap, message: v.message ?? '' }; continue }
      return null  // unknown expression type — fall through to YAML editor
    }
    // Build security context rule from parts
    const hasNoPriv = scParts.some(p => p.part === 'no-privileged')
    const hasNonRoot = scParts.some(p => p.part === 'run-as-non-root')
    const checkType: SecurityContextCheckType = hasNoPriv && hasNonRoot ? 'both'
      : hasNonRoot ? 'run-as-non-root' : 'no-privileged'
    const securityContextRule: SecurityContextRule = {
      checkType,
      message: scParts[0]?.message ?? '',
    }
    const hostAccessRule: HostAccessRule = hostAccessParsed ?? emptyHostAccessRule()
    // All rules must be the same type
    const typesUsed = [labelRules.length > 0, annotationRules.length > 0, imageRules.length > 0, replicaRules.length > 0, resourceLimitRules.length > 0, scParts.length > 0, hostAccessParsed !== null].filter(Boolean).length
    if (typesUsed > 1) return null
    const ruleType: PolicyRuleType = replicaRules.length > 0 ? 'replica'
      : imageRules.length > 0 ? 'image'
      : annotationRules.length > 0 ? 'annotation'
      : resourceLimitRules.length > 0 ? 'resource-limits'
      : scParts.length > 0 ? 'security-context'
      : hostAccessParsed !== null ? 'host-access'
      : 'label'
    const applyTo = (meta?.annotations?.['sentinel.io/apply-to'] as LabelApplyTo | undefined) || 'workloads'
    return { name: meta?.name ?? '', ruleType, applyTo, labelRules: annotationRules.length > 0 ? annotationRules : labelRules, imageRules, replicaRules, resourceLimitRules, securityContextRule, hostAccessRule }
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

const _vapCache = { loaded: false }

export function VAPPage() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const toast = useToast()

  const [policies, setPolicies] = useState<VAPRecord[]>([])
  const [bindings, setBindings] = useState<VAPBindingRecord[]>([])
  const [loading, setLoading] = useState(!_vapCache.loaded)
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
  const [builderApplyTo, setBuilderApplyTo] = useState<LabelApplyTo>('workloads')
  const [labelRules, setLabelRules] = useState<LabelRule[]>([emptyRule()])
  const [imageRules, setImageRules] = useState<ImageRule[]>([emptyImageRule()])
  const [replicaRules, setReplicaRules] = useState<ReplicaRule[]>([emptyReplicaRule()])
  const [resourceLimitRules, setResourceLimitRules] = useState<ResourceLimitRule[]>([emptyResourceLimitRule()])
  const [securityContextRule, setSecurityContextRule] = useState<SecurityContextRule>(emptySecurityContextRule())
  const [hostAccessRule, setHostAccessRule] = useState<HostAccessRule>(emptyHostAccessRule())
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


  const updateResourceLimitRule = (i: number, field: keyof ResourceLimitRule, val: string) =>
    setResourceLimitRules(prev => prev.map((r, idx) => idx === i ? { ...r, [field]: val } : r))


  const resetBuilderForm = () => {
    setBuilderEditName(undefined)
    setBuilderName('')
    setBuilderRuleType('label')
    setBuilderApplyTo('workloads')
    setLabelRules([emptyRule()])
    setImageRules([emptyImageRule()])
    setReplicaRules([emptyReplicaRule()])
    setResourceLimitRules([emptyResourceLimitRule()])
    setSecurityContextRule(emptySecurityContextRule())
    setHostAccessRule(emptyHostAccessRule())
  }

  // Binding builder state
  const [showBindingBuilder, setShowBindingBuilder] = useState(false)
  const [bindingEditName, setBindingEditName] = useState<string | undefined>()
  const [bindingName, setBindingName] = useState('')
  const [bindingPolicy, setBindingPolicy] = useState('')
  const [bindingNamespace, setBindingNamespace] = useState('')
  const [bindingActions, setBindingActions] = useState<Set<ValidationAction>>(new Set(['Deny']))
  const [bindingBuilderSaving, setBindingBuilderSaving] = useState(false)

  const load = useCallback(async (showSpinner = false) => {
    if (showSpinner) setLoading(true)
    try {
      const [p, b] = await Promise.all([vapApi.listPolicies(), vapApi.listBindings()])
      setPolicies(p)
      setBindings(b)
      _vapCache.loaded = true
    } catch { /* ignore */ }
    finally { setLoading(false) }
  }, [])

  // Show spinner only on first load; subsequent navigations silently refresh in background
  useEffect(() => { load(!_vapCache.loaded) }, [load])

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
        setBuilderApplyTo(parsed.applyTo)
        setLabelRules(parsed.labelRules.length ? parsed.labelRules : [emptyRule()])
        setImageRules(parsed.imageRules.length ? parsed.imageRules : [emptyImageRule()])
        setReplicaRules(parsed.replicaRules.length ? parsed.replicaRules : [emptyReplicaRule()])
        setResourceLimitRules(parsed.resourceLimitRules.length ? parsed.resourceLimitRules : [emptyResourceLimitRule()])
        setSecurityContextRule(parsed.securityContextRule)
        setHostAccessRule(parsed.hostAccessRule)
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
    const rulesOk = (builderRuleType === 'label' || builderRuleType === 'annotation')
      ? labelRules.some(r => r.key.trim() && r.value.trim())
      : builderRuleType === 'image'
      ? imageRules.some(r => r.type === 'no-latest' || r.registry.trim())
      : builderRuleType === 'resource-limits'
      ? true
      : (builderRuleType === 'security-context' || builderRuleType === 'host-access')
      ? true
      : replicaRules.some(r => r.maxReplicas > 0)
    if (!nameOk || !rulesOk) return
    setBuilderSaving(true)
    try {
      const y = generatePolicyYaml(builderName, builderRuleType, labelRules, imageRules, replicaRules, builderApplyTo, resourceLimitRules, securityContextRule, hostAccessRule)
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
    const previewYaml = generatePolicyYaml(builderName, builderRuleType, labelRules, imageRules, replicaRules, builderApplyTo, resourceLimitRules, securityContextRule, hostAccessRule)
    const rulesOk = (builderRuleType === 'label' || builderRuleType === 'annotation')
      ? labelRules.some(r => r.key.trim() && r.value.trim())
      : builderRuleType === 'image'
      ? imageRules.some(r => r.type === 'no-latest' || r.registry.trim())
      : builderRuleType === 'resource-limits'
      ? true
      : (builderRuleType === 'security-context' || builderRuleType === 'host-access')
      ? true
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
                {builderEditName ? (
                  <div className="flex h-9 items-center rounded-md border bg-muted/40 px-3 text-sm text-muted-foreground opacity-60">
                    {([
                      { value: 'label', label: 'Label Check' },
                      { value: 'annotation', label: 'Annotation Check' },
                      { value: 'image', label: 'Image Policy' },
                      { value: 'replica', label: 'Replica Limit' },
                      { value: 'resource-limits', label: 'Resource Limits' },
                      { value: 'security-context', label: 'Security Context' },
                      { value: 'host-access', label: 'Host Access' },
                    ] as { value: PolicyRuleType; label: string }[]).find(t => t.value === builderRuleType)?.label}
                  </div>
                ) : (
                  <div className="grid grid-cols-4 gap-2">
                    {([
                      { value: 'label',            icon: <IconTag size={20} />,          label: 'Label',      desc: 'Label key=value check' },
                      { value: 'annotation',        icon: <IconNotes size={20} />,        label: 'Annotation', desc: 'Annotation key=value check' },
                      { value: 'image',             icon: <IconBrandDocker size={20} />,  label: 'Image',      desc: 'Registry & tag policy' },
                      { value: 'replica',           icon: <IconCopy size={20} />,         label: 'Replica',    desc: 'Max replica count' },
                      { value: 'resource-limits',   icon: <IconCpu size={20} />,          label: 'Resources',  desc: 'CPU / memory limits' },
                      { value: 'security-context',  icon: <IconShieldLock size={20} />,   label: 'Security',   desc: 'Privileged & non-root' },
                      { value: 'host-access',       icon: <IconServer size={20} />,       label: 'Host',       desc: 'hostNetwork / PID / IPC' },
                    ] as { value: PolicyRuleType; icon: React.ReactNode; label: string; desc: string }[]).map(t => (
                      <button
                        key={t.value}
                        type="button"
                        onClick={() => {
                          setBuilderRuleType(t.value)
                          setLabelRules([emptyRule()])
                          setImageRules([emptyImageRule()])
                          setReplicaRules([emptyReplicaRule()])
                          setResourceLimitRules([emptyResourceLimitRule()])
                          setSecurityContextRule(emptySecurityContextRule())
                          setHostAccessRule(emptyHostAccessRule())
                        }}
                        className={[
                          'flex flex-col items-center gap-1.5 rounded-lg border p-3 text-center transition-colors',
                          builderRuleType === t.value
                            ? 'border-primary bg-primary/5 text-primary'
                            : 'border-border hover:border-primary/40 hover:bg-muted/40 text-muted-foreground',
                        ].join(' ')}
                      >
                        <span className={builderRuleType === t.value ? 'text-primary' : 'text-muted-foreground'}>
                          {t.icon}
                        </span>
                        <span className="text-xs font-medium leading-tight">{t.label}</span>
                        <span className="text-[10px] leading-tight opacity-70">{t.desc}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {/* ── Apply To (label / annotation only) ── */}
              {(builderRuleType === 'label' || builderRuleType === 'annotation') && (
                <div className="flex flex-col gap-1.5">
                  <Label>Apply To</Label>
                  <Select value={builderApplyTo} onValueChange={v => setBuilderApplyTo(v as LabelApplyTo)}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        <SelectItem value="workloads">All Workloads (Pods, Deployments, StatefulSets, DaemonSets, Jobs, CronJobs)</SelectItem>
                        <SelectItem value="pods">Pods</SelectItem>
                        <SelectItem value="deployments">Deployments</SelectItem>
                        <SelectItem value="statefulsets">StatefulSets</SelectItem>
                        <SelectItem value="daemonsets">DaemonSets</SelectItem>
                        <SelectItem value="jobs">Jobs</SelectItem>
                        <SelectItem value="cronjobs">CronJobs</SelectItem>
                        <SelectItem value="configmaps">ConfigMaps</SelectItem>
                        <SelectItem value="secrets">Secrets</SelectItem>
                        <SelectItem value="persistentvolumeclaims">PersistentVolumeClaims (PVC)</SelectItem>
                        <SelectItem value="services">Services</SelectItem>
                        <SelectItem value="serviceaccounts">ServiceAccounts</SelectItem>
                        <SelectItem value="ingresses">Ingresses</SelectItem>
                        <SelectItem value="networkpolicies">NetworkPolicies</SelectItem>
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                </div>
              )}

              {/* ── Label / Annotation Check rules ── */}
              {(builderRuleType === 'label' || builderRuleType === 'annotation') && (
                <div className="flex flex-col gap-3">
                  <div className="flex items-center justify-between">
                    <Label>{builderRuleType === 'annotation' ? 'Annotation Rules' : 'Label Rules'}</Label>
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
                              <SelectItem value="==">
                                {builderRuleType === 'annotation' ? 'Deny when annotation key matches the value' : 'Deny when label key matches the value'}
                              </SelectItem>
                              <SelectItem value="!=">
                                {builderRuleType === 'annotation' ? 'Deny when annotation key is missing or does not match the value' : 'Deny when label key is missing or does not match the value'}
                              </SelectItem>
                            </SelectGroup>
                          </SelectContent>
                        </Select>
                      </div>

                      <div className="flex flex-col gap-1">
                        <span className="text-xs text-muted-foreground">Violation Message (optional)</span>
                        <Input value={rule.message} onChange={e => updateRule(i, 'message', e.target.value)}
                          placeholder={builderRuleType === 'annotation'
                            ? autoAnnotationMessage(rule.key || 'key', rule.condition, rule.value || 'value')
                            : autoMessage(rule.key || 'key', rule.condition, rule.value || 'value')}
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
                              <SelectItem value="required-registry">Required Registry</SelectItem>
                            </SelectGroup>
                          </SelectContent>
                        </Select>
                      </div>

                      {rule.type === 'required-registry' && (
                        <div className="flex flex-col gap-1">
                          <span className="text-xs text-muted-foreground">Registry</span>
                          <Input
                            value={rule.registry}
                            onChange={e => updateImageRule(i, 'registry', e.target.value)}
                            onBlur={e => {
                              const v = e.target.value.trim()
                              if (v && !v.endsWith('/')) updateImageRule(i, 'registry', v + '/')
                            }}
                            placeholder="e.g. registry.example.com/"
                            className="h-8 text-sm"
                          />
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
              {builderRuleType === 'replica' && (() => {
                const rule = replicaRules[0]
                return (
                  <div className="flex flex-col gap-3">
                    <Label>Replica Limit Rule</Label>
                    <div className="flex flex-col gap-3 rounded-lg border p-4">
                      <div className="grid grid-cols-2 gap-2">
                        <div className="flex flex-col gap-1">
                          <span className="text-xs text-muted-foreground">Resource Type</span>
                          <Select value={rule.resourceType} onValueChange={v => updateReplicaRule(0, 'resourceType', v)}>
                            <SelectTrigger className="h-8 text-sm"><SelectValue /></SelectTrigger>
                            <SelectContent>
                              <SelectGroup>
                                <SelectItem value="deployments">Deployments</SelectItem>
                                <SelectItem value="statefulsets">StatefulSets</SelectItem>
                                <SelectItem value="both">Both</SelectItem>
                              </SelectGroup>
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="flex flex-col gap-1">
                          <span className="text-xs text-muted-foreground">Max Replicas</span>
                          <Input
                            type="number" min={1}
                            value={rule.maxReplicas}
                            onChange={e => updateReplicaRule(0, 'maxReplicas', Math.max(1, parseInt(e.target.value) || 1))}
                            className="h-8 text-sm"
                          />
                        </div>
                      </div>
                      <div className="flex flex-col gap-1">
                        <span className="text-xs text-muted-foreground">Violation Message (optional)</span>
                        <Input value={rule.message} onChange={e => updateReplicaRule(0, 'message', e.target.value)}
                          placeholder={autoReplicaMessage(rule)} className="h-8 text-sm" />
                      </div>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Applies to <span className="font-medium">apps/v1</span> Deployments and StatefulSets (CREATE/UPDATE) and their scale subresources (UPDATE).
                    </p>
                  </div>
                )
              })()}

              {/* ── Resource Limits rules ── */}
              {builderRuleType === 'resource-limits' && (() => {
                const rule = resourceLimitRules[0]
                return (
                  <div className="flex flex-col gap-3">
                    <Label>Resource Limit Rule</Label>
                    <div className="flex flex-col gap-3 rounded-lg border p-4">
                      <div className="flex flex-col gap-1">
                        <span className="text-xs text-muted-foreground">Limit Type</span>
                        <Select value={rule.limitType} onValueChange={v => updateResourceLimitRule(0, 'limitType', v)}>
                          <SelectTrigger className="text-sm"><SelectValue /></SelectTrigger>
                          <SelectContent>
                            <SelectGroup>
                              <SelectItem value="both">CPU and Memory — both limits must be set</SelectItem>
                              <SelectItem value="cpu">CPU only — CPU limit must be set</SelectItem>
                              <SelectItem value="memory">Memory only — memory limit must be set</SelectItem>
                            </SelectGroup>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="flex flex-col gap-1">
                        <span className="text-xs text-muted-foreground">Violation Message (optional)</span>
                        <Input value={rule.message} onChange={e => updateResourceLimitRule(0, 'message', e.target.value)}
                          placeholder={autoResourceLimitMessage(rule)} className="h-8 text-sm" />
                      </div>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Applies to all workloads: pods, deployments, statefulsets, daemonsets, jobs, and cronjobs.
                    </p>
                  </div>
                )
              })()}

              {/* ── Security Context rules ── */}
              {builderRuleType === 'security-context' && (
                <div className="flex flex-col gap-3">
                  <Label>Security Context Rule</Label>
                  <div className="flex flex-col gap-3 rounded-lg border p-4">
                    <div className="flex flex-col gap-1">
                      <span className="text-xs text-muted-foreground">Check Type</span>
                      <Select value={securityContextRule.checkType} onValueChange={v => setSecurityContextRule(r => ({ ...r, checkType: v as SecurityContextCheckType }))}>
                        <SelectTrigger className="text-sm"><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectGroup>
                            <SelectItem value="no-privileged">No Privileged Containers</SelectItem>
                            <SelectItem value="run-as-non-root">Run as Non-Root</SelectItem>
                            <SelectItem value="both">Both</SelectItem>
                          </SelectGroup>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="flex flex-col gap-1">
                      <span className="text-xs text-muted-foreground">Violation Message (optional)</span>
                      <Input
                        value={securityContextRule.message}
                        onChange={e => setSecurityContextRule(r => ({ ...r, message: e.target.value }))}
                        placeholder={autoSecurityContextMessage(securityContextRule)}
                        className="h-8 text-sm"
                      />
                    </div>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Applies to all workloads: pods, deployments, statefulsets, daemonsets, jobs, and cronjobs.
                  </p>
                </div>
              )}

              {/* ── Host Access rules ── */}
              {builderRuleType === 'host-access' && (
                <div className="flex flex-col gap-3">
                  <Label>Host Access Rule</Label>
                  <div className="flex flex-col gap-3 rounded-lg border p-4">
                    <div className="flex flex-col gap-1">
                      <span className="text-xs text-muted-foreground">Check Type</span>
                      <Select value={hostAccessRule.checkType} onValueChange={v => setHostAccessRule(r => ({ ...r, checkType: v as HostAccessCheckType }))}>
                        <SelectTrigger className="text-sm"><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectGroup>
                            <SelectItem value="all">All — deny hostNetwork, hostPID, and hostIPC</SelectItem>
                            <SelectItem value="no-host-network">No Host Network</SelectItem>
                            <SelectItem value="no-host-pid">No Host PID</SelectItem>
                            <SelectItem value="no-host-ipc">No Host IPC</SelectItem>
                          </SelectGroup>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="flex flex-col gap-1">
                      <span className="text-xs text-muted-foreground">Violation Message (optional)</span>
                      <Input
                        value={hostAccessRule.message}
                        onChange={e => setHostAccessRule(r => ({ ...r, message: e.target.value }))}
                        placeholder={autoHostAccessMessage(hostAccessRule)}
                        className="h-8 text-sm"
                      />
                    </div>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Applies to all workloads: pods, deployments, statefulsets, daemonsets, jobs, and cronjobs.
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
                {!loading && policies.length === 0 ? (
                  <Input value={bindingPolicy} onChange={e => setBindingPolicy(e.target.value)}
                    placeholder="Enter policy name..." />
                ) : (
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
                )}
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
