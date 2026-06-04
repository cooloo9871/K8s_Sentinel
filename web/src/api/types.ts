export interface ProcessRule {
  binaries: string[]
}

export interface FileRule {
  paths: string[]
  operation: 'read' | 'write' | 'open'
}

export interface PolicyFormInput {
  name: string
  namespace?: string
  podSelector?: Record<string, string>
  process?: ProcessRule[]
  file?: FileRule[]
}

export interface PolicyRecord {
  name: string
  namespace?: string
  scope: 'cluster' | 'namespaced'
  createdAt: string
  rawYaml: string
}

export type Mode = 'Monitoring' | 'Protect' | 'Mixed'

export interface SecurityEvent {
  namespace: string
  involvedKind: string
  involvedName: string
  involvedNamespace: string
  reason: string
  message: string
  type: string
  count: number
  firstTime: string
  lastTime: string
  source: string
}

export interface CreatePolicyPayload {
  source: 'form' | 'yaml'
  form?: PolicyFormInput
  action?: string
  rawYaml?: string
}
