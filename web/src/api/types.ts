export interface ProcessRule {
  binaries: string[]
}

export interface FileRule {
  paths: string[]
}

export interface NetworkRule {
  address: string  // allowed IP or CIDR, e.g. "127.0.0.1" or "10.0.0.0/8"
}

export interface PolicyFormInput {
  name: string
  namespace?: string
  podSelector?: Record<string, string>
  process?: ProcessRule[]
  file?: FileRule[]
  network?: NetworkRule[]
}

export interface PolicyRecord {
  name: string
  namespace?: string
  scope: 'cluster' | 'namespaced'
  mode: 'Monitoring' | 'Protect' | 'Mixed'
  createdAt: string
  rawYaml: string
}

export type Mode = 'Monitoring' | 'Protect' | 'Mixed'

export interface TetragonEvent {
  type: 'exec' | 'exit' | 'kprobe'
  time: string
  nodeName: string
  namespace: string
  pod: string
  container: string
  binary: string
  arguments: string
  parentBin: string
  action: 'monitor' | 'kill' | ''
  policyName: string
  function: string
}

export interface CreatePolicyPayload {
  source: 'form' | 'yaml'
  form?: PolicyFormInput
  action?: string
  rawYaml?: string
}
