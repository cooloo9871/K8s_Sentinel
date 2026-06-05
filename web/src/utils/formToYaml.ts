import yaml from 'js-yaml'
import type { PolicyFormInput } from '../api/types'

interface KProbeMatchArg {
  index: number
  operator: string
  values: string[]
}

interface KProbeSpec {
  call: string
  syscall: boolean
  args?: { index: number; type: string }[]
  selectors: {
    matchBinaries?: { operator: string; values: string[] }[]
    matchArgs?: KProbeMatchArg[]
    matchActions: { action: string }[]
  }[]
}

interface TracingPolicyDoc {
  apiVersion: string
  kind: string
  metadata: { name: string; namespace?: string }
  spec: {
    podSelector?: { matchLabels: Record<string, string> }
    kprobes: KProbeSpec[]
  }
}

export function formToYaml(input: PolicyFormInput, action: string): string {
  const kind = input.namespace ? 'TracingPolicyNamespaced' : 'TracingPolicy'

  const doc: TracingPolicyDoc = {
    apiVersion: 'cilium.io/v1alpha1',
    kind,
    metadata: { name: input.name, ...(input.namespace ? { namespace: input.namespace } : {}) },
    spec: { kprobes: [] },
  }

  if (input.podSelector && Object.keys(input.podSelector).length > 0) {
    doc.spec.podSelector = { matchLabels: input.podSelector }
  }

  // Process rules: sys_execve kprobe
  for (const r of input.process ?? []) {
    doc.spec.kprobes.push({
      call: 'sys_execve',
      syscall: true,
      args: [{ index: 0, type: 'string' }],
      selectors: [{
        matchBinaries: [{ operator: 'In', values: r.binaries }],
        matchActions: [{ action }],
      }],
    })
  }

  // File rules: security_file_permission kprobe
  // arg[0] = file object (path). We match on path only — Tetragon captures all
  // permission types (read/write/exec) for the matched paths.
  for (const r of input.file ?? []) {
    doc.spec.kprobes.push({
      call: 'security_file_permission',
      syscall: false,
      args: [
        { index: 0, type: 'file' },
        { index: 1, type: 'int' },
      ],
      selectors: [{
        matchArgs: [{ index: 0, operator: 'Prefix', values: r.paths }],
        matchActions: [{ action }],
      }],
    })
  }

  return yaml.dump(doc, { lineWidth: -1 })
}
