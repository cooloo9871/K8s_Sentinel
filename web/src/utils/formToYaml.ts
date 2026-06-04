import yaml from 'js-yaml'
import type { PolicyFormInput } from '../api/types'

interface KProbeSpec {
  call: string
  syscall: boolean
  args?: { index: number; type: string }[]
  selectors: {
    matchBinaries?: { operator: string; values: string[] }[]
    matchArgs?: { index: number; operator: string; values: string[] }[]
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

const FILE_OP_CALL: Record<string, string> = {
  read: 'sys_read',
  write: 'sys_write',
  open: 'sys_openat',
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

  for (const r of input.process ?? []) {
    doc.spec.kprobes.push({
      call: 'sys_execve',
      syscall: true,
      args: [{ index: 0, type: 'string' }],
      selectors: [
        {
          matchBinaries: [{ operator: 'In', values: r.binaries }],
          matchActions: [{ action }],
        },
      ],
    })
  }

  for (const r of input.file ?? []) {
    const call = FILE_OP_CALL[r.operation] ?? 'sys_write'
    doc.spec.kprobes.push({
      call,
      syscall: true,
      selectors: [
        {
          matchArgs: [{ index: 0, operator: 'Prefix', values: r.paths }],
          matchActions: [{ action }],
        },
      ],
    })
  }

  return yaml.dump(doc, { lineWidth: -1 })
}
