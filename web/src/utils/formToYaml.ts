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

// File permission values for security_file_permission arg[1]
const FILE_OP_PERM: Record<string, string | null> = {
  read:  '4',  // MAY_READ
  write: '2',  // MAY_WRITE
  open:  null, // no permission filter — monitor all access
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
  // arg[0] = file object (path), arg[1] = permission int (MAY_READ=4, MAY_WRITE=2)
  for (const r of input.file ?? []) {
    const matchArgs: KProbeMatchArg[] = [
      { index: 0, operator: 'Prefix', values: r.paths },
    ]
    const perm = FILE_OP_PERM[r.operation]
    if (perm !== null && perm !== undefined) {
      matchArgs.push({ index: 1, operator: 'Equal', values: [perm] })
    }

    doc.spec.kprobes.push({
      call: 'security_file_permission',
      syscall: false,
      args: [
        { index: 0, type: 'file' },
        { index: 1, type: 'int' },
      ],
      selectors: [{ matchArgs, matchActions: [{ action }] }],
    })
  }

  return yaml.dump(doc, { lineWidth: -1 })
}
