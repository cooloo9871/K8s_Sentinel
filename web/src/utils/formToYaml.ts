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

  // Process rules: ONE sys_execve kprobe with all binaries in a single matchBinaries.
  // Multiple kprobes for the same function name would fail to pin their BPF links.
  const allBinaries = (input.process ?? []).flatMap((r) => r.binaries).filter(Boolean)
  if (allBinaries.length > 0) {
    doc.spec.kprobes.push({
      call: 'sys_execve',
      syscall: true,
      args: [{ index: 0, type: 'string' }],
      selectors: [{
        matchBinaries: [{ operator: 'In', values: allBinaries }],
        matchActions: [{ action }],
      }],
    })
  }

  // File rules: ONE security_file_permission kprobe with all paths in a single matchArgs.
  // Values in the same matchArgs entry are OR'd by Tetragon.
  const allPaths = (input.file ?? []).flatMap((r) => r.paths).filter(Boolean)
  if (allPaths.length > 0) {
    doc.spec.kprobes.push({
      call: 'security_file_permission',
      syscall: false,
      args: [
        { index: 0, type: 'file' },
        { index: 1, type: 'int' },
      ],
      selectors: [{
        matchArgs: [{ index: 0, operator: 'Prefix', values: allPaths }],
        matchActions: [{ action }],
      }],
    })
  }

  return yaml.dump(doc, { lineWidth: -1, quotingType: '"', forceQuotes: true })
}
