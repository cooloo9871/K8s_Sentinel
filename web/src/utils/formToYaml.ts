import yaml from 'js-yaml'
import type { PolicyFormInput } from '../api/types'

interface KProbeSpec {
  call: string
  syscall: boolean
  args?: { index: number; type: string }[]
  selectors: {
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

  // Process rules: ONE sys_execve kprobe with all values combined.
  // Uses matchArgs + Postfix: "/cat" matches /bin/cat, /usr/bin/cat, etc.
  // Multiple kprobes for the same function cause BPF link pin conflicts.
  const allBinaries = (input.process ?? []).flatMap((r) => r.binaries).filter(Boolean)
  if (allBinaries.length > 0) {
    doc.spec.kprobes.push({
      call: 'sys_execve',
      syscall: true,
      args: [{ index: 0, type: 'string' }],
      selectors: [{
        matchArgs: [{ index: 0, operator: 'Postfix', values: allBinaries }],
        matchActions: [{ action }],
      }],
    })
  }

  // File rules: ONE security_file_permission kprobe with all paths combined.
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

  // Network rules: ONE tcp_connect kprobe with multiple selectors (one per rule, OR'd).
  // Each selector uses DAddr for CIDR and DPort for port (sock-type operators).
  const netSelectors = (input.network ?? [])
    .map((r) => {
      const matchArgs: { index: number; operator: string; values: string[] }[] = []
      if (r.cidr.trim()) matchArgs.push({ index: 0, operator: 'DAddr', values: [r.cidr.trim()] })
      if (r.port.trim()) matchArgs.push({ index: 0, operator: 'DPort', values: [r.port.trim()] })
      return matchArgs.length > 0 ? { matchArgs, matchActions: [{ action }] } : null
    })
    .filter((s): s is NonNullable<typeof s> => s !== null)

  if (netSelectors.length > 0) {
    doc.spec.kprobes.push({
      call: 'tcp_connect',
      syscall: false,
      args: [{ index: 0, type: 'sock' }],
      selectors: netSelectors,
    })
  }

  return yaml.dump(doc, { lineWidth: -1 })
}
