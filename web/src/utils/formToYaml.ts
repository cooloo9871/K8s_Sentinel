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

  // Network rules: ONE tcp_connect kprobe.
  // networkMode 'whitelist' → NotDAddr (block connections NOT in list)
  // networkMode 'blacklist' → DAddr    (block connections IN list)
  const netAddresses = (input.network ?? []).map((r) => r.address.trim()).filter(Boolean)
  const ports = (input.networkPorts ?? []).map((p) => p.trim()).filter(Boolean)

  // Guard on either addresses OR ports — ports-only rules are valid
  // (e.g. NotDPort:6379 = kill anything not on port 6379).
  if (netAddresses.length > 0 || ports.length > 0) {
    let selectors: { matchArgs: { index: number; operator: string; values: string[] }[]; matchActions: { action: string }[] }[]

    if (input.networkMode === 'blacklist') {
      // Blacklist: ONE selector → DAddr AND DPort (AND semantics).
      const matchArgs: { index: number; operator: string; values: string[] }[] = []
      if (netAddresses.length > 0) matchArgs.push({ index: 0, operator: 'DAddr', values: netAddresses })
      if (ports.length > 0) matchArgs.push({ index: 0, operator: 'DPort', values: ports })
      selectors = [{ matchArgs, matchActions: [{ action }] }]
    } else {
      // Whitelist: SEPARATE selectors → NotDAddr OR NotDPort (OR semantics).
      // Kill if (dest NOT in address list) OR (port NOT in port list).
      selectors = []
      if (netAddresses.length > 0) {
        selectors.push({ matchArgs: [{ index: 0, operator: 'NotDAddr', values: netAddresses }], matchActions: [{ action }] })
      }
      if (ports.length > 0) {
        selectors.push({ matchArgs: [{ index: 0, operator: 'NotDPort', values: ports }], matchActions: [{ action }] })
      }
    }

    doc.spec.kprobes.push({
      call: 'tcp_connect',
      syscall: false,
      args: [{ index: 0, type: 'sock' }],
      selectors,
    })
  }

  return yaml.dump(doc, { lineWidth: -1 })
}
