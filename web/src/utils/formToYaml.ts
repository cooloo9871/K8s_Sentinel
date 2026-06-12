import yaml from 'js-yaml'
import type { PolicyFormInput } from '../api/types'

interface Selector {
  matchBinaries?: { operator: string; values: string[] }[]
  matchArgs?: { index: number; operator: string; values: string[] }[]
  matchActions: { action: string }[]
}

interface KProbeSpec {
  call: string
  syscall: boolean
  args?: { index: number; type: string }[]
  selectors: Selector[]
}

interface LSMHookSpec {
  hook: string
  args: { index: number; type: string }[]
  selectors: Selector[]
}

interface TracingPolicyDoc {
  apiVersion: string
  kind: string
  metadata: { name: string; namespace?: string }
  spec: {
    podSelector?: { matchLabels: Record<string, string> }
    kprobes: KProbeSpec[]
    lsmhooks?: LSMHookSpec[]
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
  // Whitelist (default): NotPostfix — kill anything NOT ending with a listed suffix.
  // Blacklist: Postfix — kill anything ending with a listed suffix.
  // Strip leading '/' so the suffix matches both absolute (/cgichild.sh) and
  // relative-path calls (cgichild.sh). e.g. "/usr/bin/cat" → "usr/bin/cat"
  const allBinaries = (input.process ?? [])
    .flatMap((r) => r.binaries)
    .filter(Boolean)
    .map((b) => b.startsWith('/') ? b.slice(1) : b)
    .filter(Boolean)
  if (allBinaries.length > 0) {
    const processOp = input.processMode === 'blacklist' ? 'Postfix' : 'NotPostfix'
    doc.spec.kprobes.push({
      call: 'sys_execve',
      syscall: true,
      args: [{ index: 0, type: 'string' }],
      selectors: [{
        matchArgs: [{ index: 0, operator: processOp, values: allBinaries }],
        matchActions: [{ action }],
      }],
    })
  }

  // File rules: ONE security_file_permission kprobe.
  // Blacklist (default): Prefix. Whitelist: NotPrefix.
  // ExceptBinaries: matchBinaries NotIn so those binaries bypass this rule.
  const fileOp = input.fileMode === 'whitelist' ? 'NotPrefix' : 'Prefix'
  const fileSelectors = (input.file ?? [])
    .filter(r => r.paths.some(Boolean))
    .map(r => {
      const paths = r.paths.filter(Boolean)
      const except = (r.exceptBinaries ?? []).filter(Boolean)
      const matchArgs: NonNullable<Selector['matchArgs']> = [{ index: 0, operator: fileOp, values: paths }]
      if (r.permission === 'read')  matchArgs.push({ index: 1, operator: 'Equal', values: ['4'] })
      if (r.permission === 'write') matchArgs.push({ index: 1, operator: 'Equal', values: ['2'] })
      // Build selector with matchBinaries FIRST to match Go struct field order.
      const sel: Selector = {
        ...(except.length > 0 ? { matchBinaries: [{ operator: 'NotIn', values: except }] } : {}),
        matchArgs,
        matchActions: [{ action }],
      }
      return sel
    })
  if (fileSelectors.length > 0) {
    doc.spec.kprobes.push({
      call: 'security_file_permission',
      syscall: false,
      args: [{ index: 0, type: 'file' }, { index: 1, type: 'int' }],
      selectors: fileSelectors,
    })
  }

  // Network rules: ONE tcp_connect kprobe.
  // networkMode 'whitelist' → NotDAddr (block connections NOT in list)
  // networkMode 'blacklist' → DAddr    (block connections IN list)
  const netAddresses = (input.network ?? []).map(r => r.address.trim()).filter(Boolean)
  const ports = (input.networkPorts ?? []).map(p => p.trim()).filter(Boolean)

  if (netAddresses.length > 0 || ports.length > 0) {
    let selectors: Selector[]
    if (input.networkMode === 'blacklist') {
      const matchArgs: { index: number; operator: string; values: string[] }[] = []
      if (netAddresses.length > 0) matchArgs.push({ index: 0, operator: 'DAddr', values: netAddresses })
      if (ports.length > 0) matchArgs.push({ index: 0, operator: 'DPort', values: ports })
      selectors = [{ matchArgs, matchActions: [{ action }] }]
    } else {
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

  // LSM rules: lsmhooks file_open — blocks access at open time, before data is read/written.
  const lsmSelectors: Selector[] = (input.lsmRules ?? [])
    .flatMap(r => r.paths.filter(Boolean).map(p => {
      const except = (r.exceptBinaries ?? []).filter(Boolean)
      const sel: Selector = {
        ...(except.length > 0 ? { matchBinaries: [{ operator: 'NotIn', values: except }] } : {}),
        matchArgs: [{ index: 0, operator: 'Prefix', values: [p] }],
        matchActions: [{ action }],
      }
      return sel
    }))
  if (lsmSelectors.length > 0) {
    doc.spec.lsmhooks = [{
      hook: 'file_open',
      args: [{ index: 0, type: 'file' }],
      selectors: lsmSelectors,
    }]
  }

  return yaml.dump(doc, { lineWidth: -1 })
}
