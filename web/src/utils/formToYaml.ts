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

  // Process rules: ONE sys_execve kprobe with all values combined, matched
  // exactly against the absolute path.
  //
  // Must stay in step with Build in internal/policy/builder.go, which is what
  // actually gets applied — this only draws the preview. They disagreed once,
  // and the preview showed a rule the cluster never received.
  //
  // Suffix matching was the previous design. A whitelist of suffixes is walked
  // straight past: NotPostfix "usr/sbin/nginx" allows anything ending in that,
  // so a binary at /tmp/usr/sbin/nginx runs.
  const allBinaries = (input.process ?? [])
    .flatMap((r) => r.binaries)
    .map((b) => b.trim())
    .filter((b) => b.startsWith('/'))
  if (allBinaries.length > 0) {
    const processOp = input.processMode === 'blacklist' ? 'Equal' : 'NotEqual'
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

  // No network kprobe is emitted: network access control belongs to
  // CiliumNetworkPolicy (see PolicyFormInput). Policies that do need a
  // tcp_connect rule — typically to bind it to process context — are written
  // in the YAML editor or started from the process-aware template.

  return yaml.dump(doc, { lineWidth: -1 })
}
