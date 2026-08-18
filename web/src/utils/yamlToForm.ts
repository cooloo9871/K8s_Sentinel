import yaml from 'js-yaml'
import type { PolicyFormInput } from '../api/types'

/**
 * Parses a TracingPolicy YAML string back into PolicyFormInput.
 * Returns null if the YAML cannot be parsed or doesn't match the expected schema.
 */
// The form models a subset of TracingPolicy: a list of binaries, a list of file
// paths, one action, and nothing else. Anything outside that subset is dropped
// when the form saves, so a policy carrying it must stay in the YAML editor.
//
// Counting the rules the form managed to read is not enough on its own. The
// monitor-all-file template parses its paths cleanly and would still have been
// mangled: its `return: true` and `returnArg` are not modelled at all, and its
// second selector matches with Postfix, which the form would rewrite as Prefix —
// turning ".bashrc" into a rule that matches nothing.
const KPROBE_UNSUPPORTED = ['return', 'returnArg', 'message', 'tags']
const SELECTOR_UNSUPPORTED = [
  'matchNamespaces', 'matchCapabilities', 'matchPIDs', 'matchReturnArgs',
  'matchNamespaceChanges', 'matchCapabilityChanges',
]

/** Operators the form can read back on the argument it matches paths against. */
const PROCESS_OPERATORS = ['Equal', 'NotEqual', 'Postfix', 'NotPostfix']
const FILE_OPERATORS = ['Prefix', 'NotPrefix']

// What Tetragon's CRD schema defaults onto every stored kprobe. A field equal
// to its default is not information the form can lose — a save without it gets
// it defaulted right back — so only a non-default value blocks the form. This
// is what the cluster's copy of every form-built policy looks like; treating
// the defaults as user data locked all of them out of the form. (The arg-level
// defaults — maxData, resolve, returnCopy — need no handling: args are read by
// index and type, and extra keys were never grounds for refusal.)
const KPROBE_DEFAULTS: Record<string, unknown> = { return: false }

function representable(kp: any, argOperators: string[]): boolean {
  if (KPROBE_UNSUPPORTED.some(k => kp[k] !== undefined && kp[k] !== KPROBE_DEFAULTS[k])) return false
  for (const sel of kp.selectors ?? []) {
    if (SELECTOR_UNSUPPORTED.some(k => sel[k] !== undefined)) return false
    // The form writes exactly one action, with nothing beside it — an argError,
    // a rateLimit or a second action would not survive the round trip.
    const actions = sel.matchActions ?? []
    if (actions.length > 1) return false
    if (actions.some((a: any) => Object.keys(a).length > 1)) return false
    // matchBinaries is read only as per-rule exceptions, which is NotIn.
    if ((sel.matchBinaries ?? []).some((mb: any) => mb.operator !== 'NotIn')) return false
    for (const ma of sel.matchArgs ?? []) {
      if (ma.index === 0 && !argOperators.includes(ma.operator)) return false
    }
  }
  return true
}

export function yamlToForm(rawYaml: string): PolicyFormInput | null {
  if (!rawYaml.trim()) return null

  let doc: any
  try {
    doc = yaml.load(rawYaml)
  } catch {
    return null
  }

  if (!doc || typeof doc !== 'object' || !doc.metadata?.name) return null

  const matchLabels = doc.spec?.podSelector?.matchLabels
  const result: PolicyFormInput = {
    name: doc.metadata.name ?? '',
    namespace: doc.metadata.namespace || undefined,
    podSelector: matchLabels && typeof matchLabels === 'object' && Object.keys(matchLabels).length > 0
      ? matchLabels as Record<string, string>
      : undefined,
    processMode: 'whitelist',
    process: [],
    file: [],
  }

  const kprobes: any[] = doc.spec?.kprobes ?? []
  // How many rules the form managed to take from the policy. A kprobe the form
  // cannot represent has to send the whole policy to the YAML editor instead —
  // loading it into a form that shows none of it means saving writes the policy
  // back with those rules gone. That is what happened to the monitor-all-exec
  // template: an execve kprobe with no matchArgs matches everything, which a
  // form built around a list of binaries has no way to express, so it opened
  // empty and would have saved as spec: {}.
  let rulesBefore = 0

  for (const kp of kprobes) {
    rulesBefore = result.process!.length + result.file!.length
    const call: string = kp.call ?? ''
    const selectors: any[] = kp.selectors ?? []

    // Match sys_execve and any arch-prefixed variant (__x64_sys_execve, __arm64_sys_execve…)
    if (call === 'sys_execve' || call.includes('sys_execve')) {
      if (!representable(kp, PROCESS_OPERATORS)) return null
      for (const sel of selectors) {
        // Track whether matchArgs index:0 was already parsed to avoid
        // double-counting when both matchArgs and matchBinaries are present.
        let parsedFromMatchArgs = false

        // Equal / NotEqual is what the builder writes. Postfix / NotPostfix is
        // what it wrote before absolute paths were required, and policies saved
        // then are still in clusters — reading only the current pair would leave
        // processMode unset on those, so a blacklist would reopen as a whitelist
        // and invert on save.
        const matchArgsIdx0 = (sel.matchArgs ?? []).filter((a: any) => a.index === 0)
        for (const ma of matchArgsIdx0) {
          if (ma.operator === 'NotEqual' || ma.operator === 'NotPostfix') result.processMode = 'whitelist'
          else if (ma.operator === 'Equal' || ma.operator === 'Postfix') result.processMode = 'blacklist'
          for (const bin of ma.values ?? []) {
            // Older policies hold the path with its leading slash stripped.
            if (bin) result.process!.push({ binaries: [bin.startsWith('/') ? bin : '/' + bin] })
          }
          parsedFromMatchArgs = true
        }

        // Legacy format: matchBinaries — only parse if matchArgs index:0 was absent
        if (!parsedFromMatchArgs) {
          for (const mb of sel.matchBinaries ?? []) {
            for (const bin of mb.values ?? []) {
              if (bin) result.process!.push({ binaries: [bin.startsWith('/') ? bin : '/' + bin] })
            }
          }
        }
      }

    } else if (call === 'tcp_connect' || call === 'inet_csk_accept') {
      // The form no longer manages network rules — they belong to
      // CiliumNetworkPolicy. Returning null keeps the policy in the YAML
      // editor instead of loading it into a form that cannot represent these
      // rules, which on save would silently delete them.
      return null

    } else if (
      call === 'security_file_permission' ||
      call === 'sys_read' ||
      call === 'sys_write' ||
      call === 'sys_openat'
    ) {
      if (!representable(kp, FILE_OPERATORS)) return null
      for (const sel of selectors) {
        const exceptBins: string[] = (sel.matchBinaries ?? [])
          .filter((mb: any) => mb.operator === 'NotIn')
          .flatMap((mb: any) => mb.values ?? [])
          .filter(Boolean)
        // Detect permission from index-1 Equal args (MAY_READ=4, MAY_WRITE=2)
        const permArg = (sel.matchArgs ?? []).find((a: any) => a.index === 1 && a.operator === 'Equal')
        let permission: 'all' | 'read' | 'write' = 'all'
        if (permArg) {
          if ((permArg.values ?? []).includes('4')) permission = 'read'
          else if ((permArg.values ?? []).includes('2')) permission = 'write'
        }
        for (const ma of (sel.matchArgs ?? []).filter((a: any) => a.index === 0)) {
          if (ma.operator === 'NotPrefix') result.fileMode = 'whitelist'
          else if (ma.operator === 'Prefix') result.fileMode = 'blacklist'
          for (const path of ma.values ?? []) {
            if (path) result.file!.push({
              paths: [path],
              ...(exceptBins.length > 0 ? { exceptBinaries: exceptBins } : {}),
              ...(permission !== 'all' ? { permission } : {}),
            })
          }
        }
      }
    }

    if (result.process!.length + result.file!.length === rulesBefore) {
      return null // this kprobe contributed nothing the form can show
    }
  }

  return result
}
