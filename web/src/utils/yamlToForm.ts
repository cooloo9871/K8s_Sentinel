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
  // First process/file mode seen, to detect selectors that contradict it.
  let processModeSeen: 'whitelist' | 'blacklist' | null = null

  for (const kp of kprobes) {
    rulesBefore = result.process!.length + result.file!.length
    const call: string = kp.call ?? ''
    const selectors: any[] = kp.selectors ?? []

    // Match sys_execve and any arch-prefixed variant (__x64_sys_execve, __arm64_sys_execve…)
    if (call === 'sys_execve' || call.includes('sys_execve')) {
      if (!representable(kp, PROCESS_OPERATORS)) return null
      for (const sel of selectors) {
        // The builder writes exactly one index-0 arg per selector. A second one
        // is an AND the form cannot express — a save would merge the lists into
        // one arg (an OR) and change the semantics — and any other index would
        // simply be dropped. Both must stay in the YAML editor.
        const args = sel.matchArgs ?? []
        if (args.some((a: any) => a.index !== 0)) return null
        if (args.length > 1) return null

        // Track whether matchArgs index:0 was already parsed to avoid
        // double-counting when both matchArgs and matchBinaries are present.
        let parsedFromMatchArgs = false

        // Equal / NotEqual is what the builder writes. Postfix / NotPostfix is
        // what it wrote before absolute paths were required, and policies saved
        // then are still in clusters — reading only the current pair would leave
        // processMode unset on those, so a blacklist would reopen as a whitelist
        // and invert on save.
        for (const ma of args) {
          const mode = (ma.operator === 'NotEqual' || ma.operator === 'NotPostfix') ? 'whitelist'
            : (ma.operator === 'Equal' || ma.operator === 'Postfix') ? 'blacklist' : null
          if (mode) {
            // Mixed whitelist and blacklist selectors cannot share the form's
            // single mode: keeping the last one would invert the other half of
            // the policy on save.
            if (processModeSeen && processModeSeen !== mode) return null
            processModeSeen = mode
            result.processMode = mode
          }
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
        // The form models exactly one path arg (index 0) and at most one
        // permission arg: index 1, Equal, a single value of MAY_READ (4) or
        // MAY_WRITE (2) — precisely what the builder writes. Anything else
        // (Mask, NotEqual, other indexes, multi-value like ["4","2"], a second
        // path arg) would be silently dropped or rewritten on save, widening or
        // narrowing the rule, so the policy stays in the YAML editor.
        let permission: 'all' | 'read' | 'write' = 'all'
        let idx0Count = 0
        for (const ma of sel.matchArgs ?? []) {
          if (ma.index === 0) { idx0Count++; continue }
          if (ma.index !== 1 || ma.operator !== 'Equal') return null
          // String() so an unquoted YAML number (values: [4]) reads the same
          // as the quoted form the builder writes.
          const vals = (ma.values ?? []).map((v: any) => String(v))
          if (vals.length !== 1 || (vals[0] !== '4' && vals[0] !== '2')) return null
          if (permission !== 'all') return null // a second permission arg
          permission = vals[0] === '4' ? 'read' : 'write'
        }
        if (idx0Count > 1) return null
        for (const ma of (sel.matchArgs ?? []).filter((a: any) => a.index === 0)) {
          const mode = ma.operator === 'NotPrefix' ? 'whitelist'
            : ma.operator === 'Prefix' ? 'blacklist' : null
          if (!mode) continue
          // Mixed Prefix and NotPrefix selectors cannot share the form's single
          // fileMode: keeping the last one would invert the other half on save.
          if (result.fileMode && result.fileMode !== mode) return null
          result.fileMode = mode
          const paths = (ma.values ?? []).filter(Boolean)
          if (paths.length === 0) continue
          const extra = {
            ...(exceptBins.length > 0 ? { exceptBinaries: exceptBins } : {}),
            ...(permission !== 'all' ? { permission } : {}),
          }
          if (mode === 'whitelist') {
            // The builder emits whitelist as ONE selector holding all excluded
            // paths, so restore it as a single rule to round-trip exactly.
            result.file!.push({ paths, ...extra })
          } else {
            for (const path of paths) result.file!.push({ paths: [path], ...extra })
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
