import yaml from 'js-yaml'
import type { PolicyFormInput } from '../api/types'

/**
 * Parses a TracingPolicy YAML string back into PolicyFormInput.
 * Returns null if the YAML cannot be parsed or doesn't match the expected schema.
 */
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
    fileMode: 'blacklist',
    file: [],
    network: [],
    networkMode: 'whitelist',
    networkPorts: [],
  }

  const kprobes: any[] = doc.spec?.kprobes ?? []

  for (const kp of kprobes) {
    const call: string = kp.call ?? ''
    const selectors: any[] = kp.selectors ?? []

    // Match sys_execve and any arch-prefixed variant (__x64_sys_execve, __arm64_sys_execve…)
    if (call === 'sys_execve' || call.includes('sys_execve')) {
      for (const sel of selectors) {
        // Track whether matchArgs index:0 was already parsed to avoid
        // double-counting when both matchArgs and matchBinaries are present.
        let parsedFromMatchArgs = false

        // Current format: matchArgs index:0 with Postfix or NotPostfix operator
        const matchArgsIdx0 = (sel.matchArgs ?? []).filter((a: any) => a.index === 0)
        for (const ma of matchArgsIdx0) {
          if (ma.operator === 'NotPostfix') result.processMode = 'whitelist'
          else if (ma.operator === 'Postfix') result.processMode = 'blacklist'
          for (const bin of ma.values ?? []) {
            if (bin) result.process!.push({ binaries: [bin] })
          }
          parsedFromMatchArgs = true
        }

        // Legacy format: matchBinaries — only parse if matchArgs index:0 was absent
        if (!parsedFromMatchArgs) {
          for (const mb of sel.matchBinaries ?? []) {
            for (const bin of mb.values ?? []) {
              if (bin) result.process!.push({ binaries: [bin] })
            }
          }
        }
      }

    } else if (call === 'tcp_connect') {
      for (const sel of selectors) {
        const args: any[] = sel.matchArgs ?? []
        const notDAddr = args.find((a: any) => a.operator === 'NotDAddr')
        const dAddr    = args.find((a: any) => a.operator === 'DAddr')
        if (notDAddr) {
          result.networkMode = 'whitelist'
          for (const addr of notDAddr.values ?? []) {
            if (addr) result.network!.push({ address: addr })
          }
        } else if (dAddr) {
          result.networkMode = 'blacklist'
          for (const addr of dAddr.values ?? []) {
            if (addr) result.network!.push({ address: addr })
          }
        }
        const dPort = args.find((a: any) => a.operator === 'DPort' || a.operator === 'NotDPort')
        if (dPort) {
          // DPort without a corresponding DAddr means blacklist (port-only rule).
          if (dPort.operator === 'DPort' && !dAddr && !notDAddr) {
            result.networkMode = 'blacklist'
          }
          for (const port of dPort.values ?? []) {
            if (port) result.networkPorts!.push(String(port))
          }
        }
      }

    } else if (
      call === 'security_file_permission' ||
      call === 'sys_read' ||
      call === 'sys_write' ||
      call === 'sys_openat'
    ) {
      for (const sel of selectors) {
        const exceptBins: string[] = (sel.matchBinaries ?? [])
          .filter((mb: any) => mb.operator === 'NotIn')
          .flatMap((mb: any) => mb.values ?? [])
          .filter(Boolean)
        // Detect permission from index-1 Bitmask args
        const permArg = (sel.matchArgs ?? []).find((a: any) => a.index === 1 && a.operator === 'Bitmask')
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
  }

  return result
}
