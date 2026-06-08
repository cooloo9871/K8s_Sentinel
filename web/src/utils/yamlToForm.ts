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
    process: [],
    file: [],
    network: [],
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

        // Current format: matchArgs index:0 with Postfix operator
        const matchArgsIdx0 = (sel.matchArgs ?? []).filter((a: any) => a.index === 0)
        for (const ma of matchArgsIdx0) {
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
      // Whitelist format: NotDAddr selector, each value is an allowed address
      for (const sel of selectors) {
        const args: any[] = sel.matchArgs ?? []
        const notDAddr = args.find((a: any) => a.operator === 'NotDAddr')
        if (notDAddr) {
          for (const addr of notDAddr.values ?? []) {
            if (addr) result.network!.push({ address: addr })
          }
        } else {
          // Legacy DAddr (old blacklist format) — import as whitelist entry
          const dAddr = args.find((a: any) => a.operator === 'DAddr')
          if (dAddr?.values?.[0]) result.network!.push({ address: dAddr.values[0] })
        }
      }

    } else if (
      call === 'security_file_permission' ||
      call === 'sys_read' ||
      call === 'sys_write' ||
      call === 'sys_openat'
    ) {
      // All file-related kprobes: extract path values from matchArgs index 0
      for (const sel of selectors) {
        for (const ma of (sel.matchArgs ?? []).filter((a: any) => a.index === 0)) {
          for (const path of ma.values ?? []) {
            if (path) result.file!.push({ paths: [path] })
          }
        }
      }
    }
  }

  return result
}
