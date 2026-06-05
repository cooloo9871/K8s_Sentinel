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

  const result: PolicyFormInput = {
    name: doc.metadata.name ?? '',
    namespace: doc.metadata.namespace || undefined,
    process: [],
    file: [],
  }

  const kprobes: any[] = doc.spec?.kprobes ?? []

  for (const kp of kprobes) {
    const call: string = kp.call ?? ''
    const selectors: any[] = kp.selectors ?? []

    if (call === 'sys_execve') {
      for (const sel of selectors) {
        for (const mb of sel.matchBinaries ?? []) {
          for (const bin of mb.values ?? []) {
            if (bin) result.process!.push({ binaries: [bin] })
          }
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
