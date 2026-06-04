import yaml from 'js-yaml'
import type { PolicyFormInput } from '../api/types'

const FILE_CALL_OP: Record<string, 'read' | 'write' | 'open'> = {
  sys_read: 'read',
  sys_write: 'write',
  sys_openat: 'open',
}

/**
 * Parses a TracingPolicy YAML string back into PolicyFormInput.
 * Returns null if the YAML cannot be parsed or doesn't match the expected schema.
 * Kprobes that don't match known calls (sys_execve, sys_read, sys_write, sys_openat)
 * are silently ignored — the user can see and edit them in the YAML tab.
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
    } else if (call in FILE_CALL_OP) {
      const operation = FILE_CALL_OP[call]
      for (const sel of selectors) {
        for (const ma of sel.matchArgs ?? []) {
          for (const path of ma.values ?? []) {
            if (path) result.file!.push({ paths: [path], operation })
          }
        }
      }
    }
  }

  return result
}
