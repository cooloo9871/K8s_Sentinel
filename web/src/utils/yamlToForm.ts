import yaml from 'js-yaml'
import type { PolicyFormInput } from '../api/types'

// Backward-compatible mapping for old-style file kprobes
const LEGACY_FILE_CALL_OP: Record<string, 'read' | 'write' | 'open'> = {
  sys_read:   'read',
  sys_write:  'write',
  sys_openat: 'open',
}

// MAY_READ=4, MAY_WRITE=2 for security_file_permission arg[1]
const PERM_TO_OP: Record<string, 'read' | 'write' | 'open'> = {
  '4': 'read',
  '2': 'write',
}

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
      // Process rule
      for (const sel of selectors) {
        for (const mb of sel.matchBinaries ?? []) {
          for (const bin of mb.values ?? []) {
            if (bin) result.process!.push({ binaries: [bin] })
          }
        }
      }

    } else if (call === 'security_file_permission') {
      // File rule (current format)
      for (const sel of selectors) {
        const args: any[] = sel.matchArgs ?? []
        const pathArg = args.find((a: any) => a.index === 0)
        const permArg = args.find((a: any) => a.index === 1)

        const operation: 'read' | 'write' | 'open' =
          PERM_TO_OP[permArg?.values?.[0]] ?? 'open'

        for (const path of pathArg?.values ?? []) {
          if (path) result.file!.push({ paths: [path], operation })
        }
      }

    } else if (call in LEGACY_FILE_CALL_OP) {
      // Legacy format (sys_read / sys_write / sys_openat)
      const operation = LEGACY_FILE_CALL_OP[call]
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
