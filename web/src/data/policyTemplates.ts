export interface PolicyTemplate {
  id: string
  name: string
  description: string
  tags: string[]
  yaml: string
  custom?: boolean  // user-created templates
}

const CUSTOM_TEMPLATES_KEY = 'sentinel_custom_templates'

export function loadCustomTemplates(): PolicyTemplate[] {
  try {
    const raw = localStorage.getItem(CUSTOM_TEMPLATES_KEY)
    if (raw) return JSON.parse(raw) as PolicyTemplate[]
  } catch {}
  return []
}

export function saveCustomTemplates(templates: PolicyTemplate[]): void {
  try {
    localStorage.setItem(CUSTOM_TEMPLATES_KEY, JSON.stringify(templates))
  } catch {}
}

export const POLICY_TEMPLATES: PolicyTemplate[] = [
  {
    id: 'monitor-all-exec',
    name: 'Monitor All Process Executions',
    description: 'Record every command executed inside any pod across the cluster. Useful for understanding what your workloads are actually running — a good first step before writing enforcement rules.',
    tags: ['cluster-wide', 'process', 'monitoring'],
    yaml: `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: monitor-all-exec
spec:
  podSelector: {}
  kprobes:
    - call: sys_execve
      syscall: true
      args:
        - index: 0
          type: string
      selectors:
        - matchActions:
            - action: Post
`,
  },
]
