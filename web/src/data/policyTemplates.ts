export interface PolicyTemplate {
  id: string
  name: string
  description: string
  tags: string[]
  yaml: string
}

export const POLICY_TEMPLATES: PolicyTemplate[] = [
  {
    id: 'monitor-all-exec',
    name: 'Monitor All Process Executions',
    description: 'Log every process execution across the entire cluster. Uses podSelector: {} to capture only pod processes, excluding host-level processes. Suitable as a starting point for behavioral analysis.',
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
