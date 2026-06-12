export interface PolicyTemplate {
  id: string
  name: string
  description: string
  tags: string[]
  yaml: string
  custom?: boolean  // user-created templates
}


export const POLICY_TEMPLATES: PolicyTemplate[] = [
  {
    id: 'monitor-all-exec',
    name: 'Monitor All Process Executions',
    description: 'Record every command executed inside any pod across the cluster.',
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
