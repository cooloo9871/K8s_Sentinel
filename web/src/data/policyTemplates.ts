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
  {
    id: 'monitor-external-network',
    name: 'Monitor External Network (Outside Cluster)',
    description: 'Alert when any pod connects to an address outside the cluster CIDR ranges. Pod and Service CIDRs are auto-detected. Only needed on clusters without Cilium — Cilium clusters get this from Hubble automatically.',
    tags: ['cluster-wide', 'network', 'monitoring', 'non-cilium'],
    yaml: `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: monitor-external-network
spec:
  podSelector: {}
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "NotDAddr"
        values:
        - "127.0.0.1"
        - "\${PODCIDR}"
        - "\${SVCCIDR}"
        - "\${NODEIPS}"
`,
  },
  {
    id: 'monitor-internal-network',
    name: 'Monitor Internal Network (Inside Cluster)',
    description: 'Capture TCP connections between pods within the cluster to feed Network Topology. CIDRs are auto-detected. Only needed on clusters without Cilium — Cilium clusters get richer data from Hubble automatically.',
    tags: ['cluster-wide', 'network', 'monitoring', 'non-cilium'],
    yaml: `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: monitor-internal-network
spec:
  podSelector: {}
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "DAddr"
        values:
        - "\${PODCIDR}"
        - "\${SVCCIDR}"
        - "\${NODEIPS}"
`,
  },
  {
    id: 'monitor-all-file',
    name: 'Monitor All File Access',
    description: 'Monitor sensitive file and directory reads/writes across all pods in the cluster.',
    tags: ['cluster-wide', 'file', 'monitoring'],
    yaml: `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: monitor-all-file
spec:
  podSelector: {}
  kprobes:
  - call: "security_file_permission"
    syscall: false
    return: true
    args:
    - index: 0
      type: "file"
    - index: 1
      type: "int"
    returnArg:
      index: 0
      type: "int"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/boot"
        - "/root/.ssh"
        - "/etc/shadow"
        - "/etc/profile"
        - "/etc/sudoers"
        - "/etc/pam.conf"
        - "/etc/bashrc"
        - "/etc/csh.cshrc"
        - "/etc/csh.login"
      - index: 1
        operator: "Equal"
        values:
        - "4"
    - matchArgs:
      - index: 0
        operator: "Postfix"
        values:
        - ".bashrc"
        - ".bash_profile"
        - ".bash_login"
        - ".bash_logout"
        - ".cshrc"
        - ".cshdirs"
        - ".profile"
        - ".login"
        - ".logout"
        - ".history"
      - index: 1
        operator: "Equal"
        values:
        - "4"
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/etc"
        - "/boot"
        - "/lib"
        - "/lib64"
        - "/bin"
        - "/usr/lib"
        - "/usr/local/lib"
        - "/usr/local/sbin"
        - "/usr/local/bin"
        - "/usr/bin"
        - "/usr/sbin"
        - "/var/log"
        - "/dev/log"
        - "/root/.ssh"
      - index: 1
        operator: "Equal"
        values:
        - "2"
  - call: "security_mmap_file"
    syscall: false
    return: true
    args:
    - index: 0
      type: "file"
    - index: 1
      type: "uint32"
    - index: 2
      type: "uint32"
    returnArg:
      index: 0
      type: "int"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/boot"
        - "/root/.ssh"
        - "/etc/shadow"
        - "/etc/sudoers"
        - "/etc/pam.conf"
        - "/etc/profile"
        - "/etc/bashrc"
        - "/etc/csh.cshrc"
        - "/etc/csh.login"
        - ".bashrc"
        - ".bash_profile"
        - ".bash_login"
        - ".bash_logout"
        - ".cshrc"
        - ".cshdirs"
        - ".profile"
        - ".login"
        - ".logout"
        - ".history"
      - index: 1
        operator: "Equal"
        values:
        - "1"
      - index: 2
        operator: "Mask"
        values:
        - "1"
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/etc"
        - "/boot"
        - "/lib"
        - "/lib64"
        - "/bin"
        - "/usr/lib"
        - "/usr/local/lib"
        - "/usr/local/sbin"
        - "/usr/local/bin"
        - "/usr/bin"
        - "/usr/sbin"
        - "/var/log"
        - "/dev/log"
        - "/root/.ssh"
      - index: 1
        operator: "Mask"
        values:
        - "2"
      - index: 2
        operator: "Mask"
        values:
        - "1"
  - call: "security_path_truncate"
    syscall: false
    return: true
    args:
    - index: 0
      type: "path"
    returnArg:
      index: 0
      type: "int"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/etc"
        - "/boot"
        - "/lib"
        - "/lib64"
        - "/usr/lib"
        - "/usr/local/lib"
        - "/usr/local/sbin"
        - "/usr/local/bin"
        - "/usr/bin"
        - "/usr/sbin"
        - "/var/log"
        - "/dev/log"
        - "/root/.ssh"
`,
  },
  {
    id: 'block-unexpected-egress-binaries',
    name: 'Block Egress From Unexpected Binaries (Advanced)',
    description:
      'Kills processes that open outbound connections unless they are on the allowed binary list. This is the one network control CiliumNetworkPolicy cannot express: CNP decides by workload identity, so it cannot tell a legitimate server process apart from a cryptominer or reverse shell running inside the same pod. Edit matchBinaries and podSelector before applying.',
    tags: ['network', 'process', 'enforcing', 'advanced'],
    yaml: `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: block-unexpected-egress-binaries
spec:
  podSelector:
    matchLabels:
      app: my-app
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    # Fires for any binary NOT in this list, then kills that process.
    # Switch Sigkill to Post first to see what would be killed.
    - matchBinaries:
      - operator: "NotIn"
        values:
        - "/usr/sbin/nginx"
        - "/usr/bin/curl"
      matchActions:
      - action: Sigkill
`,
  },
]
