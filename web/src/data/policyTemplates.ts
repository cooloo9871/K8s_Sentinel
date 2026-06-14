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
    id: 'monitor-all-file',
    name: 'Monitor All File Access',
    description: 'Monitor sensitive file and directory reads/writes across all pods in the cluster.',
    tags: ['cluster-wide', 'file', 'monitoring'],
    yaml: `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: monitor-all-file
spec:
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
]
