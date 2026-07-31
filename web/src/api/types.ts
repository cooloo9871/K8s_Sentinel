export interface ProcessRule {
  binaries: string[]
}

export interface FileRule {
  paths: string[]
  exceptBinaries?: string[]              // binaries exempted from this rule (matchBinaries: NotIn)
  permission?: 'all' | 'read' | 'write' // default 'all'; 'read'=MAY_READ=4, 'write'=MAY_WRITE=2
}

// Network access control lives in CiliumNetworkPolicy, not here: CNP selects by
// identity so it cannot be bypassed by connecting straight to a backend pod IP,
// it covers ingress as well as egress, and it drops packets rather than killing
// the process. TracingPolicy keeps what only it can do — process and file rules
// with full process context. IP/port rules remain expressible via the YAML
// editor and the process-aware template for cases that need process context.
export interface PolicyFormInput {
  name: string
  namespace?: string
  podSelector?: Record<string, string>
  processMode?: 'whitelist' | 'blacklist'  // whitelist = NotPostfix (default), blacklist = Postfix
  process?: ProcessRule[]
  fileMode?: 'whitelist' | 'blacklist'     // whitelist = NotPrefix, blacklist = Prefix (default)
  file?: FileRule[]
}

export interface PolicyRecord {
  name: string
  namespace?: string
  scope: 'cluster' | 'namespaced'
  mode: 'Monitoring' | 'Protect' | 'Mixed'
  createdBy: string
  createdAt: string
  rawYaml: string
}

export type Mode = 'Monitoring' | 'Protect' | 'Mixed'

export interface TetragonEvent {
  type: 'exec' | 'exit' | 'kprobe'
  time: string
  nodeName: string
  namespace: string
  pod: string
  container: string
  binary: string
  arguments: string
  parentBin: string
  action: 'monitor' | 'kill' | ''
  policyName: string
  function: string
  filePath: string     // file path from file kprobes
  fileOp: string       // "read" | "write" | "mmap-read" | "mmap-write" | "truncate"
  netDest: string      // network destination "addr:port" from tcp_connect kprobe
  netSrc: string       // network source "addr:port" from tcp_connect kprobe
  processUid?: number  // effective UID of the process (undefined = unknown)
}

export interface CreatePolicyPayload {
  source: 'form' | 'yaml'
  form?: PolicyFormInput
  action?: string
  rawYaml?: string
}
