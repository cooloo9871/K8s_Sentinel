export interface ProcessRule {
  binaries: string[]
}

export interface FileRule {
  paths: string[]
}

export interface NetworkRule {
  address: string  // allowed IP or CIDR, e.g. "127.0.0.1" or "10.0.0.0/8"
}

export interface PolicyFormInput {
  name: string
  namespace?: string
  podSelector?: Record<string, string>
  processMode?: 'whitelist' | 'blacklist'  // whitelist = NotPostfix (default), blacklist = Postfix
  process?: ProcessRule[]
  fileMode?: 'whitelist' | 'blacklist'     // whitelist = NotPrefix (default), blacklist = Prefix
  file?: FileRule[]
  network?: NetworkRule[]
  networkPorts?: string[]                  // destination ports to restrict (DPort, ANDed with address rule)
  networkMode?: 'whitelist' | 'blacklist'  // whitelist = NotDAddr, blacklist = DAddr
}

export interface PolicyRecord {
  name: string
  namespace?: string
  scope: 'cluster' | 'namespaced'
  mode: 'Monitoring' | 'Protect' | 'Mixed'
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
  filePath: string   // file path from security_file_permission kprobe
  netDest: string    // network destination "addr:port" from tcp_connect kprobe
}

export interface CreatePolicyPayload {
  source: 'form' | 'yaml'
  form?: PolicyFormInput
  action?: string
  rawYaml?: string
}
