// The one classifier for what a security event's rule governs, shared by the
// Security Events badge and the CSV export. It used to be written twice — with
// a comment on the copy saying to keep them in step — and the copies drifted
// until the export called inbound connections and LSM file hooks "Process".
//
// Every event with a function gets a type: an unrecognised kernel function is
// Kernel rather than untyped, so no event is invisible to the rule-type filter.
export type RuleType = 'File' | 'Network' | 'Process' | 'Kernel'

export function ruleType(fn: string): RuleType | null {
  if (!fn) return null
  // All three functions of a file rule (read/write, mmap, truncate), plus the
  // LSM file hooks.
  if (fn.includes('file_permission') || fn.includes('mmap_file') || fn.includes('path_truncate') ||
      fn.includes('file_open') ||
      fn.includes('sys_read') || fn.includes('sys_write') || fn.includes('sys_open')) return 'File'
  if (fn.includes('tcp_connect') || fn.includes('tcp_sendmsg') || fn.includes('udp') || fn.includes('inet_csk_accept') ||
      fn.includes('socket_connect') || fn.includes('socket_bind') ||
      fn.includes('deny')) return 'Network'
  if (fn.includes('execve') || fn.includes('bprm')) return 'Process'
  return 'Kernel'
}
