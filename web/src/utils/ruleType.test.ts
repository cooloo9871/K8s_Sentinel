import { describe, it, expect } from 'vitest'
import { ruleType } from './ruleType'

// The cases the duplicated copy got wrong before it was unified — the CSV
// export called all of these "Process".
describe('ruleType', () => {
  it('classifies every hook the parser produces', () => {
    expect(ruleType('inet_csk_accept')).toBe('Network')
    expect(ruleType('socket_connect')).toBe('Network')
    expect(ruleType('cilium-egress-deny')).toBe('Network')
    expect(ruleType('security_mmap_file')).toBe('File')
    expect(ruleType('file_open')).toBe('File')
    expect(ruleType('security_path_truncate')).toBe('File')
    expect(ruleType('__x64_sys_execve')).toBe('Process')
    expect(ruleType('raw_syscalls/sys_enter')).toBe('Kernel')
    expect(ruleType('/usr/lib/libssl.so:SSL_write')).toBe('Kernel')
    expect(ruleType('')).toBeNull()
  })
})
