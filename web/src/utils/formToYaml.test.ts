import { describe, it, expect } from 'vitest'
import { formToYaml } from './formToYaml'
import type { PolicyFormInput } from '../api/types'

describe('formToYaml', () => {
  it('generates process kprobe for cluster-wide policy', () => {
    const input: PolicyFormInput = {
      name: 'block-shells',
      process: [{ binaries: ['/bin/bash', '/bin/sh'] }],
    }
    const out = formToYaml(input, 'Post')
    expect(out).toContain('name: block-shells')
    expect(out).toContain('kind: TracingPolicy')
    expect(out).toContain('sys_execve')
    expect(out).toContain('Post')
    expect(out).toContain('/bin/bash')
  })

  it('sets kind to TracingPolicyNamespaced when namespace is set', () => {
    const input: PolicyFormInput = {
      name: 'ns-policy',
      namespace: 'production',
      process: [{ binaries: ['/bin/sh'] }],
    }
    const out = formToYaml(input, 'Post')
    expect(out).toContain('kind: TracingPolicyNamespaced')
    expect(out).toContain('namespace: production')
  })

  it('generates security_file_permission kprobe for file rule', () => {
    const input: PolicyFormInput = {
      name: 'watch-etc',
      file: [{ paths: ['/etc/passwd'], operation: 'write' }],
    }
    const out = formToYaml(input, 'Post')
    expect(out).toContain('security_file_permission')
    expect(out).toContain('syscall: false')
    expect(out).toContain('/etc/passwd')
    // path-only matching — no permission int filter
    expect(out).not.toContain("'2'")
    expect(out).not.toContain("'4'")
    expect(out).not.toContain('sys_write')
  })

  it('includes podSelector when provided', () => {
    const input: PolicyFormInput = {
      name: 'scoped',
      podSelector: { app: 'myapp' },
      process: [{ binaries: ['/bin/sh'] }],
    }
    const out = formToYaml(input, 'Post')
    expect(out).toContain('podSelector')
    expect(out).toContain('myapp')
  })

  it('returns multiple kprobes for mixed rules', () => {
    const input: PolicyFormInput = {
      name: 'multi',
      process: [{ binaries: ['/bin/bash'] }],
      file: [{ paths: ['/etc'], operation: 'open' }],
    }
    const out = formToYaml(input, 'Post')
    expect(out).toContain('sys_execve')
    expect(out).toContain('security_file_permission')
  })
})
