import { describe, it, expect } from 'vitest'
import { formToYaml } from './formToYaml'
import type { PolicyFormInput } from '../api/types'

describe('formToYaml', () => {
  it('generates process kprobe for cluster-wide policy', () => {
    const input: PolicyFormInput = {
      name: 'block-shells',
      process: [{ binaries: ['/bin/bash', '/bin/sh'] }],
    }
    const yaml = formToYaml(input, 'Post')
    expect(yaml).toContain('name: block-shells')
    expect(yaml).toContain('kind: TracingPolicy')
    expect(yaml).toContain('sys_execve')
    expect(yaml).toContain('Post')
    expect(yaml).toContain('/bin/bash')
  })

  it('sets kind to TracingPolicyNamespaced when namespace is set', () => {
    const input: PolicyFormInput = {
      name: 'ns-policy',
      namespace: 'production',
      process: [{ binaries: ['/bin/sh'] }],
    }
    const yaml = formToYaml(input, 'Post')
    expect(yaml).toContain('kind: TracingPolicyNamespaced')
    expect(yaml).toContain('namespace: production')
  })

  it('generates file kprobe for write operation', () => {
    const input: PolicyFormInput = {
      name: 'watch-etc',
      file: [{ paths: ['/etc/passwd'], operation: 'write' }],
    }
    const yaml = formToYaml(input, 'Post')
    expect(yaml).toContain('sys_write')
    expect(yaml).toContain('/etc/passwd')
  })

  it('includes podSelector when provided', () => {
    const input: PolicyFormInput = {
      name: 'scoped',
      podSelector: { app: 'myapp' },
      process: [{ binaries: ['/bin/sh'] }],
    }
    const yaml = formToYaml(input, 'Post')
    expect(yaml).toContain('podSelector')
    expect(yaml).toContain('myapp')
  })

  it('returns multiple kprobes for mixed rules', () => {
    const input: PolicyFormInput = {
      name: 'multi',
      process: [{ binaries: ['/bin/bash'] }],
      file: [{ paths: ['/etc'], operation: 'open' }],
    }
    const yaml = formToYaml(input, 'Post')
    expect(yaml).toContain('sys_execve')
    expect(yaml).toContain('sys_openat')
  })
})
