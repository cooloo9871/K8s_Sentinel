import { describe, it, expect } from 'vitest'
import { formToYaml } from './formToYaml'
import type { PolicyFormInput } from '../api/types'

describe('formToYaml', () => {
  it('generates a single sys_execve kprobe using matchArgs Postfix', () => {
    const input: PolicyFormInput = {
      name: 'block-shells',
      process: [{ binaries: ['/bash'] }, { binaries: ['/sh'] }],
    }
    const out = formToYaml(input, 'Post')
    expect(out).toContain('kind: TracingPolicy')
    expect(out).toContain('sys_execve')
    expect(out).toContain('Postfix')
    expect(out).toContain('/bash')
    expect(out).toContain('/sh')
    expect(out).not.toContain('matchBinaries')
    // Only ONE kprobe definition — no duplicate
    expect(out.split('sys_execve').length - 1).toBe(1)
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

  it('generates a single security_file_permission kprobe with all paths combined', () => {
    const input: PolicyFormInput = {
      name: 'watch-files',
      file: [
        { paths: ['/etc/shadow'] },
        { paths: ['/root'] },
      ],
    }
    const out = formToYaml(input, 'Post')
    expect(out).toContain('security_file_permission')
    expect(out).toContain('syscall: false')
    expect(out).toContain('/etc/shadow')
    expect(out).toContain('/root')
    // Only ONE kprobe definition — no duplicate function
    expect(out.split('security_file_permission').length - 1).toBe(1)
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

  it('returns both kprobes for mixed process and file rules', () => {
    const input: PolicyFormInput = {
      name: 'multi',
      process: [{ binaries: ['/bin/bash'] }],
      file: [{ paths: ['/etc'] }],
    }
    const out = formToYaml(input, 'Post')
    expect(out).toContain('sys_execve')
    expect(out).toContain('security_file_permission')
  })

  it('emits no process kprobe when process list is empty', () => {
    const input: PolicyFormInput = {
      name: 'file-only',
      file: [{ paths: ['/etc/passwd'] }],
    }
    const out = formToYaml(input, 'Post')
    expect(out).not.toContain('sys_execve')
    expect(out).toContain('security_file_permission')
  })
})
