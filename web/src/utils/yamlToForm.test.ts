import { describe, it, expect } from 'vitest'
import { yamlToForm } from './yamlToForm'

// Reopening a saved policy in the form has to read back what the builder wrote.
// Getting the mode wrong is not a display bug: the form saves what it shows, so
// a blacklist reopened as a whitelist inverts the policy on the next save.

function processPolicy(operator: string, values: string[]): string {
  return `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: p
spec:
  kprobes:
    - call: sys_execve
      syscall: true
      args:
        - index: 0
          type: string
      selectors:
        - matchArgs:
            - index: 0
              operator: ${operator}
              values:
${values.map(v => `                - ${v}`).join('\n')}
          matchActions:
            - action: Sigkill
`
}

describe('yamlToForm — process rules', () => {
  it('reads what the builder writes now', () => {
    const whitelist = yamlToForm(processPolicy('NotEqual', ['/usr/sbin/nginx']))
    expect(whitelist?.processMode).toBe('whitelist')
    expect(whitelist?.process?.[0].binaries).toEqual(['/usr/sbin/nginx'])

    const blacklist = yamlToForm(processPolicy('Equal', ['/bin/bash']))
    expect(blacklist?.processMode).toBe('blacklist')
  })

  // Policies saved before absolute paths were required are still in clusters.
  // Reading only the current operators would leave processMode unset on those,
  // and unset defaults to whitelist — so a blacklist would come back inverted.
  it('still reads the operators it used to write', () => {
    const whitelist = yamlToForm(processPolicy('NotPostfix', ['usr/sbin/nginx']))
    expect(whitelist?.processMode).toBe('whitelist')

    const blacklist = yamlToForm(processPolicy('Postfix', ['bin/bash']))
    expect(blacklist?.processMode).toBe('blacklist')
  })

  // Those older values have the leading slash stripped. The form shows absolute
  // paths, and saving one back writes it as an absolute path.
  it('restores the leading slash on older values', () => {
    const form = yamlToForm(processPolicy('NotPostfix', ['bin/bash']))
    expect(form?.process?.[0].binaries).toEqual(['/bin/bash'])
  })
})

// The monitor-all-exec template. An execve kprobe with no matchArgs matches
// every execution, which a form built around a list of binaries cannot express.
// Loading it into the form showed nothing, and saving would have written the
// policy back as spec: {} — the rules silently gone.
describe('yamlToForm — policies the form cannot represent', () => {
  it('refuses an execve kprobe that matches everything', () => {
    const monitorAll = `apiVersion: cilium.io/v1alpha1
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
`
    expect(yamlToForm(monitorAll)).toBeNull()
  })

  // One representable rule must not carry an unrepresentable one into the form,
  // where saving would drop it.
  it('refuses a policy where only some kprobes fit the form', () => {
    const mixed = `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: mixed
spec:
  kprobes:
    - call: sys_execve
      syscall: true
      args:
        - index: 0
          type: string
      selectors:
        - matchArgs:
            - index: 0
              operator: NotEqual
              values:
                - /bin/bash
          matchActions:
            - action: Sigkill
    - call: sys_execve
      syscall: true
      selectors:
        - matchActions:
            - action: Post
`
    expect(yamlToForm(mixed)).toBeNull()
  })

  // The one it can represent still opens in the form.
  it('accepts a policy it can show in full', () => {
    const ok = `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: allow-nginx
spec:
  kprobes:
    - call: sys_execve
      syscall: true
      args:
        - index: 0
          type: string
      selectors:
        - matchArgs:
            - index: 0
              operator: NotEqual
              values:
                - /usr/sbin/nginx
          matchActions:
            - action: Sigkill
`
    expect(yamlToForm(ok)?.process?.[0].binaries).toEqual(['/usr/sbin/nginx'])
  })
})

// The built-in monitor-all-file template. Its paths parse cleanly, so counting
// rules alone let it into the form — where saving would have dropped its
// `return`/`returnArg` and rewritten its Postfix selector as Prefix, turning
// ".bashrc" into a rule matching nothing.
describe('yamlToForm — fidelity, not just rule count', () => {
  const fileKprobe = (extra: string, selector: string) => `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: t
spec:
  kprobes:
    - call: security_file_permission
      syscall: false
${extra}      args:
        - index: 0
          type: file
      selectors:
${selector}`

  const prefixSelector = `        - matchArgs:
            - index: 0
              operator: Prefix
              values:
                - /etc/shadow
          matchActions:
            - action: Post
`

  it('accepts a file rule it can express in full', () => {
    expect(yamlToForm(fileKprobe('', prefixSelector))?.file?.[0].paths).toEqual(['/etc/shadow'])
  })

  it('refuses a kprobe carrying return and returnArg', () => {
    const withReturn = `      return: true
      returnArg:
        index: 0
        type: int
`
    expect(yamlToForm(fileKprobe(withReturn, prefixSelector))).toBeNull()
  })

  it('refuses a Postfix file selector, which it would rewrite as Prefix', () => {
    const postfix = `        - matchArgs:
            - index: 0
              operator: Postfix
              values:
                - .bashrc
          matchActions:
            - action: Post
`
    expect(yamlToForm(fileKprobe('', postfix))).toBeNull()
  })

  it('refuses a kprobe carrying a message or tags', () => {
    expect(yamlToForm(fileKprobe('      message: "sensitive file"\n', prefixSelector))).toBeNull()
    expect(yamlToForm(fileKprobe('      tags: ["observability"]\n', prefixSelector))).toBeNull()
  })

  it('refuses selector matchers it does not model', () => {
    const withNamespaces = `        - matchNamespaces:
            - namespace: Pid
              operator: In
              values:
                - host_ns
          matchArgs:
            - index: 0
              operator: Prefix
              values:
                - /etc/shadow
          matchActions:
            - action: Post
`
    expect(yamlToForm(fileKprobe('', withNamespaces))).toBeNull()
  })

  it('refuses an action carrying more than the action itself', () => {
    const override = `        - matchArgs:
            - index: 0
              operator: Prefix
              values:
                - /etc/shadow
          matchActions:
            - action: Override
              argError: -1
`
    expect(yamlToForm(fileKprobe('', override))).toBeNull()
  })
})

// A policy as the cluster returns it: Tetragon's CRD schema defaults fields on
// persist — return: false on the kprobe, maxData/resolve/returnCopy on every
// arg — so nothing the builder writes ever comes back byte-identical. Treating
// those defaults as user data meant every form-built policy in a real cluster
// refused to reopen in the form. Same lesson the VAP builder learned with the
// apiserver's own defaulting.
describe('cluster-defaulted fields', () => {
  const clusterReturned = `apiVersion: cilium.io/v1alpha1
kind: TracingPolicyNamespaced
metadata:
  annotations:
    sentinel.io/created-by: admin
  creationTimestamp: "2026-08-18T03:45:01Z"
  generation: 2
  name: test2
  namespace: default
  resourceVersion: "11470760"
  uid: bf9fc65a-677d-4ace-bb1b-a9d279e3d83a
spec:
  kprobes:
  - args:
    - index: 0
      maxData: false
      resolve: ""
      returnCopy: false
      type: file
    - index: 1
      maxData: false
      resolve: ""
      returnCopy: false
      type: int
    call: security_file_permission
    return: false
    selectors:
    - matchActions:
      - action: Sigkill
      matchArgs:
      - index: 0
        operator: Prefix
        values:
        - /etc
      - index: 1
        operator: Equal
        values:
        - "2"
    syscall: false
  podSelector:
    matchLabels:
      run: test2
`

  it('reopens a form-built policy the cluster has defaulted', () => {
    const form = yamlToForm(clusterReturned)
    expect(form).not.toBeNull()
    expect(form?.file?.[0]?.paths).toEqual(['/etc'])
    expect(form?.file?.[0]?.permission).toBe('write')
    expect(form?.podSelector).toEqual({ run: 'test2' })
  })

  // Only the default value passes: a kprobe that really collects the return
  // value is something the form cannot show, and must still fall back.
  it('still refuses return: true', () => {
    expect(yamlToForm(clusterReturned.replace('return: false', 'return: true'))).toBeNull()
  })
})
