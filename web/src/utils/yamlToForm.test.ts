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
