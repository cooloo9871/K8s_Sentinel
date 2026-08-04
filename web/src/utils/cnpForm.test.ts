import { describe, it, expect } from 'vitest'
import {
  cnpFormToYaml, validateCNPForm, tryParseCNPForm, toMatchLabels, toLabelPairs,
  emptyForm, emptyRule, type CNPFormInput, type CNPRule,
} from './cnpForm'

function rule(over: Partial<CNPRule> = {}): CNPRule {
  return { ...emptyRule(), ...over }
}

const base: CNPFormInput = {
  name: 'deny-tg-to-echo',
  scope: 'namespaced',
  namespace: 'net-lab',
  comment: '',
  subject: [{ key: 'app', value: 'traffic-generator' }],
  direction: 'egress',
  mode: 'blacklist',
  rules: [rule({
    peerLabels: [{ key: 'app', value: 'echo-server' }],
    ports: [{ port: '80', protocol: 'TCP' }],
  })],
}

describe('toMatchLabels', () => {
  it('drops blank rows and keeps the filled ones', () => {
    expect(toMatchLabels([
      { key: 'app', value: 'api' },
      { key: '', value: '' },
      { key: 'env', value: 'prod' },
    ])).toEqual({ app: 'api', env: 'prod' })
  })

  it('trims, so a stray space does not become part of a label', () => {
    expect(toMatchLabels([{ key: ' app ', value: ' api ' }])).toEqual({ app: 'api' })
  })

  // This is how a rule reaches a workload in another namespace.
  it('expands the namespace aliases to the label Cilium actually uses', () => {
    expect(toMatchLabels([{ key: 'namespace', value: 'prod' }]))
      .toEqual({ 'io.kubernetes.pod.namespace': 'prod' })
    expect(toMatchLabels([{ key: 'ns', value: 'prod' }]))
      .toEqual({ 'io.kubernetes.pod.namespace': 'prod' })
  })
})

describe('toLabelPairs', () => {
  it('shows the namespace alias rather than the real key', () => {
    expect(toLabelPairs({ 'io.kubernetes.pod.namespace': 'prod' }))
      .toEqual([{ key: 'namespace', value: 'prod' }])
  })

  it('always yields at least one row for the form to render', () => {
    expect(toLabelPairs({})).toEqual([{ key: '', value: '' }])
  })
})

describe('cnpFormToYaml', () => {
  it('anchors an egress deny on the subject and names the peer', () => {
    const out = cnpFormToYaml(base)
    expect(out).toContain('kind: CiliumNetworkPolicy')
    expect(out).toContain('namespace: net-lab')
    expect(out.indexOf('app: traffic-generator')).toBeLessThan(out.indexOf('egressDeny'))
    expect(out).toContain('toEndpoints')
    expect(out).toContain('app: echo-server')
  })

  it('puts the peer on the from side for an ingress rule', () => {
    const out = cnpFormToYaml({ ...base, direction: 'ingress' })
    expect(out).toContain('ingressDeny')
    expect(out).toContain('fromEndpoints')
  })

  it('joins several labels into one selector', () => {
    const out = cnpFormToYaml({
      ...base,
      subject: [{ key: 'app', value: 'api' }, { key: 'env', value: 'prod' }],
    })
    expect(out).toContain('app: api')
    expect(out).toContain('env: prod')
  })

  // A CNP has one endpointSelector, so every rule shares the subject.
  it('emits one entry per rule under a single selector', () => {
    const out = cnpFormToYaml({
      ...base,
      mode: 'whitelist',
      direction: 'ingress',
      rules: [
        rule({ peerLabels: [{ key: 'app', value: 'frontend' }], ports: [{ port: '80', protocol: 'TCP' }] }),
        rule({ peerLabels: [{ key: 'app', value: 'admin' }], ports: [{ port: '8080', protocol: 'TCP' }] }),
        rule({ peerKind: 'entity', peerEntity: 'world' }),
      ],
    })
    expect((out.match(/endpointSelector/g) ?? []).length).toBe(1)
    expect((out.match(/fromEndpoints/g) ?? []).length).toBe(2)
    expect(out).toContain('fromEntities')
    expect(out).toContain('- world')
  })

  it('emits every port of a rule', () => {
    const out = cnpFormToYaml({
      ...base,
      rules: [rule({
        peerLabels: [{ key: 'app', value: 'echo-server' }],
        ports: [
          { port: '80', protocol: 'TCP' },
          { port: '443', protocol: 'TCP' },
          { port: '53', protocol: 'UDP' },
        ],
      })],
    })
    expect(out).toContain('protocol: UDP')
    expect((out.match(/- port:/g) ?? []).length).toBe(3)
  })

  // Without this a one-line deny rule would lock down the endpoint's whole
  // direction, denying far more than what was written.
  it('opts out of default-deny for a blacklist, in the rule direction only', () => {
    expect(cnpFormToYaml(base)).toContain('egress: false')
    expect(cnpFormToYaml({ ...base, direction: 'ingress' })).toContain('ingress: false')
  })

  it('uses the allow sections and leaves default-deny alone for a whitelist', () => {
    const out = cnpFormToYaml({ ...base, mode: 'whitelist' })
    expect(out).toContain('egress:')
    expect(out).not.toContain('egressDeny')
    expect(out).not.toContain('enableDefaultDeny')
  })

  // A namespaced policy's endpointSelector only matches its own namespace, so
  // governing pods elsewhere means the cluster-wide kind.
  it('emits the cluster-wide kind with no namespace', () => {
    const out = cnpFormToYaml({
      ...base,
      scope: 'cluster',
      namespace: '',
      subject: [{ key: 'app', value: 'echo' }, { key: 'namespace', value: 'other' }],
    })
    expect(out).toContain('kind: CiliumClusterwideNetworkPolicy')
    expect(out).not.toContain('namespace: net-lab')
    expect(out).toContain('io.kubernetes.pod.namespace: other')
  })

  it('attaches an HTTP rule under toPorts', () => {
    const out = cnpFormToYaml({
      ...base,
      mode: 'whitelist',
      rules: [rule({
        peerLabels: [{ key: 'app', value: 'echo' }],
        ports: [{ port: '80', protocol: 'TCP' }],
        http: [{ method: 'GET', path: '/api/.*' }],
      })],
    })
    expect(out).toContain('method: GET')
    expect(out).toContain('path: /api/.*')
  })

  // Cilium's rules.http is a list of alternatives, so several entries belong
  // under one toPorts.
  it('emits every HTTP entry of a rule', () => {
    const out = cnpFormToYaml({
      ...base,
      mode: 'whitelist',
      rules: [rule({
        peerLabels: [{ key: 'app', value: 'echo' }],
        ports: [{ port: '80', protocol: 'TCP' }],
        http: [
          { method: 'GET', path: '/api/.*' },
          { method: 'POST', path: '/submit' },
          { method: '', path: '/public' },
        ],
      })],
    })
    expect((out.match(/- method:|- path:/g) ?? []).length).toBe(3)
    expect(out).toContain('method: POST')
    // A blank method means any method, so only the path is written.
    expect(out).toContain('path: /public')
  })

  it('omits toPorts entirely when no port is given', () => {
    expect(cnpFormToYaml({
      ...base,
      rules: [rule({ peerLabels: [{ key: 'app', value: 'echo' }] })],
    })).not.toContain('toPorts')
  })

  it('returns nothing when the form is invalid', () => {
    expect(cnpFormToYaml({ ...base, subject: [] })).toBe('')
    expect(cnpFormToYaml({ ...base, name: 'Bad_Name' })).toBe('')
    expect(cnpFormToYaml({ ...base, rules: [] })).toBe('')
  })
})

describe('validateCNPForm', () => {
  it('accepts a complete form', () => {
    expect(validateCNPForm(base)).toEqual([])
  })

  it('rejects a blank form with one reason per missing field', () => {
    const errors = validateCNPForm(emptyForm()).join(' ')
    expect(errors).toContain('Name is required')
    expect(errors).toContain('Namespace is required')
    expect(errors).toContain('Applies to needs at least one label')
    expect(errors).toContain('From needs at least one label')
  })

  // A half-typed row selects nothing, which is the failure this form exists to
  // prevent — so it is named rather than quietly dropped.
  it('catches a label row with only one half filled in', () => {
    expect(validateCNPForm({
      ...base,
      subject: [{ key: 'app', value: 'api' }, { key: 'env', value: '' }],
    }).join(' ')).toContain('has a key but no value')

    expect(validateCNPForm({
      ...base,
      subject: [{ key: 'app', value: 'api' }, { key: '', value: 'prod' }],
    }).join(' ')).toContain('has a value but no key')
  })

  it('catches an empty or out-of-range port row', () => {
    expect(validateCNPForm({
      ...base,
      rules: [rule({ peerLabels: [{ key: 'a', value: 'b' }], ports: [{ port: '', protocol: 'TCP' }] })],
    }).join(' ')).toContain('is empty')

    expect(validateCNPForm({
      ...base,
      rules: [rule({ peerLabels: [{ key: 'a', value: 'b' }], ports: [{ port: '70000', protocol: 'TCP' }] })],
    }).join(' ')).toContain('between 1 and 65535')
  })

  it('does not ask a cluster-wide policy for a namespace', () => {
    expect(validateCNPForm({ ...base, scope: 'cluster', namespace: '' })).toEqual([])
  })

  // With several rules the operator needs to know which one is wrong.
  it('numbers the rule a problem is in', () => {
    const errors = validateCNPForm({
      ...base,
      rules: [
        rule({ peerLabels: [{ key: 'app', value: 'ok' }] }),
        rule({ peerLabels: [] }),
      ],
    }).join(' ')
    expect(errors).toContain('Rule 2:')
    expect(errors).not.toContain('Rule 1:')
  })

  it('refuses an entity it does not know', () => {
    expect(validateCNPForm({
      ...base,
      rules: [rule({ peerKind: 'entity', peerEntity: 'outside' })],
    }).join(' ')).toContain('not a Cilium entity')
  })

  // Cilium rejects an HTTP rule inside egressDeny/ingressDeny, so say why here
  // rather than letting the apply fail with an API server error.
  it('refuses HTTP rules on a blacklist, with the reason', () => {
    expect(validateCNPForm({
      ...base,
      rules: [rule({
        peerLabels: [{ key: 'a', value: 'b' }],
        ports: [{ port: '80', protocol: 'TCP' }],
        http: [{ method: 'GET', path: '' }],
      })],
    }).join(' ')).toContain('L3/L4 only')
  })

  it('requires a port for an HTTP rule to attach to', () => {
    expect(validateCNPForm({
      ...base,
      mode: 'whitelist',
      rules: [rule({ peerLabels: [{ key: 'a', value: 'b' }], http: [{ method: '', path: '/x' }] })],
    }).join(' ')).toContain('needs at least one port')
  })

  // A row with neither is what leaving HTTP out already does, so it looks like a
  // restriction and is not.
  it('catches an HTTP row with neither a method nor a path', () => {
    expect(validateCNPForm({
      ...base,
      mode: 'whitelist',
      rules: [rule({
        peerLabels: [{ key: 'a', value: 'b' }],
        ports: [{ port: '80', protocol: 'TCP' }],
        http: [{ method: '', path: '' }],
      })],
    }).join(' ')).toContain('is empty')
  })
})

describe('tryParseCNPForm', () => {
  // What the form generated must read back as what was typed, or Edit would show
  // something different from what is deployed.
  it('round-trips every field', () => {
    const forms: CNPFormInput[] = [
      base,
      { ...base, direction: 'ingress' },
      { ...base, mode: 'whitelist' },
      { ...base, comment: 'why this exists' },
      { ...base, scope: 'cluster', namespace: '' },
      { ...base, subject: [{ key: 'app', value: 'api' }, { key: 'env', value: 'prod' }] },
      { ...base, rules: [rule({ peerKind: 'entity', peerEntity: 'world' })] },
      {
        ...base, mode: 'whitelist', direction: 'ingress',
        rules: [
          rule({
            peerLabels: [{ key: 'app', value: 'frontend' }],
            ports: [{ port: '80', protocol: 'TCP' }, { port: '443', protocol: 'TCP' }],
            http: [{ method: 'GET', path: '/api/.*' }, { method: 'POST', path: '/submit' }],
          }),
          rule({ peerLabels: [{ key: 'app', value: 'admin' }], ports: [{ port: '8080', protocol: 'TCP' }] }),
        ],
      },
    ]
    for (const form of forms) {
      const parsed = tryParseCNPForm(cnpFormToYaml(form))
      expect(parsed, JSON.stringify(form)).not.toBeNull()
      expect(parsed).toEqual(form)
    }
  })

  // A hand-written policy can hold rules the form cannot show, and reopening it
  // there would drop them on save.
  it('refuses a policy without the builder annotation', () => {
    const yaml = cnpFormToYaml(base).replace("sentinel.io/builder: 'true'", "other: 'true'")
    expect(tryParseCNPForm(yaml)).toBeNull()
  })

  it('refuses both directions in one policy', () => {
    expect(tryParseCNPForm(`apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: x
  namespace: demo
  annotations:
    sentinel.io/builder: 'true'
spec:
  endpointSelector:
    matchLabels:
      role: backend
  ingress:
    - fromEndpoints:
        - matchLabels:
            role: frontend
  egress:
    - toEndpoints:
        - matchLabels:
            role: db
`)).toBeNull()
  })

  it('refuses a rule with more peers than one field can show', () => {
    expect(tryParseCNPForm(`apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: x
  namespace: demo
  annotations:
    sentinel.io/builder: 'true'
spec:
  endpointSelector:
    matchLabels:
      role: backend
  ingressDeny:
    - fromEndpoints:
        - matchLabels:
            role: frontend
        - matchLabels:
            role: other
`)).toBeNull()
  })

  it('refuses another kind, and unparseable text', () => {
    expect(tryParseCNPForm('kind: NetworkPolicy')).toBeNull()
    expect(tryParseCNPForm('::: not yaml :::')).toBeNull()
  })
})

describe('tryParseCNPForm — selectors the form cannot show', () => {
  // The form requires at least one label, so an empty selector — every endpoint —
  // would open as a blank field that refuses to save until a valid policy was
  // changed. The subject was already guarded; the peer was not.
  it('refuses an empty peer selector', () => {
    expect(tryParseCNPForm(`apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: x
  namespace: demo
  annotations:
    sentinel.io/builder: 'true'
spec:
  endpointSelector:
    matchLabels:
      role: backend
  ingress:
    - fromEndpoints:
        - {}
`)).toBeNull()
  })

  it('refuses an empty subject selector', () => {
    expect(tryParseCNPForm(`apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: x
  namespace: demo
  annotations:
    sentinel.io/builder: 'true'
spec:
  endpointSelector: {}
  ingress:
    - fromEndpoints:
        - matchLabels:
            role: frontend
`)).toBeNull()
  })
})
