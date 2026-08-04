import { describe, it, expect } from 'vitest'
import {
  cnpFormToYaml, parsePeer, parsePorts, validateCNPForm, tryParseCNPForm,
  emptyForm, type CNPFormInput,
} from './cnpForm'

const base: CNPFormInput = {
  name: 'deny-tg-to-echo',
  scope: 'namespaced',
  namespace: 'net-lab',
  subject: 'app=traffic-generator',
  direction: 'egress',
  mode: 'blacklist',
  rules: [{ peer: 'app=echo-server', ports: '80/TCP', httpMethod: '', httpPath: '' }],
}

describe('parsePeer', () => {
  it('reads key=value pairs', () => {
    expect(parsePeer('app=echo-server')).toEqual({ matchLabels: { app: 'echo-server' } })
    expect(parsePeer('app=api, env=prod')).toEqual({ matchLabels: { app: 'api', env: 'prod' } })
  })

  it('reads a bare Cilium entity', () => {
    expect(parsePeer('world')).toEqual({ entity: 'world' })
    expect(parsePeer('cluster')).toEqual({ entity: 'cluster' })
  })

  // Nobody remembers the real key, so the form accepts the short forms. This is
  // how a rule reaches a workload in another namespace.
  it('expands the namespace aliases to the label Cilium actually uses', () => {
    expect(parsePeer('namespace=prod')).toEqual({
      matchLabels: { 'io.kubernetes.pod.namespace': 'prod' },
    })
    expect(parsePeer('ns=prod')).toEqual({
      matchLabels: { 'io.kubernetes.pod.namespace': 'prod' },
    })
    expect(parsePeer('app=api, ns=prod')).toEqual({
      matchLabels: { app: 'api', 'io.kubernetes.pod.namespace': 'prod' },
    })
  })

  it('rejects text that is neither an entity nor key=value', () => {
    expect(parsePeer('echo-server')).toBeNull()
    expect(parsePeer('app=')).toBeNull()
    expect(parsePeer('=value')).toBeNull()
    expect(parsePeer('')).toBeNull()
  })
})

describe('parsePorts', () => {
  it('defaults the protocol to TCP', () => {
    expect(parsePorts('80')).toEqual([{ port: '80', protocol: 'TCP' }])
  })

  it('reads several ports with explicit protocols', () => {
    expect(parsePorts('80/TCP, 53/udp')).toEqual([
      { port: '80', protocol: 'TCP' },
      { port: '53', protocol: 'UDP' },
    ])
  })

  it('treats blank as no port restriction', () => {
    expect(parsePorts('')).toEqual([])
    expect(parsePorts(undefined)).toEqual([])
  })

  it('rejects nonsense rather than emitting a policy that matches nothing', () => {
    expect(parsePorts('http')).toBeNull()
    expect(parsePorts('0')).toBeNull()
    expect(parsePorts('70000')).toBeNull()
    expect(parsePorts('80/ICMP')).toBeNull()
  })
})

describe('cnpFormToYaml', () => {
  it('anchors an egress deny on the subject and names the peer', () => {
    const out = cnpFormToYaml(base)
    expect(out).toContain('kind: CiliumNetworkPolicy')
    expect(out).toContain('name: deny-tg-to-echo')
    expect(out).toContain('namespace: net-lab')
    expect(out.indexOf('app: traffic-generator')).toBeLessThan(out.indexOf('egressDeny'))
    expect(out).toContain('egressDeny')
    expect(out).toContain('toEndpoints')
    expect(out).toContain('app: echo-server')
    expect(out).not.toContain('ingressDeny')
  })

  it('puts the peer on the from side for an ingress rule', () => {
    const out = cnpFormToYaml({ ...base, direction: 'ingress' })
    expect(out).toContain('ingressDeny')
    expect(out).toContain('fromEndpoints')
    expect(out).not.toContain('egressDeny')
  })

  // A CNP has one endpointSelector, so every rule shares the subject and only
  // the peer varies. That is what lets one policy hold several rules.
  it('emits one entry per rule under a single selector', () => {
    const out = cnpFormToYaml({
      ...base,
      mode: 'whitelist',
      direction: 'ingress',
      subject: 'app=echo-server',
      rules: [
        { peer: 'app=frontend', ports: '80/TCP' },
        { peer: 'app=admin', ports: '8080/TCP' },
        { peer: 'world', ports: '' },
      ],
    })
    expect((out.match(/endpointSelector/g) ?? []).length).toBe(1)
    expect((out.match(/fromEndpoints/g) ?? []).length).toBe(2)
    expect(out).toContain('app: frontend')
    expect(out).toContain('app: admin')
    expect(out).toContain('fromEntities')
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
      subject: 'app=echo-server, namespace=other',
    })
    expect(out).toContain('kind: CiliumClusterwideNetworkPolicy')
    expect(out).not.toContain('namespace: net-lab')
    // The subject's namespace label is how it reaches into that namespace.
    expect(out).toContain('io.kubernetes.pod.namespace: other')
  })

  it('attaches an HTTP rule under toPorts', () => {
    const out = cnpFormToYaml({
      ...base,
      mode: 'whitelist',
      rules: [{ peer: 'app=echo-server', ports: '80/TCP', httpMethod: 'GET', httpPath: '/api/.*' }],
    })
    expect(out).toContain('toPorts')
    expect(out).toContain('http:')
    expect(out).toContain('method: GET')
    expect(out).toContain('path: /api/.*')
  })

  it('omits toPorts entirely when no port is given', () => {
    expect(cnpFormToYaml({ ...base, rules: [{ peer: 'app=echo-server', ports: '' }] }))
      .not.toContain('toPorts')
  })

  it('returns nothing when the form is invalid', () => {
    expect(cnpFormToYaml({ ...base, subject: '' })).toBe('')
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
    expect(errors).toContain('Applies to is required')
    expect(errors).toContain('From is required')
  })

  // An entity has no labels, so it cannot own a policy.
  it('refuses an entity as the subject', () => {
    expect(validateCNPForm({ ...base, subject: 'world' }).join(' '))
      .toContain('cannot be an entity')
  })

  it('does not ask a cluster-wide policy for a namespace', () => {
    expect(validateCNPForm({ ...base, scope: 'cluster', namespace: '' })).toEqual([])
  })

  // With several rules the operator needs to know which one is wrong.
  it('numbers the rule a problem is in', () => {
    const errors = validateCNPForm({
      ...base,
      rules: [{ peer: 'app=ok' }, { peer: '' }],
    }).join(' ')
    expect(errors).toContain('Rule 2:')
    expect(errors).not.toContain('Rule 1:')
  })

  // Cilium rejects an HTTP rule inside egressDeny/ingressDeny, so say why here
  // rather than letting the apply fail with an API server error.
  it('refuses HTTP rules on a blacklist, with the reason', () => {
    const errors = validateCNPForm({
      ...base,
      rules: [{ peer: 'app=x', ports: '80', httpMethod: 'GET' }],
    }).join(' ')
    expect(errors).toContain('L3/L4 only')
  })

  it('requires a port for an HTTP rule to attach to', () => {
    const errors = validateCNPForm({
      ...base,
      mode: 'whitelist',
      rules: [{ peer: 'app=x', ports: '', httpPath: '/x' }],
    }).join(' ')
    expect(errors).toContain('needs at least one port')
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
      { ...base, rules: [{ peer: 'world', ports: '', httpMethod: '', httpPath: '' }] },
      {
        ...base, mode: 'whitelist', direction: 'ingress', subject: 'app=echo-server',
        rules: [
          { peer: 'app=frontend', ports: '80/TCP', httpMethod: 'GET', httpPath: '/api/.*' },
          { peer: 'app=admin', ports: '8080/TCP', httpMethod: '', httpPath: '' },
        ],
      },
    ]
    for (const form of forms) {
      const parsed = tryParseCNPForm(cnpFormToYaml(form))
      expect(parsed, JSON.stringify(form)).not.toBeNull()
      expect(parsed).toEqual({
        ...form,
        comment: form.comment ?? '',
        rules: form.rules.map(r => ({
          peer: r.peer,
          ports: r.ports ?? '',
          httpMethod: r.httpMethod ?? '',
          httpPath: r.httpPath ?? '',
        })),
      })
    }
  })

  // ns= and namespace= are aliases for one label, so only one of them can come
  // back. The canonical spelling is the long one.
  it('normalizes the ns= alias on the way back', () => {
    const parsed = tryParseCNPForm(cnpFormToYaml({
      ...base, mode: 'whitelist', rules: [{ peer: 'app=x, ns=other' }],
    }))
    expect(parsed?.rules[0].peer).toContain('namespace=other')
  })

  // A hand-written policy can hold rules the form cannot show, and reopening it
  // there would drop them on save.
  it('refuses a policy without the builder annotation', () => {
    const yaml = cnpFormToYaml(base).replace("sentinel.io/builder: 'true'", "other: 'true'")
    expect(tryParseCNPForm(yaml)).toBeNull()
  })

  it('refuses both directions in one policy', () => {
    const bothWays = `apiVersion: cilium.io/v2
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
`
    expect(tryParseCNPForm(bothWays)).toBeNull()
  })

  it('refuses a rule with more peers than one field can show', () => {
    const twoPeers = `apiVersion: cilium.io/v2
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
`
    expect(tryParseCNPForm(twoPeers)).toBeNull()
  })

  it('refuses another kind, and unparseable text', () => {
    expect(tryParseCNPForm('kind: NetworkPolicy')).toBeNull()
    expect(tryParseCNPForm('::: not yaml :::')).toBeNull()
  })
})
