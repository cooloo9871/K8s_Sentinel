import { describe, it, expect } from 'vitest'
import {
  cnpFormToYaml, validateCNPForm, tryParseCNPForm, toMatchLabels, toLabelPairs,
  emptyForm, emptyRule, emptySection,
  type CNPFormInput, type CNPRule, type CNPMode, type CNPDirection,
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
  subjectNamespace: '',
  ingress: emptySection(),
  egress: {
    mode: 'blacklist',
    rules: [rule({
      peerLabels: [{ key: 'app', value: 'echo-server' }],
      ports: [{ port: '80', protocol: 'TCP' }],
    })],
  },
}

// Most cases are about one direction. This keeps them to their subject, and
// leaves the other direction as the empty section a parse reads back.
function only(
  direction: CNPDirection,
  mode: CNPMode,
  rules: CNPRule[],
  over: Partial<CNPFormInput> = {},
): CNPFormInput {
  return {
    ...base,
    ingress: direction === 'ingress' ? { mode, rules } : emptySection(),
    egress: direction === 'egress' ? { mode, rules } : emptySection(),
    ...over,
  }
}

const baseRules = base.egress.rules

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
    const out = cnpFormToYaml(only('ingress', 'blacklist', baseRules))
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
    const out = cnpFormToYaml(only('ingress', 'whitelist', [
      rule({ peerLabels: [{ key: 'app', value: 'frontend' }], ports: [{ port: '80', protocol: 'TCP' }] }),
      rule({ peerLabels: [{ key: 'app', value: 'admin' }], ports: [{ port: '8080', protocol: 'TCP' }] }),
      rule({ peerKind: 'entity', peerEntity: 'world' }),
    ]))
    expect((out.match(/endpointSelector/g) ?? []).length).toBe(1)
    expect((out.match(/fromEndpoints/g) ?? []).length).toBe(2)
    expect(out).toContain('fromEntities')
    expect(out).toContain('- world')
  })

  it('emits every port of a rule', () => {
    const out = cnpFormToYaml(only('egress', 'blacklist', [rule({
      peerLabels: [{ key: 'app', value: 'echo-server' }],
      ports: [
        { port: '80', protocol: 'TCP' },
        { port: '443', protocol: 'TCP' },
        { port: '53', protocol: 'UDP' },
      ],
    })]))
    expect(out).toContain('protocol: UDP')
    expect((out.match(/- port:/g) ?? []).length).toBe(3)
  })

  // Without this a one-line deny rule would lock down the endpoint's whole
  // direction, denying far more than what was written.
  it('opts out of default-deny for a blacklist, in the rule direction only', () => {
    expect(cnpFormToYaml(base)).toContain('egress: false')
    expect(cnpFormToYaml(only('ingress', 'blacklist', baseRules))).toContain('ingress: false')
  })

  it('uses the allow sections and leaves default-deny alone for a whitelist', () => {
    const out = cnpFormToYaml(only('egress', 'whitelist', baseRules))
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
    const out = cnpFormToYaml(only('egress', 'whitelist', [rule({
      peerLabels: [{ key: 'app', value: 'echo' }],
      ports: [{ port: '80', protocol: 'TCP' }],
      http: [{ method: 'GET', path: '/api/.*' }],
    })]))
    expect(out).toContain('method: GET')
    expect(out).toContain('path: /api/.*')
  })

  // Cilium's rules.http is a list of alternatives, so several entries belong
  // under one toPorts.
  it('emits every HTTP entry of a rule', () => {
    const out = cnpFormToYaml(only('egress', 'whitelist', [rule({
      peerLabels: [{ key: 'app', value: 'echo' }],
      ports: [{ port: '80', protocol: 'TCP' }],
      http: [
        { method: 'GET', path: '/api/.*' },
        { method: 'POST', path: '/submit' },
        { method: '', path: '/public' },
      ],
    })]))
    expect((out.match(/- method:|- path:/g) ?? []).length).toBe(3)
    expect(out).toContain('method: POST')
    // A blank method means any method, so only the path is written.
    expect(out).toContain('path: /public')
  })

  it('omits toPorts entirely when no port is given', () => {
    expect(cnpFormToYaml(only('egress', 'blacklist', [
      rule({ peerLabels: [{ key: 'app', value: 'echo' }] }),
    ]))).not.toContain('toPorts')
  })

  it('returns nothing when the form is invalid', () => {
    expect(cnpFormToYaml({ ...base, subject: [] })).toBe('')
    expect(cnpFormToYaml({ ...base, name: 'Bad_Name' })).toBe('')
    expect(cnpFormToYaml({ ...base, ingress: emptySection(), egress: emptySection() })).toBe('')
  })
})

// One policy covering both ways is ordinary — "this pod talks to the database
// and nothing else reaches it" is a single intent, and splitting it across two
// policies makes it easy to delete half of it.
describe('cnpFormToYaml — both directions', () => {
  const bothWays = {
    ...base,
    ingress: { mode: 'whitelist' as const, rules: [rule({ peerLabels: [{ key: 'app', value: 'frontend' }] })] },
    egress: { mode: 'whitelist' as const, rules: [rule({ peerLabels: [{ key: 'app', value: 'db' }] })] },
  }

  it('writes both sections into one policy', () => {
    const out = cnpFormToYaml(bothWays)
    expect(out).toContain('fromEndpoints')
    expect(out).toContain('toEndpoints')
    // Still one policy, anchored on one subject.
    expect((out.match(/endpointSelector/g) ?? []).length).toBe(1)
  })

  // enableDefaultDeny is keyed by direction, so denying one way must not touch
  // what the other way was written to do.
  it('opts out of default-deny only for the direction that is a blacklist', () => {
    const out = cnpFormToYaml({ ...bothWays, egress: { mode: 'blacklist', rules: bothWays.egress.rules } })
    expect(out).toContain('egressDeny')
    expect(out).toContain('egress: false')
    expect(out).not.toContain('ingress: false')
  })

  // An empty ingress: [] would switch the endpoint to default-deny for a
  // direction nobody filled in.
  it('leaves an empty section out of the manifest', () => {
    const out = cnpFormToYaml(base)
    expect(out).not.toContain('ingress')
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
    expect(errors).toContain('Applies to needs a label or a namespace')
    expect(errors).toContain('At least one rule is required')
  })

  // A new policy picks neither direction for the operator, so the form opens
  // with both empty and the first thing done is choosing one.
  it('opens with no rules in either direction', () => {
    const blank = emptyForm()
    expect(blank.ingress.rules).toEqual([])
    expect(blank.egress.rules).toEqual([])
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
    expect(validateCNPForm(only('egress', 'blacklist', [
      rule({ peerLabels: [{ key: 'a', value: 'b' }], ports: [{ port: '', protocol: 'TCP' }] }),
    ])).join(' ')).toContain('is empty')

    expect(validateCNPForm(only('egress', 'blacklist', [
      rule({ peerLabels: [{ key: 'a', value: 'b' }], ports: [{ port: '70000', protocol: 'TCP' }] }),
    ])).join(' ')).toContain('between 1 and 65535')
  })

  it('does not ask a cluster-wide policy for a namespace', () => {
    expect(validateCNPForm({ ...base, scope: 'cluster', namespace: '' })).toEqual([])
  })

  // With several rules the operator needs to know which one is wrong — and now
  // which direction it is in, since both can carry rules.
  it('names the direction and numbers the rule a problem is in', () => {
    const errors = validateCNPForm(only('egress', 'blacklist', [
      rule({ peerLabels: [{ key: 'app', value: 'ok' }] }),
      rule({ peerLabels: [] }),
    ])).join(' ')
    expect(errors).toContain('Egress rule 2:')
    expect(errors).not.toContain('Egress rule 1:')
  })

  // A complaint about one direction must not read as though it were the other.
  it('tells the two directions apart', () => {
    const errors = validateCNPForm({
      ...base,
      ingress: { mode: 'whitelist', rules: [rule({ peerLabels: [] })] },
    }).join(' ')
    expect(errors).toContain('Ingress: From needs a label or a namespace')
    expect(errors).not.toContain('Egress')
  })

  it('refuses an entity it does not know', () => {
    expect(validateCNPForm(only('egress', 'blacklist', [
      rule({ peerKind: 'entity', peerEntity: 'outside' }),
    ])).join(' ')).toContain('not a Cilium entity')
  })

  // Cilium rejects an HTTP rule inside egressDeny/ingressDeny, so say why here
  // rather than letting the apply fail with an API server error.
  it('refuses HTTP rules on a blacklist, with the reason', () => {
    expect(validateCNPForm(only('egress', 'blacklist', [rule({
      peerLabels: [{ key: 'a', value: 'b' }],
      ports: [{ port: '80', protocol: 'TCP' }],
      http: [{ method: 'GET', path: '' }],
    })])).join(' ')).toContain('L3/L4 only')
  })

  it('requires a port for an HTTP rule to attach to', () => {
    expect(validateCNPForm(only('egress', 'whitelist', [
      rule({ peerLabels: [{ key: 'a', value: 'b' }], http: [{ method: '', path: '/x' }] }),
    ])).join(' ')).toContain('needs at least one port')
  })

  // A row with neither is what leaving HTTP out already does, so it looks like a
  // restriction and is not.
  it('catches an HTTP row with neither a method nor a path', () => {
    expect(validateCNPForm(only('egress', 'whitelist', [rule({
      peerLabels: [{ key: 'a', value: 'b' }],
      ports: [{ port: '80', protocol: 'TCP' }],
      http: [{ method: '', path: '' }],
    })])).join(' ')).toContain('is empty')
  })

  // Emptying one direction is how the operator says "this policy is one-way".
  it('accepts a policy with rules in one direction only', () => {
    expect(validateCNPForm({ ...base, ingress: emptySection() })).toEqual([])
  })

  it('still requires a rule somewhere', () => {
    expect(validateCNPForm({ ...base, ingress: emptySection(), egress: emptySection() }).join(' '))
      .toContain('At least one rule is required')
  })
})

describe('tryParseCNPForm', () => {
  // What the form generated must read back as what was typed, or Edit would show
  // something different from what is deployed.
  it('round-trips every field', () => {
    const forms: CNPFormInput[] = [
      base,
      only('ingress', 'blacklist', baseRules),
      only('egress', 'whitelist', baseRules),
      { ...base, comment: 'why this exists' },
      { ...base, scope: 'cluster', namespace: '' },
      { ...base, subject: [{ key: 'app', value: 'api' }, { key: 'env', value: 'prod' }] },
      only('egress', 'blacklist', [rule({ peerKind: 'entity', peerEntity: 'world' })]),
      only('ingress', 'whitelist', [
        rule({
          peerLabels: [{ key: 'app', value: 'frontend' }],
          ports: [{ port: '80', protocol: 'TCP' }, { port: '443', protocol: 'TCP' }],
          http: [{ method: 'GET', path: '/api/.*' }, { method: 'POST', path: '/submit' }],
        }),
        rule({ peerLabels: [{ key: 'app', value: 'admin' }], ports: [{ port: '8080', protocol: 'TCP' }] }),
      ]),
      // Both directions at once, in either combination of modes.
      {
        ...base,
        ingress: { mode: 'whitelist', rules: [rule({ peerLabels: [{ key: 'app', value: 'frontend' }] })] },
        egress: { mode: 'whitelist', rules: [rule({ peerLabels: [{ key: 'app', value: 'db' }] })] },
      },
      {
        ...base,
        ingress: { mode: 'blacklist', rules: [rule({ peerKind: 'entity', peerEntity: 'world' })] },
        egress: { mode: 'whitelist', rules: [rule({ peerLabels: [{ key: 'app', value: 'db' }] })] },
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

  // The mode belongs to the direction, so one direction holding both an allow
  // and a deny section has nowhere to go in the form.
  it('refuses an allow and a deny in the same direction', () => {
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
  ingressDeny:
    - fromEndpoints:
        - matchLabels:
            role: other
`)).toBeNull()
  })

  // The opposite case: two directions is what the form now expresses, so it must
  // open rather than fall back to YAML.
  it('reads both directions of a hand-written policy', () => {
    const parsed = tryParseCNPForm(`apiVersion: cilium.io/v2
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
  egressDeny:
    - toEndpoints:
        - matchLabels:
            role: db
`)
    expect(parsed?.ingress.mode).toBe('whitelist')
    expect(parsed?.ingress.rules[0].peerLabels).toEqual([{ key: 'role', value: 'frontend' }])
    expect(parsed?.egress.mode).toBe('blacklist')
    expect(parsed?.egress.rules[0].peerLabels).toEqual([{ key: 'role', value: 'db' }])
  })

  // A policy with neither section governs nothing, and the form would open blank.
  it('refuses a policy with no rules at all', () => {
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

// Selecting a peer in another namespace is the case that catches everyone: a
// namespaced policy matches only its own namespace unless the namespace is
// named as a label. The form accepts a short alias for the real key, which
// nobody would guess.
describe('cross-namespace peers', () => {
  it('rewrites the namespace aliases to the label Cilium reads', () => {
    for (const alias of ['namespace', 'ns']) {
      expect(toMatchLabels([
        { key: 'k8s-app', value: 'kube-dns' },
        { key: alias, value: 'kube-system' },
      ])).toEqual({
        'k8s-app': 'kube-dns',
        'io.kubernetes.pod.namespace': 'kube-system',
      })
    }
  })

  it('accepts the full key unchanged', () => {
    expect(toMatchLabels([
      { key: 'io.kubernetes.pod.namespace', value: 'kube-system' },
    ])).toEqual({ 'io.kubernetes.pod.namespace': 'kube-system' })
  })

  // Reopening the policy has to show something the field would accept back.
  it('shows the alias when reading a policy back', () => {
    expect(toLabelPairs({
      'k8s-app': 'kube-dns',
      'io.kubernetes.pod.namespace': 'kube-system',
    })).toEqual([
      { key: 'k8s-app', value: 'kube-dns' },
      { key: 'namespace', value: 'kube-system' },
    ])
  })
})

// The peer namespace is a field of its own now. It has to reach the YAML as the
// label Cilium reads, and come back out of it into the same field rather than
// reappearing as a label row the form would then write twice.
describe('peer namespace field', () => {
  const withPeerNs = (ns: string): CNPFormInput => ({
    ...emptyForm(),
    name: 'allow-dns', scope: 'namespaced', namespace: 'net-lab',
    subject: [{ key: 'app', value: 'traffic-generator' }],
    ingress: emptySection(),
    egress: {
      mode: 'whitelist',
      rules: [rule({
        peerLabels: [{ key: 'k8s-app', value: 'kube-dns' }],
        peerNamespace: ns,
      })],
    },
  })

  it('writes the namespace into the peer selector', () => {
    const yaml = cnpFormToYaml(withPeerNs('kube-system'))
    expect(yaml).toContain('io.kubernetes.pod.namespace: kube-system')
    expect(yaml).toContain('k8s-app: kube-dns')
  })

  // Empty means Cilium's default, which is the policy's own namespace. Writing
  // the key with an empty value would select nothing at all.
  it('omits the namespace when none is chosen', () => {
    expect(cnpFormToYaml(withPeerNs(''))).not.toContain('io.kubernetes.pod.namespace')
  })

  it('reads the namespace back into its own field', () => {
    const parsed = tryParseCNPForm(cnpFormToYaml(withPeerNs('kube-system')))
    expect(parsed?.egress.rules[0].peerNamespace).toBe('kube-system')
    // And not left among the labels, or saving would write it from both places.
    expect(parsed?.egress.rules[0].peerLabels).toEqual([{ key: 'k8s-app', value: 'kube-dns' }])
  })
})

// "Everything in ingress-nginx" is a policy shape of its own. Cilium writes it
// as a label, which is not something anyone types from memory, so the form has
// a field for it.
describe('subject namespace field', () => {
  it('writes the namespace into the endpointSelector', () => {
    const out = cnpFormToYaml({
      ...base, scope: 'cluster', namespace: '',
      subject: [{ key: '', value: '' }],
      subjectNamespace: 'ingress-nginx',
    })
    expect(out).toContain('io.kubernetes.pod.namespace: ingress-nginx')
  })

  // A namespace on its own is a complete subject — it selects everything in it.
  it('accepts a namespace with no labels beside it', () => {
    expect(validateCNPForm({
      ...base, subject: [{ key: '', value: '' }], subjectNamespace: 'ingress-nginx',
    })).toEqual([])
  })

  // Neither is not. An empty endpointSelector on a cluster-wide policy governs
  // every endpoint in the cluster.
  it('still rejects a subject that selects nothing', () => {
    expect(validateCNPForm({
      ...base, subject: [{ key: '', value: '' }], subjectNamespace: '',
    }).join(' ')).toContain('Applies to')
  })

  it('reads the namespace back into its own field', () => {
    const parsed = tryParseCNPForm(cnpFormToYaml({
      ...base,
      subject: [{ key: 'app', value: 'api' }],
      subjectNamespace: 'ingress-nginx',
    }))
    expect(parsed?.subjectNamespace).toBe('ingress-nginx')
    expect(parsed?.subject).toEqual([{ key: 'app', value: 'api' }])
  })
})

// The peer takes a namespace on its own too — "anything in kube-system" — and
// only refuses when it would select nothing at all.
describe('peer namespace alone', () => {
  const peerOnlyNs = (ns: string) => only('egress', 'blacklist', [
    rule({ peerLabels: [{ key: '', value: '' }], peerNamespace: ns }),
  ])

  it('accepts a peer that is only a namespace', () => {
    expect(validateCNPForm(peerOnlyNs('kube-system'))).toEqual([])
  })

  it('writes it as the selector', () => {
    expect(cnpFormToYaml(peerOnlyNs('kube-system')))
      .toContain('io.kubernetes.pod.namespace: kube-system')
  })

  it('still refuses a peer that selects nothing', () => {
    expect(validateCNPForm(peerOnlyNs('')).join(' ')).toContain('needs a label or a namespace')
  })
})
