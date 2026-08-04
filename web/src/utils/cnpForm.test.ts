import { describe, it, expect } from 'vitest'
import { cnpFormToYaml, parsePeer, parsePorts, validateCNPForm, type CNPFormInput } from './cnpForm'

const base: CNPFormInput = {
  name: 'deny-tg-to-echo',
  namespace: 'net-lab',
  from: 'app=traffic-generator',
  to: 'app=echo-server',
  direction: 'egress',
  ports: '80/TCP',
  action: 'deny',
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

  // Nobody remembers the real key, so the form accepts the short forms.
  it('expands the namespace aliases to the label Cilium actually uses', () => {
    expect(parsePeer('namespace=prod')).toEqual({
      matchLabels: { 'io.kubernetes.pod.namespace': 'prod' },
    })
    expect(parsePeer('ns=prod')).toEqual({
      matchLabels: { 'io.kubernetes.pod.namespace': 'prod' },
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
  it('anchors an egress deny on the source and names the destination as peer', () => {
    const out = cnpFormToYaml(base)
    expect(out).toContain('kind: CiliumNetworkPolicy')
    expect(out).toContain('name: deny-tg-to-echo')
    expect(out).toContain('namespace: net-lab')
    // endpointSelector is the From side
    expect(out.indexOf('app: traffic-generator')).toBeLessThan(out.indexOf('egressDeny'))
    expect(out).toContain('egressDeny')
    expect(out).toContain('toEndpoints')
    expect(out).toContain('app: echo-server')
    expect(out).not.toContain('ingressDeny')
  })

  it('anchors an ingress deny on the destination and names the source as peer', () => {
    const out = cnpFormToYaml({ ...base, direction: 'ingress' })
    expect(out.indexOf('app: echo-server')).toBeLessThan(out.indexOf('ingressDeny'))
    expect(out).toContain('ingressDeny')
    expect(out).toContain('fromEndpoints')
    expect(out).toContain('app: traffic-generator')
    expect(out).not.toContain('egressDeny')
  })

  // Without this a one-line deny rule would lock down the endpoint's whole
  // direction, denying far more than what was written.
  it('opts out of default-deny for a deny rule, in the rule direction only', () => {
    expect(cnpFormToYaml(base)).toContain('egress: false')
    expect(cnpFormToYaml({ ...base, direction: 'ingress' })).toContain('ingress: false')
  })

  it('uses the allow sections and leaves default-deny alone for an allow rule', () => {
    const out = cnpFormToYaml({ ...base, action: 'allow' })
    expect(out).toContain('egress:')
    expect(out).not.toContain('egressDeny')
    expect(out).not.toContain('enableDefaultDeny')
  })

  it('renders an entity peer as toEntities rather than a label selector', () => {
    const out = cnpFormToYaml({ ...base, to: 'world', action: 'allow' })
    expect(out).toContain('toEntities')
    expect(out).toContain('- world')
    expect(out).not.toContain('toEndpoints')
  })

  it('attaches an HTTP rule under toPorts', () => {
    const out = cnpFormToYaml({
      ...base, action: 'allow', httpMethod: 'GET', httpPath: '/api/.*',
    })
    expect(out).toContain('toPorts')
    expect(out).toContain('rules:')
    expect(out).toContain('http:')
    expect(out).toContain('method: GET')
    expect(out).toContain('path: /api/.*')
  })

  it('omits toPorts entirely when no port is given', () => {
    const out = cnpFormToYaml({ ...base, ports: '' })
    expect(out).not.toContain('toPorts')
  })

  it('returns nothing when the form is invalid', () => {
    expect(cnpFormToYaml({ ...base, from: '' })).toBe('')
    expect(cnpFormToYaml({ ...base, name: 'Bad_Name' })).toBe('')
  })

  // An entity has no labels, so it cannot own the policy.
  it('returns nothing when the enforced side is an entity', () => {
    expect(cnpFormToYaml({ ...base, from: 'world' })).toBe('')
    expect(cnpFormToYaml({ ...base, to: 'world', direction: 'ingress' })).toBe('')
  })
})

describe('validateCNPForm', () => {
  it('accepts a complete form', () => {
    expect(validateCNPForm(base)).toEqual([])
  })

  it('requires name, namespace, from and to', () => {
    const errors = validateCNPForm({ ...base, name: '', namespace: '', from: '', to: '' })
    expect(errors).toHaveLength(4)
  })

  // Cilium rejects an HTTP rule inside egressDeny/ingressDeny, so say why here
  // rather than letting the apply fail with an API server error.
  it('refuses HTTP rules on a deny action, with the reason', () => {
    const errors = validateCNPForm({ ...base, httpMethod: 'GET' })
    expect(errors.join(' ')).toContain('L3/L4 only')
  })

  it('requires a port for an HTTP rule to attach to', () => {
    const errors = validateCNPForm({ ...base, action: 'allow', ports: '', httpPath: '/x' })
    expect(errors.join(' ')).toContain('needs at least one port')
  })
})
