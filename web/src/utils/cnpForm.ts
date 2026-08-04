import yaml from 'js-yaml'

// Builds a CiliumNetworkPolicy from the simple rule form. NeuVector states a
// rule as a flat "From → To"; Cilium anchors a policy on one endpoint and lists
// the other side as a peer, so the form asks which side to enforce on and this
// module does the translation.

export type CNPAction = 'allow' | 'deny'
export type CNPDirection = 'ingress' | 'egress'

export interface CNPFormInput {
  name: string
  namespace: string
  comment?: string
  from: string
  to: string
  direction: CNPDirection
  ports?: string
  action: CNPAction
  httpMethod?: string
  httpPath?: string
}

export const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD']

// Cilium's reserved identities. Written bare in a From/To field they select a
// category of peer rather than a set of labels.
const ENTITIES = new Set([
  'world', 'host', 'cluster', 'remote-node', 'all', 'init', 'health', 'unmanaged',
])

// Cilium exposes a pod's namespace as a label, so selecting across namespaces
// means writing that key. Nobody remembers it, hence the aliases.
const NAMESPACE_KEY = 'io.kubernetes.pod.namespace'
const NAMESPACE_ALIASES = new Set(['namespace', 'ns'])

export interface Peer {
  entity?: string
  matchLabels?: Record<string, string>
}

/** Parses a From/To field: a bare Cilium entity, or `key=value` pairs. */
export function parsePeer(text: string): Peer | null {
  const trimmed = text.trim()
  if (!trimmed) return null
  if (ENTITIES.has(trimmed)) return { entity: trimmed }

  const matchLabels: Record<string, string> = {}
  for (const part of trimmed.split(',')) {
    const piece = part.trim()
    if (!piece) continue
    const eq = piece.indexOf('=')
    if (eq < 1) return null // not key=value, and not an entity either
    const key = piece.slice(0, eq).trim()
    const value = piece.slice(eq + 1).trim()
    if (!key || !value) return null
    matchLabels[NAMESPACE_ALIASES.has(key) ? NAMESPACE_KEY : key] = value
  }
  return Object.keys(matchLabels).length > 0 ? { matchLabels } : null
}

export interface Port {
  port: string
  protocol: string
}

/** Parses `80/TCP, 443, 53/UDP` — protocol defaults to TCP. */
export function parsePorts(text: string | undefined): Port[] | null {
  if (!text || !text.trim()) return []
  const out: Port[] = []
  for (const part of text.split(',')) {
    const piece = part.trim()
    if (!piece) continue
    const [portRaw, protoRaw] = piece.split('/')
    const port = portRaw.trim()
    if (!/^\d+$/.test(port)) return null
    const n = Number(port)
    if (n < 1 || n > 65535) return null
    const protocol = (protoRaw ?? 'TCP').trim().toUpperCase()
    if (protocol !== 'TCP' && protocol !== 'UDP' && protocol !== 'SCTP') return null
    out.push({ port, protocol })
  }
  return out
}

const DNS1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/

/**
 * Reports what stops the form from producing a valid policy. Empty means the
 * form is ready.
 */
export function validateCNPForm(input: CNPFormInput): string[] {
  const errors: string[] = []

  if (!input.name.trim()) {
    errors.push('Name is required.')
  } else if (!DNS1123.test(input.name.trim())) {
    errors.push('Name must be lowercase alphanumeric or "-", starting and ending alphanumeric.')
  }
  if (!input.namespace.trim()) errors.push('Namespace is required.')

  if (!input.from.trim()) errors.push('From is required.')
  else if (!parsePeer(input.from)) errors.push('From must be key=value pairs, or an entity like "world".')

  if (!input.to.trim()) errors.push('To is required.')
  else if (!parsePeer(input.to)) errors.push('To must be key=value pairs, or an entity like "world".')

  const ports = parsePorts(input.ports)
  if (ports === null) errors.push('Ports must look like "80/TCP, 443" — protocol defaults to TCP.')

  const hasL7 = !!(input.httpMethod || input.httpPath?.trim())
  if (hasL7) {
    // Cilium deny rules match on L3/L4 only. An HTTP rule under egressDeny or
    // ingressDeny is rejected by the API server, so refuse it here with a
    // reason instead of letting the apply fail.
    if (input.action === 'deny') {
      errors.push('HTTP rules cannot be combined with Deny — Cilium deny rules match on L3/L4 only.')
    }
    // An L7 rule lives under toPorts, so there has to be a port to attach it to.
    if (ports !== null && ports.length === 0) {
      errors.push('An HTTP rule needs at least one port.')
    }
  }
  return errors
}

interface PortRule {
  ports: Port[]
  rules?: { http: { method?: string; path?: string }[] }
}

interface Rule {
  fromEndpoints?: { matchLabels: Record<string, string> }[]
  toEndpoints?: { matchLabels: Record<string, string> }[]
  fromEntities?: string[]
  toEntities?: string[]
  toPorts?: PortRule[]
}

/** Renders the peer as the correct rule field for the direction. */
function peerRule(peer: Peer, direction: CNPDirection): Rule {
  const isIngress = direction === 'ingress'
  if (peer.entity) {
    return isIngress ? { fromEntities: [peer.entity] } : { toEntities: [peer.entity] }
  }
  const endpoints = [{ matchLabels: peer.matchLabels! }]
  return isIngress ? { fromEndpoints: endpoints } : { toEndpoints: endpoints }
}

/**
 * Generates the policy YAML. Returns '' when the form is not yet valid, so the
 * caller can show validateCNPForm's reasons rather than a broken manifest.
 */
export function cnpFormToYaml(input: CNPFormInput): string {
  if (validateCNPForm(input).length > 0) return ''

  const from = parsePeer(input.from)!
  const to = parsePeer(input.to)!
  const ports = parsePorts(input.ports)!
  const isIngress = input.direction === 'ingress'

  // The policy is anchored on the side being enforced: for an ingress rule the
  // destination owns the policy and the source is the peer, and the other way
  // round for egress.
  const subject = isIngress ? to : from
  const peer = isIngress ? from : to
  if (subject.entity) {
    // An entity cannot own a policy — only a label-selected endpoint can.
    return ''
  }

  const rule: Rule = peerRule(peer, input.direction)
  if (ports.length > 0) {
    const portRule: PortRule = { ports }
    if (input.httpMethod || input.httpPath?.trim()) {
      const http: { method?: string; path?: string } = {}
      if (input.httpMethod) http.method = input.httpMethod
      if (input.httpPath?.trim()) http.path = input.httpPath.trim()
      portRule.rules = { http: [http] }
    }
    rule.toPorts = [portRule]
  }

  const spec: Record<string, unknown> = {
    endpointSelector: { matchLabels: subject.matchLabels },
  }
  if (input.comment?.trim()) spec.description = input.comment.trim()

  if (input.action === 'deny') {
    // Without this, adding a deny rule would also switch the endpoint to
    // default-deny for the whole direction — denying far more than the one rule
    // the operator wrote.
    spec.enableDefaultDeny = { [input.direction]: false }
    spec[isIngress ? 'ingressDeny' : 'egressDeny'] = [rule]
  } else {
    spec[isIngress ? 'ingress' : 'egress'] = [rule]
  }

  return yaml.dump({
    apiVersion: 'cilium.io/v2',
    kind: 'CiliumNetworkPolicy',
    metadata: { name: input.name.trim(), namespace: input.namespace.trim() },
    spec,
  }, { noRefs: true, lineWidth: 120 })
}
