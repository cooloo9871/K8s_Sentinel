import yaml from 'js-yaml'

// Builds a Cilium network policy from the rule form.
//
// The shape follows Cilium's, not NeuVector's. A policy is anchored on ONE
// endpointSelector and lists the other side as peers, so the subject, the
// direction and the mode belong to the policy while the peer, ports and any L7
// rule belong to each rule. That is why the form has one "Applies to" above a
// list of rules, rather than a From and a To on every rule.

// The choice is not "does this rule allow or deny" — it is which policy model
// to write. A blacklist blocks what it names and leaves everything else alone; a
// whitelist permits what it names and drops everything else reaching the
// endpoint, because in Cilium an allow section switches that endpoint to
// default-deny for the direction.
export type CNPMode = 'blacklist' | 'whitelist'
export type CNPDirection = 'ingress' | 'egress'

// A namespaced policy's endpointSelector only ever matches endpoints in its own
// namespace, so governing pods elsewhere requires the cluster-wide kind.
export type CNPScope = 'namespaced' | 'cluster'

// Written on the policies this form generates, so editing one can reopen the
// form instead of dropping to raw YAML. Matches how Admission Policy does it.
export const BUILDER_ANNOTATION = 'sentinel.io/builder'

export interface CNPRule {
  peer: string
  ports?: string
  httpMethod?: string
  httpPath?: string
}

export interface CNPFormInput {
  name: string
  scope: CNPScope
  namespace: string
  comment?: string
  subject: string
  direction: CNPDirection
  mode: CNPMode
  rules: CNPRule[]
}

export const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD']

export function emptyRule(): CNPRule {
  return { peer: '', ports: '', httpMethod: '', httpPath: '' }
}

export function emptyForm(): CNPFormInput {
  return {
    name: '', scope: 'namespaced', namespace: '', comment: '',
    subject: '', direction: 'ingress', mode: 'whitelist', rules: [emptyRule()],
  }
}

// Cilium's reserved identities. Written bare in a peer field they select a
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

/** Parses a peer field: a bare Cilium entity, or `key=value` pairs. */
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

function ruleHasL7(r: CNPRule): boolean {
  return !!(r.httpMethod || r.httpPath?.trim())
}

/** What the peer field is called, which depends on which way the rule runs. */
export function peerLabel(direction: CNPDirection): string {
  return direction === 'ingress' ? 'From' : 'To'
}

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
  // A cluster-wide policy carries no namespace; a namespaced one is nothing
  // without one.
  if (input.scope === 'namespaced' && !input.namespace.trim()) {
    errors.push('Namespace is required for a namespaced policy.')
  }

  if (!input.subject.trim()) {
    errors.push('Applies to is required.')
  } else {
    const subject = parsePeer(input.subject)
    if (!subject) {
      errors.push('Applies to must be key=value pairs.')
    } else if (subject.entity) {
      // Only a label-selected endpoint can own a policy.
      errors.push('Applies to cannot be an entity like "world" — a policy is owned by the endpoints it selects.')
    }
  }

  if (input.rules.length === 0) errors.push('At least one rule is required.')

  const side = peerLabel(input.direction)
  input.rules.forEach((r, i) => {
    const at = input.rules.length > 1 ? `Rule ${i + 1}: ` : ''
    if (!r.peer.trim()) {
      errors.push(`${at}${side} is required.`)
    } else if (!parsePeer(r.peer)) {
      errors.push(`${at}${side} must be key=value pairs, or an entity like "world".`)
    }

    const ports = parsePorts(r.ports)
    if (ports === null) {
      errors.push(`${at}Ports must look like "80/TCP, 443" — protocol defaults to TCP.`)
    }

    if (ruleHasL7(r)) {
      // Cilium deny rules match on L3/L4 only. An HTTP rule under egressDeny or
      // ingressDeny is rejected by the API server, so refuse it here with a
      // reason instead of letting the apply fail.
      if (input.mode === 'blacklist') {
        errors.push(`${at}HTTP rules cannot be combined with a blacklist — Cilium deny rules match on L3/L4 only.`)
      }
      // An L7 rule lives under toPorts, so there has to be a port to attach it to.
      if (ports !== null && ports.length === 0) {
        errors.push(`${at}An HTTP rule needs at least one port.`)
      }
    }
  })
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

/** Renders one form rule as a Cilium rule for the given direction. */
function toCiliumRule(r: CNPRule, direction: CNPDirection): Rule {
  const peer = parsePeer(r.peer)!
  const isIngress = direction === 'ingress'

  let out: Rule
  if (peer.entity) {
    out = isIngress ? { fromEntities: [peer.entity] } : { toEntities: [peer.entity] }
  } else {
    const endpoints = [{ matchLabels: peer.matchLabels! }]
    out = isIngress ? { fromEndpoints: endpoints } : { toEndpoints: endpoints }
  }

  const ports = parsePorts(r.ports)!
  if (ports.length > 0) {
    const portRule: PortRule = { ports }
    if (ruleHasL7(r)) {
      const http: { method?: string; path?: string } = {}
      if (r.httpMethod) http.method = r.httpMethod
      if (r.httpPath?.trim()) http.path = r.httpPath.trim()
      portRule.rules = { http: [http] }
    }
    out.toPorts = [portRule]
  }
  return out
}

/**
 * Generates the policy YAML. Returns '' when the form is not yet valid, so the
 * caller can show validateCNPForm's reasons rather than a broken manifest.
 */
export function cnpFormToYaml(input: CNPFormInput): string {
  if (validateCNPForm(input).length > 0) return ''

  const subject = parsePeer(input.subject)!
  const isIngress = input.direction === 'ingress'
  const rules = input.rules.map(r => toCiliumRule(r, input.direction))

  const spec: Record<string, unknown> = {
    endpointSelector: { matchLabels: subject.matchLabels },
  }
  if (input.comment?.trim()) spec.description = input.comment.trim()

  if (input.mode === 'blacklist') {
    // Without this, adding a deny rule would also switch the endpoint to
    // default-deny for the whole direction — denying far more than the rules
    // the operator wrote.
    spec.enableDefaultDeny = { [input.direction]: false }
    spec[isIngress ? 'ingressDeny' : 'egressDeny'] = rules
  } else {
    spec[isIngress ? 'ingress' : 'egress'] = rules
  }

  const clusterWide = input.scope === 'cluster'
  return yaml.dump({
    apiVersion: 'cilium.io/v2',
    kind: clusterWide ? 'CiliumClusterwideNetworkPolicy' : 'CiliumNetworkPolicy',
    metadata: {
      name: input.name.trim(),
      ...(clusterWide ? {} : { namespace: input.namespace.trim() }),
      annotations: { [BUILDER_ANNOTATION]: 'true' },
    },
    spec,
  }, { noRefs: true, lineWidth: 120 })
}

/** Renders a peer back into the text the form's fields accept. */
function peerToText(peer: Peer): string {
  if (peer.entity) return peer.entity
  return Object.entries(peer.matchLabels ?? {})
    // Emit the alias, not the real key: it is what the field shows and it parses
    // back to the same label.
    .map(([k, v]) => `${k === NAMESPACE_KEY ? 'namespace' : k}=${v}`)
    .join(', ')
}

interface ParsedDoc {
  kind?: string
  metadata?: { name?: string; namespace?: string; annotations?: Record<string, unknown> }
  spec?: Record<string, unknown>
}

/**
 * Reads a policy this form generated back into form state, so editing it can
 * reopen the form. Returns null for anything else — a policy written by hand can
 * hold rules these fields cannot represent, and reopening it here would silently
 * discard them on save. The caller falls back to the YAML editor.
 */
export function tryParseCNPForm(rawYaml: string): CNPFormInput | null {
  let doc: ParsedDoc
  try {
    doc = yaml.load(rawYaml) as ParsedDoc
  } catch {
    return null
  }
  const clusterWide = doc?.kind === 'CiliumClusterwideNetworkPolicy'
  if (doc?.kind !== 'CiliumNetworkPolicy' && !clusterWide) return null
  if (String(doc.metadata?.annotations?.[BUILDER_ANNOTATION]) !== 'true') return null

  const spec = doc.spec
  const subjectLabels = (spec?.endpointSelector as { matchLabels?: Record<string, string> } | undefined)?.matchLabels
  if (!spec || !subjectLabels || Object.keys(subjectLabels).length === 0) return null

  // Exactly one rule section: a policy mixing allow with deny, or covering both
  // directions, is not something this form can show.
  const sections: { key: string; direction: CNPDirection; mode: CNPMode }[] = [
    { key: 'ingressDeny', direction: 'ingress', mode: 'blacklist' },
    { key: 'egressDeny', direction: 'egress', mode: 'blacklist' },
    { key: 'ingress', direction: 'ingress', mode: 'whitelist' },
    { key: 'egress', direction: 'egress', mode: 'whitelist' },
  ]
  const present = sections.filter(s => Array.isArray(spec[s.key]))
  if (present.length !== 1) return null
  const section = present[0]
  const ciliumRules = spec[section.key] as Rule[]
  if (ciliumRules.length === 0) return null

  const isIngress = section.direction === 'ingress'
  const rules: CNPRule[] = []
  for (const cr of ciliumRules) {
    const endpoints = isIngress ? cr.fromEndpoints : cr.toEndpoints
    const entities = isIngress ? cr.fromEntities : cr.toEntities
    let peer: Peer | null = null
    if (endpoints?.length === 1) peer = { matchLabels: endpoints[0].matchLabels }
    else if (entities?.length === 1) peer = { entity: entities[0] }
    if (!peer) return null

    const rule: CNPRule = { peer: peerToText(peer), ports: '', httpMethod: '', httpPath: '' }
    if (cr.toPorts) {
      if (cr.toPorts.length !== 1) return null
      const pr = cr.toPorts[0]
      rule.ports = (pr.ports ?? []).map(p => `${p.port}/${p.protocol}`).join(', ')
      const http = pr.rules?.http
      if (http) {
        if (http.length !== 1) return null
        rule.httpMethod = http[0].method ?? ''
        rule.httpPath = http[0].path ?? ''
      }
    }
    rules.push(rule)
  }

  return {
    name: doc.metadata?.name ?? '',
    scope: clusterWide ? 'cluster' : 'namespaced',
    namespace: clusterWide ? '' : (doc.metadata?.namespace ?? ''),
    comment: typeof spec.description === 'string' ? spec.description : '',
    subject: peerToText({ matchLabels: subjectLabels }),
    direction: section.direction,
    mode: section.mode,
    rules,
  }
}
