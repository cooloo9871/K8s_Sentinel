import yaml from 'js-yaml'

// Builds a Cilium network policy from the rule form.
//
// The shape follows Cilium's, not NeuVector's. A policy is anchored on ONE
// endpointSelector and lists the other side as peers, so the subject, the
// direction and the mode belong to the policy while the peer, ports and any L7
// rule belong to each rule. That is why the form has one "Applies to" above a
// list of rules, rather than a From and a To on every rule.
//
// Labels and ports are structured rather than typed as text. A mistyped
// `app=web` does not fail — it selects nothing, and a policy that silently
// governs no pods is the worst outcome this form can produce.

// The choice is not "does this rule allow or deny" — it is which policy model to
// write. A blacklist blocks what it names and leaves everything else alone; a
// whitelist permits what it names and drops everything else reaching the
// endpoint, because in Cilium an allow section switches that endpoint to
// default-deny for the direction.
export type CNPMode = 'blacklist' | 'whitelist'
export type CNPDirection = 'ingress' | 'egress'

// A namespaced policy's endpointSelector only ever matches endpoints in its own
// namespace, so governing pods elsewhere requires the cluster-wide kind.
export type CNPScope = 'namespaced' | 'cluster'

// A peer is either a set of labels or one of Cilium's reserved identities.
// `world` in particular has no labels to select, and is how a rule names traffic
// outside the cluster.
export type PeerKind = 'labels' | 'entity'

// Written on the policies this form generates, so editing one can reopen the
// form instead of dropping to raw YAML. Matches how Admission Policy does it.
export const BUILDER_ANNOTATION = 'sentinel.io/builder'

export const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD']
export const PROTOCOLS = ['TCP', 'UDP', 'SCTP']
export const ENTITIES = [
  'world', 'cluster', 'host', 'remote-node', 'all', 'init', 'health', 'unmanaged',
]

export interface LabelPair {
  key: string
  value: string
}

export interface PortEntry {
  port: string
  protocol: string
}

export interface CNPRule {
  peerKind: PeerKind
  peerLabels: LabelPair[]
  peerEntity: string
  ports: PortEntry[]
  httpMethod?: string
  httpPath?: string
}

export interface CNPFormInput {
  name: string
  scope: CNPScope
  namespace: string
  comment?: string
  subject: LabelPair[]
  direction: CNPDirection
  mode: CNPMode
  rules: CNPRule[]
}

export function emptyLabel(): LabelPair {
  return { key: '', value: '' }
}

export function emptyPort(): PortEntry {
  return { port: '', protocol: 'TCP' }
}

export function emptyRule(): CNPRule {
  return {
    peerKind: 'labels',
    peerLabels: [emptyLabel()],
    peerEntity: 'world',
    ports: [],
    httpMethod: '',
    httpPath: '',
  }
}

export function emptyForm(): CNPFormInput {
  return {
    name: '', scope: 'namespaced', namespace: '', comment: '',
    subject: [emptyLabel()], direction: 'ingress', mode: 'whitelist',
    rules: [emptyRule()],
  }
}

// Cilium exposes a pod's namespace as a label, so selecting across namespaces
// means writing that key. Nobody remembers it, hence the aliases.
const NAMESPACE_KEY = 'io.kubernetes.pod.namespace'
const NAMESPACE_ALIASES = new Set(['namespace', 'ns'])

/** Turns the form's label rows into a Cilium matchLabels map. */
export function toMatchLabels(pairs: LabelPair[]): Record<string, string> {
  const out: Record<string, string> = {}
  for (const p of pairs) {
    const key = p.key.trim()
    const value = p.value.trim()
    if (!key || !value) continue
    out[NAMESPACE_ALIASES.has(key) ? NAMESPACE_KEY : key] = value
  }
  return out
}

/** Turns a Cilium matchLabels map back into form rows. */
export function toLabelPairs(labels: Record<string, string>): LabelPair[] {
  const pairs = Object.entries(labels).map(([key, value]) => ({
    // Show the alias: it is what the field accepts and it maps back to the same
    // label.
    key: key === NAMESPACE_KEY ? 'namespace' : key,
    value,
  }))
  return pairs.length > 0 ? pairs : [emptyLabel()]
}

/** Reports label rows that are half filled in, which select nothing. */
function labelRowErrors(pairs: LabelPair[], what: string): string[] {
  const errors: string[] = []
  pairs.forEach((p, i) => {
    const key = p.key.trim()
    const value = p.value.trim()
    const at = pairs.length > 1 ? ` ${i + 1}` : ''
    if (!key && value) errors.push(`${what} label${at} has a value but no key.`)
    else if (key && !value) errors.push(`${what} label${at} has a key but no value.`)
  })
  return errors
}

const DNS1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/

function ruleHasL7(r: CNPRule): boolean {
  return !!(r.httpMethod || r.httpPath?.trim())
}

/** The ports of a rule, dropping rows left empty. */
function filledPorts(r: CNPRule): PortEntry[] {
  return r.ports.filter(p => p.port.trim() !== '')
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

  if (Object.keys(toMatchLabels(input.subject)).length === 0) {
    errors.push('Applies to needs at least one label.')
  }
  errors.push(...labelRowErrors(input.subject, 'Applies to'))

  if (input.rules.length === 0) errors.push('At least one rule is required.')

  const side = peerLabel(input.direction)
  input.rules.forEach((r, i) => {
    const at = input.rules.length > 1 ? `Rule ${i + 1}: ` : ''

    if (r.peerKind === 'entity') {
      if (!ENTITIES.includes(r.peerEntity)) {
        errors.push(`${at}${r.peerEntity || 'The entity'} is not a Cilium entity.`)
      }
    } else {
      if (Object.keys(toMatchLabels(r.peerLabels)).length === 0) {
        errors.push(`${at}${side} needs at least one label.`)
      }
      errors.push(...labelRowErrors(r.peerLabels, `${at}${side}`))
    }

    r.ports.forEach((p, pi) => {
      const port = p.port.trim()
      const label = r.ports.length > 1 ? ` ${pi + 1}` : ''
      // An empty row is dropped rather than silently narrowing nothing, but say
      // so — a row that looks like a restriction and is not would mislead.
      if (!port) {
        errors.push(`${at}Port${label} is empty — fill it in or remove it.`)
      } else if (!/^\d+$/.test(port) || Number(port) < 1 || Number(port) > 65535) {
        errors.push(`${at}Port${label} must be a number between 1 and 65535.`)
      }
      if (!PROTOCOLS.includes(p.protocol)) {
        errors.push(`${at}Port${label} has an unsupported protocol.`)
      }
    })

    if (ruleHasL7(r)) {
      // Cilium deny rules match on L3/L4 only. An HTTP rule under egressDeny or
      // ingressDeny is rejected by the API server, so refuse it here with a
      // reason instead of letting the apply fail.
      if (input.mode === 'blacklist') {
        errors.push(`${at}HTTP rules cannot be combined with a blacklist — Cilium deny rules match on L3/L4 only.`)
      }
      // An L7 rule lives under toPorts, so there has to be a port to attach it to.
      if (filledPorts(r).length === 0) {
        errors.push(`${at}An HTTP rule needs at least one port.`)
      }
    }
  })
  return errors
}

interface PortRule {
  ports: PortEntry[]
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
  const isIngress = direction === 'ingress'

  let out: Rule
  if (r.peerKind === 'entity') {
    out = isIngress ? { fromEntities: [r.peerEntity] } : { toEntities: [r.peerEntity] }
  } else {
    const endpoints = [{ matchLabels: toMatchLabels(r.peerLabels) }]
    out = isIngress ? { fromEndpoints: endpoints } : { toEndpoints: endpoints }
  }

  const ports = filledPorts(r).map(p => ({ port: p.port.trim(), protocol: p.protocol }))
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

  const isIngress = input.direction === 'ingress'
  const rules = input.rules.map(r => toCiliumRule(r, input.direction))

  const spec: Record<string, unknown> = {
    endpointSelector: { matchLabels: toMatchLabels(input.subject) },
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

    const rule = emptyRule()
    if (endpoints?.length === 1) {
      rule.peerKind = 'labels'
      rule.peerLabels = toLabelPairs(endpoints[0].matchLabels ?? {})
    } else if (entities?.length === 1) {
      rule.peerKind = 'entity'
      rule.peerEntity = entities[0]
    } else {
      return null
    }

    if (cr.toPorts) {
      if (cr.toPorts.length !== 1) return null
      const pr = cr.toPorts[0]
      rule.ports = (pr.ports ?? []).map(p => ({ port: p.port, protocol: p.protocol }))
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
    subject: toLabelPairs(subjectLabels),
    direction: section.direction,
    mode: section.mode,
    rules,
  }
}
