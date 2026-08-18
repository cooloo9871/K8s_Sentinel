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

// A peer is a set of labels, one of Cilium's reserved identities, an address
// range, or a domain name. The last two are for destinations that have neither
// labels nor an identity worth naming: an external database subnet, a SaaS
// endpoint.
export type PeerKind = 'labels' | 'entity' | 'cidr' | 'fqdn'

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

// Cilium's rules.http is a list, and the entries are alternatives: a request
// matching any of them matches the rule.
export interface HttpRule {
  method: string
  path: string
}

export interface CNPRule {
  peerKind: PeerKind
  peerLabels: LabelPair[]
  // Which namespace the peer is in. Its own field rather than a label row,
  // because a namespaced policy matches only its own namespace unless this is
  // set, and "add a row keyed namespace" is not something anyone finds.
  // Empty means the policy's own namespace, which is Cilium's default.
  peerNamespace: string
  peerEntity: string
  // An IP or CIDR; a bare IP is written as a /32 (or /128 for IPv6).
  peerCIDR: string
  // A domain name, with * as a wildcard. Egress whitelists only: Cilium learns
  // a name's addresses from the DNS answers the pod receives, so there is
  // nothing to match on ingress or in a deny rule.
  peerFQDN: string
  ports: PortEntry[]
  http: HttpRule[]
}

/**
 * One direction of a policy: its rules, and the mode they are written in.
 *
 * The mode belongs here rather than to the policy because it decides whether
 * that direction goes default-deny — an `ingress` section does, `ingressDeny`
 * does not, and enableDefaultDeny is itself keyed by direction. It cannot sit on
 * a rule either: two rules in one direction cannot be one allow and one deny.
 */
export interface CNPSection {
  mode: CNPMode
  rules: CNPRule[]
}

export function emptySection(mode: CNPMode = 'whitelist'): CNPSection {
  return { mode, rules: [] }
}

export interface CNPFormInput {
  name: string
  scope: CNPScope
  namespace: string
  comment?: string
  subject: LabelPair[]
  // Which namespace the subject is in, as its own field. Selecting a whole
  // namespace is a policy shape in its own right — "everything in
  // ingress-nginx" — and Cilium expresses it as a label, which is not something
  // anyone types from memory. Empty leaves the selector to its labels alone.
  subjectNamespace: string
  // Both directions, either of which may be empty. A section with no rules is
  // left out of the manifest entirely, so filling in one is the same policy the
  // form produced when it could only express one.
  ingress: CNPSection
  egress: CNPSection
}

/** The two sections, paired with the direction each one writes. */
export function sectionsOf(input: CNPFormInput): { direction: CNPDirection; section: CNPSection }[] {
  return [
    { direction: 'ingress', section: input.ingress },
    { direction: 'egress', section: input.egress },
  ]
}

export function emptyLabel(): LabelPair {
  return { key: '', value: '' }
}

export function emptyPort(): PortEntry {
  return { port: '', protocol: 'TCP' }
}

export function emptyHttp(): HttpRule {
  return { method: '', path: '' }
}

export function emptyRule(): CNPRule {
  return {
    peerKind: 'labels',
    peerLabels: [emptyLabel()],
    peerNamespace: '',
    peerEntity: 'world',
    peerCIDR: '',
    peerFQDN: '',
    ports: [],
    http: [],
  }
}

// Both directions start empty. Opening with a rule already in ingress would be
// the form choosing a direction for the operator, and the choice is the first
// thing a network policy is about.
export function emptyForm(): CNPFormInput {
  return {
    name: '', scope: 'namespaced', namespace: '', comment: '',
    subject: [emptyLabel()], subjectNamespace: '',
    ingress: emptySection(),
    egress: emptySection(),
  }
}

// Cilium exposes a pod's namespace as a label, so selecting across namespaces
// means writing that key. Nobody remembers it, hence the aliases.
export const NAMESPACE_KEY = 'io.kubernetes.pod.namespace'
const NAMESPACE_ALIASES = new Set(['namespace', 'ns'])

/** Turns the form's label rows into a Cilium matchLabels map. */
/** The subject selector: its labels, plus the namespace when one is chosen. */
export function subjectMatchLabels(input: CNPFormInput): Record<string, string> {
  const labels = toMatchLabels(input.subject)
  if (input.subjectNamespace.trim()) {
    labels[NAMESPACE_KEY] = input.subjectNamespace.trim()
  }
  return labels
}

/** The peer selector: its labels, plus the namespace when one is chosen. */
export function peerMatchLabels(rule: CNPRule): Record<string, string> {
  const labels = toMatchLabels(rule.peerLabels)
  if (rule.peerNamespace.trim()) {
    labels[NAMESPACE_KEY] = rule.peerNamespace.trim()
  }
  return labels
}

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
// Cilium's FQDNSelector shape, with * as the wildcard: no scheme, no spaces.
const FQDN_RE = /^[*a-zA-Z0-9_][-*.a-zA-Z0-9_]*$/
/** A well-formed IPv4 address or CIDR: four octets in range with no leading
 * zeros, prefix 0 to 32. */
function isV4CIDR(v: string): boolean {
  const [addr, prefix, extra] = v.split('/')
  if (extra !== undefined) return false
  if (prefix !== undefined && (!/^(0|[1-9]\d?)$/.test(prefix) || Number(prefix) > 32)) return false
  const octets = addr.split('.')
  if (octets.length !== 4) return false
  return octets.every(o => /^(0|[1-9]\d{0,2})$/.test(o) && Number(o) <= 255)
}

/** A plausible IPv6 address or CIDR: hex groups and colons, one :: at most,
 * prefix 0 to 128. Deliberately looser than a full parser; the apiserver has
 * the final word, but 10.0.0.1:443 must not slip through as "IPv6". */
function isV6CIDR(v: string): boolean {
  const [addr, prefix, extra] = v.split('/')
  if (extra !== undefined) return false
  if (prefix !== undefined && (!/^(0|[1-9]\d{0,2})$/.test(prefix) || Number(prefix) > 128)) return false
  if (!/^[0-9a-fA-F:]+$/.test(addr) || !addr.includes(':')) return false
  if (addr.includes(':::') || (addr.match(/::/g) ?? []).length > 1) return false
  return addr.split(':').every(g => g.length <= 4)
}

/** A bare address becomes a single-host CIDR, which is what Cilium expects. */
function normalizeCIDR(v: string): string {
  const s = v.trim()
  if (s.includes('/')) return s
  return s.includes(':') ? s + '/128' : s + '/32'
}

// What FQDN matching depends on: Cilium learns a name's addresses only from
// DNS answers it observes, and a whitelist egress section would block DNS
// itself. This rule allows DNS to kube-dns through the proxy, where the
// answers are seen. It is plumbing rather than a decision, so the form folds
// it away on read and re-emits it whenever a section carries FQDN rules; the
// regeneration comparison sends every hand-written variant to the YAML editor.
// CHANGING THIS SHAPE ORPHANS EXISTING POLICIES: the rider is recognised by
// exact equality below, so a policy saved with today's shape stops matching a
// changed constant, fails the regeneration comparison, and silently loses form
// editing. Any change here needs the old shape kept recognisable (a list of
// historical canons) or a migration story.
const DNS_VISIBILITY_RULE = {
  toEndpoints: [{
    matchLabels: { [NAMESPACE_KEY]: 'kube-system', 'k8s-app': 'kube-dns' },
  }],
  toPorts: [{
    ports: [{ port: '53', protocol: 'ANY' }],
    rules: { dns: [{ matchPattern: '*' }] },
  }],
}
const DNS_VISIBILITY_CANON = yaml.dump(DNS_VISIBILITY_RULE, { sortKeys: true })

/** The HTTP entries that say something, dropping rows left blank. */
function filledHttp(r: CNPRule): HttpRule[] {
  return r.http.filter(h => h.method !== '' || h.path.trim() !== '')
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

  // A namespace alone is a complete subject: it selects everything in it. What
  // must not get through is neither — an empty endpointSelector on a
  // cluster-wide policy governs every endpoint in the cluster. Only a
  // cluster-wide policy is asked for a subject namespace, though: a namespaced
  // one is confined to its own already, so naming one there says nothing.
  if (Object.keys(subjectMatchLabels(input)).length === 0) {
    errors.push(input.scope === 'cluster'
      ? 'Applies to needs a label or a namespace.'
      : 'Applies to needs at least one label.')
  }
  errors.push(...labelRowErrors(input.subject, 'Applies to'))

  if (input.ingress.rules.length + input.egress.rules.length === 0) {
    errors.push('At least one rule is required.')
  }

  for (const { direction, section } of sectionsOf(input)) {
    errors.push(...sectionErrors(direction, section))
  }
  return errors
}

/** What stops one direction from producing rules Cilium would accept. */
function sectionErrors(direction: CNPDirection, section: CNPSection): string[] {
  const errors: string[] = []
  const side = peerLabel(direction)
  // Which direction a complaint is about, once both can carry rules.
  const where = direction === 'ingress' ? 'Ingress' : 'Egress'

  section.rules.forEach((r, i) => {
    const at = section.rules.length > 1
      ? `${where} rule ${i + 1}: `
      : `${where}: `

    if (r.peerKind === 'entity') {
      if (!ENTITIES.includes(r.peerEntity)) {
        errors.push(`${at}${r.peerEntity || 'The entity'} is not a Cilium entity.`)
      }
    } else if (r.peerKind === 'cidr') {
      const v = r.peerCIDR.trim()
      if (!v) {
        errors.push(`${at}${side} needs an IP or CIDR.`)
      } else if (!isV4CIDR(v) && !isV6CIDR(v)) {
        errors.push(`${at}${v} is not an IP or CIDR.`)
      }
    } else if (r.peerKind === 'fqdn') {
      if (direction !== 'egress' || section.mode !== 'whitelist') {
        errors.push(`${at}FQDN rules only allow egress: Cilium learns a name's addresses from the DNS answers the pod receives, so there is nothing to match on ingress or in a deny rule.`)
      } else if (!r.peerFQDN.trim()) {
        errors.push(`${at}${side} needs a domain name.`)
      } else if (!FQDN_RE.test(r.peerFQDN.trim())) {
        errors.push(`${at}${r.peerFQDN.trim()} is not a domain name. Letters, digits, dots, dashes and * only; no scheme, no spaces.`)
      }
    } else {
      // A namespace alone is a complete peer, the same way it is a complete
      // subject: it names everything in that namespace. Only neither is
      // refused — a peer selecting nothing is a rule that does nothing.
      if (Object.keys(peerMatchLabels(r)).length === 0) {
        errors.push(`${at}${side} needs a label or a namespace.`)
      }
      errors.push(...labelRowErrors(r.peerLabels, `${at}${side}`))
    }

    r.ports.forEach((p, pi) => {
      const port = p.port.trim()
      const label = r.ports.length > 1 ? ` ${pi + 1}` : ''
      // An empty row is dropped rather than silently narrowing nothing, but say
      // so — a row that looks like a restriction and is not would mislead.
      if (!port) {
        errors.push(`${at}Port${label} is empty. Fill it in or remove it.`)
      } else if (!/^\d+$/.test(port) || Number(port) < 1 || Number(port) > 65535) {
        errors.push(`${at}Port${label} must be a number between 1 and 65535.`)
      }
      if (!PROTOCOLS.includes(p.protocol)) {
        errors.push(`${at}Port${label} has an unsupported protocol.`)
      }
    })

    // An entry with neither a method nor a path matches every request, which is
    // what leaving HTTP out already does — so it is a row that looks like a
    // restriction and is not.
    r.http.forEach((h, hi) => {
      const label = r.http.length > 1 ? ` ${hi + 1}` : ''
      if (h.method === '' && h.path.trim() === '') {
        errors.push(`${at}HTTP rule${label} is empty. Set a method or a path, or remove it.`)
      }
    })

    if (r.http.length > 0) {
      // Cilium deny rules match on L3/L4 only. An HTTP rule under egressDeny or
      // ingressDeny is rejected by the API server, so refuse it here with a
      // reason instead of letting the apply fail.
      if (section.mode === 'blacklist') {
        errors.push(`${at}HTTP rules cannot be combined with a blacklist: Cilium deny rules match on L3/L4 only.`)
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
  fromCIDR?: string[]
  toCIDR?: string[]
  toFQDNs?: { matchName?: string; matchPattern?: string }[]
  toPorts?: PortRule[]
}

/** Renders one form rule as a Cilium rule for the given direction. */
function toCiliumRule(r: CNPRule, direction: CNPDirection): Rule {
  const isIngress = direction === 'ingress'

  let out: Rule
  if (r.peerKind === 'entity') {
    out = isIngress ? { fromEntities: [r.peerEntity] } : { toEntities: [r.peerEntity] }
  } else if (r.peerKind === 'cidr') {
    const cidr = normalizeCIDR(r.peerCIDR)
    out = isIngress ? { fromCIDR: [cidr] } : { toCIDR: [cidr] }
  } else if (r.peerKind === 'fqdn') {
    const name = r.peerFQDN.trim()
    out = { toFQDNs: [name.includes('*') ? { matchPattern: name } : { matchName: name }] }
  } else {
    const endpoints = [{ matchLabels: peerMatchLabels(r) }]
    out = isIngress ? { fromEndpoints: endpoints } : { toEndpoints: endpoints }
  }

  const ports = filledPorts(r).map(p => ({ port: p.port.trim(), protocol: p.protocol }))
  if (ports.length > 0) {
    const portRule: PortRule = { ports }
    const http = filledHttp(r).map(h => {
      const entry: { method?: string; path?: string } = {}
      if (h.method) entry.method = h.method
      if (h.path.trim()) entry.path = h.path.trim()
      return entry
    })
    if (http.length > 0) portRule.rules = { http }
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

  const spec: Record<string, unknown> = {
    endpointSelector: { matchLabels: subjectMatchLabels(input) },
  }
  if (input.comment?.trim()) spec.description = input.comment.trim()

  // A section with no rules is left out entirely: writing an empty ingress: []
  // would switch the endpoint to default-deny for a direction the operator did
  // not fill in.
  const defaultDenyOff: Record<string, boolean> = {}
  for (const { direction, section } of sectionsOf(input)) {
    if (section.rules.length === 0) continue
    const rules = section.rules.map(r => toCiliumRule(r, direction))
    if (direction === 'egress' && section.mode === 'whitelist' &&
        section.rules.some(r => r.peerKind === 'fqdn')) {
      rules.push(DNS_VISIBILITY_RULE as unknown as Rule)
    }
    if (section.mode === 'blacklist') {
      // Without this, adding a deny rule would also switch the endpoint to
      // default-deny for the whole direction — denying far more than the rules
      // the operator wrote. Keyed per direction, so denying egress does not
      // touch what was written for ingress.
      defaultDenyOff[direction] = false
      spec[direction === 'ingress' ? 'ingressDeny' : 'egressDeny'] = rules
    } else {
      spec[direction] = rules
    }
  }
  if (Object.keys(defaultDenyOff).length > 0) spec.enableDefaultDeny = defaultDenyOff

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
  metadata?: {
    name?: string
    namespace?: string
    annotations?: Record<string, unknown>
    labels?: Record<string, unknown>
  }
  spec?: Record<string, unknown>
  specs?: unknown
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
  // Neither of these is re-emitted: the specs form holds several policies in
  // one object, and the form writes no metadata labels.
  if (doc.specs !== undefined) return null
  if (Object.keys(doc.metadata?.labels ?? {}).length > 0) return null

  const spec = doc.spec
  const subjectLabels = (spec?.endpointSelector as { matchLabels?: Record<string, string> } | undefined)?.matchLabels
  if (!spec || !subjectLabels || Object.keys(subjectLabels).length === 0) return null
  const { [NAMESPACE_KEY]: subjectNs, ...subjectRest } = subjectLabels
  // Only a cluster-wide policy has a field for the subject's namespace — a
  // namespaced one is confined to its own, so the form stopped asking. Opening
  // a namespaced policy that carries the label anyway would turn it into
  // invisible state: written back on every save, shown nowhere, impossible to
  // remove. The YAML editor shows it, so such a policy falls back there.
  if (!clusterWide && subjectNs) return null

  // Each direction reads independently. What the form cannot show is one
  // direction carrying both an allow and a deny section — the mode is a property
  // of the direction, so there is nowhere to put two of them. Covering both
  // directions is ordinary and no longer a reason to fall back to YAML.
  const parsed: Record<CNPDirection, CNPSection> = {
    ingress: emptySection(),
    egress: emptySection(),
  }
  for (const direction of ['ingress', 'egress'] as CNPDirection[]) {
    const allowKey = direction
    const denyKey = direction === 'ingress' ? 'ingressDeny' : 'egressDeny'
    const hasAllow = Array.isArray(spec[allowKey])
    const hasDeny = Array.isArray(spec[denyKey])
    if (hasAllow && hasDeny) return null
    if (!hasAllow && !hasDeny) continue

    const rules = parseRules(spec[hasDeny ? denyKey : allowKey] as Rule[], direction)
    if (rules === null) return null
    parsed[direction] = { mode: hasDeny ? 'blacklist' : 'whitelist', rules }
  }
  // A policy with neither section governs nothing, and the form would open blank.
  if (parsed.ingress.rules.length + parsed.egress.rules.length === 0) return null

  const result: CNPFormInput = {
    name: doc.metadata?.name ?? '',
    scope: clusterWide ? 'cluster' : 'namespaced',
    namespace: clusterWide ? '' : (doc.metadata?.namespace ?? ''),
    comment: typeof spec.description === 'string' ? spec.description : '',
    // Lifted into its own field, so it does not also show as a label row and
    // get written from both places.
    subject: toLabelPairs(subjectRest),
    subjectNamespace: subjectNs ?? '',
    ingress: parsed.ingress,
    egress: parsed.egress,
  }

  // The invariant behind all of this: the form may only open a policy it can
  // reproduce, because saving regenerates the whole manifest — whatever the
  // fields cannot show is deleted on save, not preserved. Rather than
  // enumerating every such shape (toCIDR peers, DNS rules, matchExpressions, a
  // port range, enableDefaultDeny that disagrees with the mode, ...), generate
  // what this form state saves as and demand the spec come out identical.
  const regen = yaml.load(cnpFormToYaml(result)) as ParsedDoc | undefined
  if (!regen || yaml.dump(regen.spec, { sortKeys: true }) !== yaml.dump(spec, { sortKeys: true })) {
    return null
  }
  return result
}

/** One section's Cilium rules as form rules, or null when one cannot be shown. */
function parseRules(ciliumRules: Rule[], direction: CNPDirection): CNPRule[] | null {
  if (ciliumRules.length === 0) return null
  const isIngress = direction === 'ingress'
  const rules: CNPRule[] = []
  for (const cr of ciliumRules) {
    // The DNS visibility rule rides along with FQDN rules and is not shown; the
    // regeneration comparison enforces that it and the FQDN rules pair up.
    if (!isIngress && yaml.dump(cr, { sortKeys: true }) === DNS_VISIBILITY_CANON) {
      continue
    }
    const endpoints = isIngress ? cr.fromEndpoints : cr.toEndpoints
    const entities = isIngress ? cr.fromEntities : cr.toEntities
    const cidrs = isIngress ? cr.fromCIDR : cr.toCIDR

    const rule = emptyRule()
    if (endpoints?.length === 1) {
      // An empty selector means every endpoint, which the form cannot express —
      // it requires at least one label. Opening it here would show a blank peer
      // and refuse to save until the operator changed a policy that was valid.
      // The subject is guarded the same way above.
      const labels = endpoints[0].matchLabels
      if (!labels || Object.keys(labels).length === 0) return null
      rule.peerKind = 'labels'
      // The namespace is edited in its own field, so it is lifted out of the
      // labels rather than shown as a row the form would write back twice.
      const { [NAMESPACE_KEY]: peerNs, ...rest } = labels
      rule.peerNamespace = peerNs ?? ''
      rule.peerLabels = toLabelPairs(rest)
    } else if (entities?.length === 1) {
      rule.peerKind = 'entity'
      rule.peerEntity = entities[0]
    } else if (cidrs?.length === 1) {
      rule.peerKind = 'cidr'
      rule.peerCIDR = cidrs[0]
    } else if (!isIngress && cr.toFQDNs?.length === 1) {
      rule.peerKind = 'fqdn'
      rule.peerFQDN = cr.toFQDNs[0].matchName ?? cr.toFQDNs[0].matchPattern ?? ''
      if (!rule.peerFQDN) return null
    } else {
      return null
    }

    if (cr.toPorts) {
      if (cr.toPorts.length !== 1) return null
      const pr = cr.toPorts[0]
      rule.ports = (pr.ports ?? []).map(p => ({ port: p.port, protocol: p.protocol }))
      rule.http = (pr.rules?.http ?? []).map(h => ({
        method: h.method ?? '',
        path: h.path ?? '',
      }))
    }
    rules.push(rule)
  }
  return rules
}
