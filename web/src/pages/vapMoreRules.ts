// The admission rule types whose whole spec is one fixed shape: hostPath
// volumes, environment variables, and vulnerabilities refused by ID. What the
// administrator chose is kept in CEL variables as plain lists, so that reading
// a policy back is reading those lists, not taking expressions apart.

export interface VolumeRule {
  // 'all' refuses every hostPath volume; 'paths' only those under the paths.
  mode: 'all' | 'paths'
  paths: string[]
  message: string
}

export interface EnvRule {
  // Names every container has to set.
  required: string[]
  // Names no container may set, in any capitalisation.
  forbidden: string[]
}

export interface CveRule {
  ids: string[]
}

export const emptyVolumeRule = (): VolumeRule => ({ mode: 'all', paths: [], message: '' })
export const emptyEnvRule = (): EnvRule => ({ required: [], forbidden: [] })
export const emptyCveRule = (): CveRule => ({ ids: [] })

// Nothing in these may end a CEL string or a YAML one.
const PATH = /^\/[^'"\\\s]*$/
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_.-]*$/
const VULN_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/

// Scanners write CVE-2024-3094 and GHSA-xxxx-xxxx-xxxx, and the policy compares
// the text: "cve-2024-3094" would be a policy that never matches anything.
export function normalizeVulnId(id: string): string {
  const t = id.trim()
  if (/^cve-/i.test(t)) return t.toUpperCase()
  if (/^ghsa-/i.test(t)) return 'GHSA-' + t.slice(5).toLowerCase()
  return t
}

// "/var/run/" and "/var/run" are one path; "/" is every path.
const cleanPath = (p: string) => p.trim().replace(/\/+$/, '')

export function volumeRuleValid(r: VolumeRule): boolean {
  return r.mode === 'all' || (r.paths.length > 0 && r.paths.every(p => PATH.test(p.trim())))
}

export function envRuleValid(r: EnvRule): boolean {
  return [...r.required, ...r.forbidden].every(n => ENV_NAME.test(n))
    && (r.required.length > 0 || r.forbidden.length > 0)
}

export function cveRuleValid(r: CveRule): boolean {
  return r.ids.length > 0 && r.ids.every(id => VULN_ID.test(id))
}

// A CEL list of strings, as one double-quoted YAML scalar. The values have
// been checked to hold no quote or backslash.
function listVariable(name: string, items: string[]): string[] {
  return [
    `    - name: ${name}`,
    `      expression: "[${items.map(i => `'${i}'`).join(', ')}]"`,
  ]
}

function readList(spec: unknown, name: string): string[] | null {
  const vars = (spec as { variables?: { name?: string; expression?: string }[] })?.variables ?? []
  const v = vars.find(x => x?.name === name)
  if (!v) return null
  return [...String(v.expression ?? '').matchAll(/'([^']*)'/g)].map(m => m[1])
}

// An update that leaves the spec as it was is let through: a label, an
// annotation, or a finalizer being taken off as the object is deleted. Without
// this, an object that broke the rule before the rule existed could not even
// be removed cleanly.
export const SPEC_CHANGE_CONDITION = [
  '    - name: creates-or-changes-the-spec',
  `      expression: "request.operation == 'CREATE' || object.spec != oldObject.spec"`,
]

// The pod spec, wherever the object keeps it.
export const POD_SPEC_VARIABLE = [
  '    - name: podSpec',
  '      expression: >-',
  "        object.kind == 'Pod' ? object.spec :",
  "        (object.kind == 'CronJob' ? object.spec.jobTemplate.spec.template.spec : object.spec.template.spec)",
]

// ── hostPath volumes ─────────────────────────────────────────────────────────

export function autoVolumeMessage(r: VolumeRule): string {
  const paths = r.paths.map(cleanPath).map(p => p || '/')
  return r.mode === 'paths' && paths.length
    ? `hostPath volumes that reach ${paths.join(', ')} are not allowed`
    : 'hostPath volumes are not allowed'
}

export function volumeSpecLines(r: VolumeRule, message: string): string[] {
  const paths = r.mode === 'paths' ? r.paths.filter(p => PATH.test(p.trim())).map(cleanPath) : []
  // A path is refused when it is a denied one, lies under one, or contains
  // one ("/var" gives access to "/var/run"). One written so that the
  // comparison cannot be trusted, "//var/run" or "/./var/run", is refused too:
  // the kernel reads those as the same place.
  return [
    '  matchConditions:',
    ...SPEC_CHANGE_CONDITION,
    '  variables:',
    ...POD_SPEC_VARIABLE,
    ...listVariable('deniedHostPaths', paths),
    '  validations:',
    '    - expression: >-',
    '        !variables.podSpec.?volumes.orValue([]).exists(v, has(v.hostPath) &&',
    '        (size(variables.deniedHostPaths) == 0 ||',
    "        v.hostPath.path.contains('//') || v.hostPath.path.contains('/./') || v.hostPath.path.endsWith('/.') ||",
    '        variables.deniedHostPaths.exists(p,',
    "        v.hostPath.path == p || v.hostPath.path.startsWith(p + '/') ||",
    "        p.startsWith(v.hostPath.path.endsWith('/') ? v.hostPath.path : v.hostPath.path + '/'))))",
    `      message: "${message}"`,
    '      reason: Forbidden',
  ]
}

export function parseVolumeSpec(spec: unknown): VolumeRule | null {
  const paths = readList(spec, 'deniedHostPaths')
  if (paths === null) return null
  const rule: VolumeRule = { mode: paths.length ? 'paths' : 'all', paths: paths.map(p => p || '/'), message: '' }
  const message = (spec as { validations?: { message?: string }[] }).validations?.[0]?.message ?? ''
  return { ...rule, message: message === autoVolumeMessage(rule) ? '' : message }
}

// ── Environment variables ────────────────────────────────────────────────────

// True when some container, of any of the three kinds, matches.
function anyContainer(pred: string): string[] {
  return [
    `        (variables.podSpec.containers.exists(c, ${pred}) ||`,
    `        variables.podSpec.?initContainers.orValue([]).exists(c, ${pred}) ||`,
    `        variables.podSpec.?ephemeralContainers.orValue([]).exists(c, ${pred}))`,
  ]
}

export function envSpecLines(r: EnvRule): string[] {
  const required = r.required.filter(n => ENV_NAME.test(n))
  const forbidden = r.forbidden.filter(n => ENV_NAME.test(n))
  const validations: string[] = []
  if (required.length) {
    validations.push(
      '    - expression: >-',
      '        variables.podSpec.containers.all(c, variables.requiredEnv.all(n,',
      '        c.?env.orValue([]).exists(e, e.name == n)))',
      `      message: "Every container must set the environment variables: ${required.join(', ')}"`,
      '      reason: Forbidden',
    )
  }
  if (forbidden.length) {
    validations.push(
      '    - expression: >-',
      '        !',
      // PASS and pass are two variables to a shell and one to whoever forbade it.
      ...anyContainer('c.?env.orValue([]).exists(e, variables.forbiddenEnv.exists(n, n.lowerAscii() == e.name.lowerAscii()))'),
      `      message: "These environment variables are not allowed: ${forbidden.join(', ')}"`,
      '      reason: Forbidden',
    )
  }
  if (!validations.length) {
    // An unfinished form still previews something that parses.
    validations.push('    - expression: "true"')
  }
  return [
    '  matchConditions:',
    ...SPEC_CHANGE_CONDITION,
    '  variables:',
    ...POD_SPEC_VARIABLE,
    ...listVariable('requiredEnv', required),
    ...listVariable('forbiddenEnv', forbidden),
    '  validations:',
    ...validations,
  ]
}

export function parseEnvSpec(spec: unknown): EnvRule | null {
  const required = readList(spec, 'requiredEnv')
  const forbidden = readList(spec, 'forbiddenEnv')
  if (required === null || forbidden === null) return null
  return { required, forbidden }
}

// ── Vulnerabilities refused by ID ────────────────────────────────────────────

// The variable K8s Sentinel reads to learn which IDs to look for in its scan
// results. internal/vulngate knows it by the same name.
const NAMED_VARIABLE = 'blockedCVEs'

export function cveVariableLines(r: CveRule): string[] {
  return [
    ...listVariable(NAMED_VARIABLE, r.ids.filter(id => VULN_ID.test(id)).map(normalizeVulnId)),
    '    - name: hits',
    '      expression: >-',
    '        has(params.spec) && has(params.spec.images)',
    '        ? variables.images.filter(i, i in params.spec.images && has(params.spec.images[i].cves) &&',
    '        params.spec.images[i].cves.exists(c, c in variables.blockedCVEs))',
    '        : []',
  ]
}

export const CVE_VALIDATION = [
  '    - expression: "variables.exempt || size(variables.hits) == 0"',
  '      messageExpression: >-',
  "        'image ' + variables.hits[0] + ' has ' +",
  "        params.spec.images[variables.hits[0]].cves.filter(c, c in variables.blockedCVEs).join(', ')",
  '      reason: Forbidden',
]

export function parseCveSpec(spec: unknown): CveRule | null {
  const ids = readList(spec, NAMED_VARIABLE)
  return ids === null ? null : { ids }
}
