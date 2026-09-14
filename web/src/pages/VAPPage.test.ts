import { describe, it, expect } from 'vitest'
import yaml from 'js-yaml'
import {
  tryParseBuilderPolicy, tryParseBuilderBinding,
  generatePolicyYaml, generateBindingYaml,
} from './VAPPage'

// What the kube-apiserver does to a policy on persist: the builder's output
// never comes back byte-identical, because defaulted fields are stored. Edit
// reads the cluster's copy, so the parser has to see through exactly these.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function withServerDefaults(rawYaml: string): string {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const doc = yaml.load(rawYaml) as any
  const mc = doc.spec.matchConstraints ?? doc.spec.matchResources
  if (mc) {
    mc.matchPolicy ??= 'Equivalent'
    mc.namespaceSelector ??= {}
    mc.objectSelector ??= {}
    for (const r of mc.resourceRules ?? []) r.scope ??= '*'
  }
  doc.metadata.uid = '5e2f1a'
  doc.metadata.generation = 1
  return yaml.dump(doc)
}

// Saving from the builder regenerates the whole manifest, so the builder may
// only open a policy it can reproduce — whatever its fields cannot show is
// deleted on save, not preserved. Same invariant as the CNP form.

const labelPolicy = () => generatePolicyYaml(
  'require-team', 'label',
  [{ key: 'team', condition: '!=', value: 'platform', message: '' }],
  [], [], 'workloads',
)

describe('tryParseBuilderPolicy', () => {
  it('round-trips what the builder generates', () => {
    const parsed = tryParseBuilderPolicy(labelPolicy())
    expect(parsed).not.toBeNull()
    expect(parsed?.ruleType).toBe('label')
    expect(parsed?.labelRules[0]?.key).toBe('team')
    // And the other rule kinds, which regenerate through different branches.
    expect(tryParseBuilderPolicy(generatePolicyYaml(
      'max-replicas', 'replica', [], [],
      [{ resourceType: 'deployments', maxReplicas: 5, message: '' }],
    ))).not.toBeNull()
    expect(tryParseBuilderPolicy(generatePolicyYaml(
      'no-latest', 'image', [],
      [{ type: 'no-latest', registry: '', message: '' }], [],
    ))).not.toBeNull()
  })

  // The bug this pins: every builder policy came back from the cluster with
  // these defaults added, failed the byte comparison, and Edit fell back to the
  // YAML editor for all of them — the builder could reopen nothing it made.
  it('accepts its own policy as the apiserver returns it', () => {
    for (const raw of [
      labelPolicy(),
      generatePolicyYaml('max-replicas', 'replica', [], [],
        [{ resourceType: 'deployments', maxReplicas: 5, message: '' }]),
      generatePolicyYaml('no-latest', 'image', [],
        [{ type: 'no-latest', registry: '', message: '' }], []),
    ]) {
      expect(tryParseBuilderPolicy(withServerDefaults(raw)), raw).not.toBeNull()
    }
  })

  // Stripping must stop at the default values: an operator's explicit
  // non-default is a real difference a rebuild-save would erase.
  it('still refuses a non-default matchPolicy', () => {
    const doc = withServerDefaults(labelPolicy()).replace('matchPolicy: Equivalent', 'matchPolicy: Exact')
    expect(tryParseBuilderPolicy(doc)).toBeNull()
  })

  it('refuses a hand-added matchCondition', () => {
    const yaml = labelPolicy().replace('spec:', `spec:
  matchConditions:
    - name: exclude-kube-system
      expression: request.namespace != 'kube-system'`)
    expect(tryParseBuilderPolicy(yaml)).toBeNull()
  })

  it('refuses a changed failurePolicy', () => {
    expect(tryParseBuilderPolicy(
      labelPolicy().replace('failurePolicy: Fail', 'failurePolicy: Ignore'),
    )).toBeNull()
  })

  it('refuses hand-tuned matchConstraints', () => {
    expect(tryParseBuilderPolicy(
      labelPolicy().replace('"deployments"', '"deployments", "pods"'),
    )).toBeNull()
  })

  it('refuses metadata labels, which a save would drop', () => {
    expect(tryParseBuilderPolicy(labelPolicy().replace('metadata:', `metadata:
  labels:
    team: platform`))).toBeNull()
  })

  const cmSizePolicy = (message = '') => generatePolicyYaml(
    'configmap-size-limit', 'configmap-size', [], [], [], 'workloads',
    [], undefined, undefined, { keyKB: '10', totalKB: '64', message },
  )
  const secretSizePolicy = (message = '') => generatePolicyYaml(
    'secret-size-limit', 'secret-size', [], [], [], 'workloads',
    [], undefined, undefined, undefined, { keyKB: '10', totalKB: '64', message },
  )

  it('round-trips a ConfigMap size policy', () => {
    const raw = cmSizePolicy()
    // Scoped to configmaps; limits live in variables; data, binaryData and the
    // total are all capped; the grandfather clause allows an existing oversized
    // key only unchanged or strictly shrinking; a cost-budget guard skips maps
    // with too many keys so they cannot become permanently unwritable.
    expect(raw).toContain('resources: ["configmaps"]')
    expect(raw).toContain('expression: "10240"')
    expect(raw).toContain('expression: "65536"')
    expect(raw).toContain('bytes(variables.newData[k]).size() <= variables.keyLimit')
    expect(raw).toContain('(variables.newBin[k].size() * 3) / 4 <= variables.keyLimit')
    expect(raw).toContain('variables.newData[k] == variables.oldData[k]')
    expect(raw).toContain('variables.newTotal <= variables.totalLimit')
    expect(raw).toContain('skip-huge-maps')
    expect(raw).toContain('messageExpression')

    const parsed = tryParseBuilderPolicy(raw)
    expect(parsed?.ruleType).toBe('configmap-size')
    expect(parsed?.configMapSizeRule.keyKB).toBe('10')
    expect(parsed?.configMapSizeRule.totalKB).toBe('64')
    expect(parsed?.configMapSizeRule.message).toBe('')
    // And as the apiserver returns it.
    expect(tryParseBuilderPolicy(withServerDefaults(raw))).not.toBeNull()
  })

  it('round-trips a Secret size policy', () => {
    const raw = secretSizePolicy()
    // Scoped to secrets; data is base64 so sizes are decoded as *3/4; managed
    // secret types whose size the user does not control are exempt.
    expect(raw).toContain('resources: ["secrets"]')
    expect(raw).toContain('(variables.newData[k].size() * 3) / 4 <= variables.keyLimit')
    expect(raw).toContain('kubernetes.io/service-account-token')
    expect(raw).toContain('helm.sh/release.v1')
    expect(raw).toContain('variables.newTotal <= variables.totalLimit')

    const parsed = tryParseBuilderPolicy(raw)
    expect(parsed?.ruleType).toBe('secret-size')
    expect(parsed?.secretSizeRule.keyKB).toBe('10')
    expect(parsed?.secretSizeRule.totalKB).toBe('64')
    expect(tryParseBuilderPolicy(withServerDefaults(raw))).not.toBeNull()
  })

  it('round-trips size policies with a custom message', () => {
    for (const raw of [cmSizePolicy('Too large'), secretSizePolicy('Too large')]) {
      expect(raw).not.toContain('messageExpression')
      const parsed = tryParseBuilderPolicy(raw)
      expect(parsed).not.toBeNull()
      const rule = parsed?.ruleType === 'secret-size' ? parsed.secretSizeRule : parsed?.configMapSizeRule
      expect(rule?.message).toBe('Too large')
      expect(tryParseBuilderPolicy(withServerDefaults(raw))).not.toBeNull()
    }
  })

  // Tampered variants of the size shapes stay in the YAML editor: a save would
  // regenerate the builder's exact form and silently change them.
  it('refuses a tampered size policy', () => {
    const cm = cmSizePolicy()
    // A hand-changed limit variable that no longer matches whole KB.
    expect(tryParseBuilderPolicy(cm.replace('expression: "10240"', 'expression: "10000"'))).toBeNull()
    // A hand-relaxed grandfather clause.
    expect(tryParseBuilderPolicy(cm.replace('variables.newData[k] == variables.oldData[k] ||', ''))).toBeNull()
    // A hand-edited exemption list is caught by the regenerate-and-compare guard.
    expect(tryParseBuilderPolicy(secretSizePolicy().replace('"helm.sh/release.v1"', '"example/other"'))).toBeNull()
  })
})

describe('tryParseBuilderBinding', () => {
  it('round-trips what the builder generates, with and without a namespace', () => {
    const scoped = tryParseBuilderBinding(generateBindingYaml('b', 'require-team', 'include', ['demo'], ['Deny']))
    expect(scoped?.nsMode).toBe('include')
    expect(scoped?.namespaces).toEqual(['demo'])
    const everywhere = tryParseBuilderBinding(generateBindingYaml('b', 'require-team', 'all', [], ['Deny', 'Audit']))
    expect(everywhere?.nsMode).toBe('all')
    expect(everywhere?.namespaces).toEqual([])
    expect(everywhere?.actions).toEqual(['Deny', 'Audit'])
  })

  // A single included namespace keeps the matchLabels shape older bindings were
  // saved with, so they reopen and resave unchanged; several use matchExpressions.
  it('round-trips multi-namespace In and NotIn scopes', () => {
    const single = generateBindingYaml('b', 'p', 'include', ['demo'], ['Deny'])
    expect(single).toContain('matchLabels')
    expect(single).not.toContain('matchExpressions')

    const multi = generateBindingYaml('b', 'p', 'include', ['team-a', 'team-b', 'team-c'], ['Deny'])
    expect(multi).toContain('operator: In')
    const parsedMulti = tryParseBuilderBinding(multi)
    expect(parsedMulti?.nsMode).toBe('include')
    expect(parsedMulti?.namespaces).toEqual(['team-a', 'team-b', 'team-c'])

    const except = generateBindingYaml('b', 'p', 'exclude', ['kube-system', 'kube-public'], ['Deny'])
    expect(except).toContain('operator: NotIn')
    const parsedExcept = tryParseBuilderBinding(except)
    expect(parsedExcept?.nsMode).toBe('exclude')
    expect(parsedExcept?.namespaces).toEqual(['kube-system', 'kube-public'])

    // A single excluded namespace still needs matchExpressions — matchLabels
    // cannot say "not".
    const exceptOne = generateBindingYaml('b', 'p', 'exclude', ['kube-system'], ['Deny'])
    expect(exceptOne).toContain('operator: NotIn')
    expect(tryParseBuilderBinding(exceptOne)?.nsMode).toBe('exclude')
  })

  it('accepts its own binding as the apiserver returns it', () => {
    expect(tryParseBuilderBinding(withServerDefaults(
      generateBindingYaml('b', 'require-team', 'include', ['demo'], ['Deny']),
    ))).not.toBeNull()
    expect(tryParseBuilderBinding(withServerDefaults(
      generateBindingYaml('b', 'require-team', 'exclude', ['kube-system', 'kube-public'], ['Deny']),
    ))).not.toBeNull()
    // A cluster-wide binding has no matchResources for the server to default.
    expect(tryParseBuilderBinding(withServerDefaults(
      generateBindingYaml('b', 'require-team', 'all', [], ['Deny', 'Audit']),
    ))).not.toBeNull()
  })

  it('refuses a hand-added selector or paramRef', () => {
    const base = generateBindingYaml('b', 'require-team', 'include', ['demo'], ['Deny'])
    expect(tryParseBuilderBinding(base + `
      objectSelector:
        matchLabels:
          env: prod`)).toBeNull()
    expect(tryParseBuilderBinding(base + `
  paramRef:
    name: config`)).toBeNull()
  })

  // A namespace selector keyed on anything but the namespace's name has no
  // field to open in — reading it as "no namespace" would widen the binding to
  // the whole cluster on save.
  it('refuses a namespace selector it cannot show', () => {
    const yaml = generateBindingYaml('b', 'require-team', 'include', ['demo'], ['Deny'])
      .replace('kubernetes.io/metadata.name: demo', 'env: prod')
    expect(tryParseBuilderBinding(yaml)).toBeNull()

    // An expression on another key, another operator, or a second expression is
    // out of the form's reach too.
    const otherKey = generateBindingYaml('b', 'p', 'exclude', ['kube-system'], ['Deny'])
      .replace('key: kubernetes.io/metadata.name', 'key: env')
    expect(tryParseBuilderBinding(otherKey)).toBeNull()
    const otherOp = generateBindingYaml('b', 'p', 'exclude', ['kube-system'], ['Deny'])
      .replace('operator: NotIn', 'operator: Exists')
    expect(tryParseBuilderBinding(otherOp)).toBeNull()
  })
})
