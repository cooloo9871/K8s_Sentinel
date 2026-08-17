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
})

describe('tryParseBuilderBinding', () => {
  it('round-trips what the builder generates, with and without a namespace', () => {
    const scoped = tryParseBuilderBinding(generateBindingYaml('b', 'require-team', 'demo', ['Deny']))
    expect(scoped?.namespace).toBe('demo')
    const everywhere = tryParseBuilderBinding(generateBindingYaml('b', 'require-team', '', ['Deny', 'Audit']))
    expect(everywhere?.namespace).toBe('')
    expect(everywhere?.actions).toEqual(['Deny', 'Audit'])
  })

  it('accepts its own binding as the apiserver returns it', () => {
    expect(tryParseBuilderBinding(withServerDefaults(
      generateBindingYaml('b', 'require-team', 'demo', ['Deny']),
    ))).not.toBeNull()
    // A cluster-wide binding has no matchResources for the server to default.
    expect(tryParseBuilderBinding(withServerDefaults(
      generateBindingYaml('b', 'require-team', '', ['Deny', 'Audit']),
    ))).not.toBeNull()
  })

  it('refuses a hand-added selector or paramRef', () => {
    const base = generateBindingYaml('b', 'require-team', 'demo', ['Deny'])
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
    const yaml = generateBindingYaml('b', 'require-team', 'demo', ['Deny'])
      .replace('kubernetes.io/metadata.name: demo', 'env: prod')
    expect(tryParseBuilderBinding(yaml)).toBeNull()
  })
})
