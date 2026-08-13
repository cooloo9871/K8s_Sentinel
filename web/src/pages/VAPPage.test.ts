import { describe, it, expect } from 'vitest'
import {
  tryParseBuilderPolicy, tryParseBuilderBinding,
  generatePolicyYaml, generateBindingYaml,
} from './VAPPage'

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
