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

  // A custom annotation would be dropped the same way labels would: a save
  // regenerates the whole manifest. kubectl's own bookkeeping is tolerated,
  // since kubectl rewrites it on its next apply anyway.
  it('refuses custom metadata annotations, tolerates kubectl bookkeeping', () => {
    expect(tryParseBuilderPolicy(labelPolicy().replace('  annotations:', `  annotations:
    owner: team-x`))).toBeNull()
    expect(tryParseBuilderPolicy(labelPolicy().replace('  annotations:', `  annotations:
    kubectl.kubernetes.io/last-applied-configuration: "{}"`))).not.toBeNull()
  })

  // Every container list is covered: a bad image in an initContainer or an
  // ephemeral (kubectl debug) container must not slip past, and the debug
  // subresource must be matched or the check never runs on injection.
  it('image rules cover initContainers and ephemeral containers', () => {
    const raw = generatePolicyYaml('no-latest', 'image', [],
      [{ type: 'no-latest', registry: '', message: '' }], [])
    expect(raw).toContain('object.spec.?initContainers.orValue([])')
    expect(raw).toContain('object.spec.?ephemeralContainers.orValue([])')
    expect(raw).toContain('object.spec.?template.?spec.?initContainers.orValue([])')
    expect(raw).toContain('resources: ["pods/ephemeralcontainers"]')
    expect(raw).toContain('"pods", "replicationcontrollers"')
    // The tag colon is looked for after the last slash, so a registry port
    // (myreg:5000/app, still untagged) cannot satisfy the tag check.
    expect(raw).toContain("c.image.substring(c.image.lastIndexOf('/') + 1).contains(':')")
    expect(tryParseBuilderPolicy(raw)).not.toBeNull()
    expect(tryParseBuilderPolicy(withServerDefaults(raw))).not.toBeNull()
  })

  // The registry prefix is compared case-insensitively (image hosts are
  // case-insensitive) and always ends with a slash (subdomain bypass).
  it('required-registry round-trips lowercased with a trailing slash', () => {
    const raw = generatePolicyYaml('from-registry', 'image', [],
      [{ type: 'required-registry', registry: 'Registry.Example.Com', message: '' }], [])
    expect(raw).toContain("c.image.lowerAscii().startsWith('registry.example.com/')")
    const parsed = tryParseBuilderPolicy(raw)
    expect(parsed?.imageRules[0]?.registry).toBe('registry.example.com/')
    expect(tryParseBuilderPolicy(withServerDefaults(raw))).not.toBeNull()
  })

  // Single-type replica rules guard on the request resource, not object.kind:
  // a kubectl scale or HPA change arrives as kind Scale, where a kind guard was
  // always true and let every scale request through.
  it('replica rules guard on the request resource so scale is covered', () => {
    const dep = generatePolicyYaml('max-replicas', 'replica', [], [],
      [{ resourceType: 'deployments', maxReplicas: 5, message: '' }])
    expect(dep).toContain("request.resource.resource != 'deployments' || object.spec.replicas <= 5")
    expect(dep).not.toContain('object.kind')
    expect(tryParseBuilderPolicy(dep)?.replicaRules[0]?.resourceType).toBe('deployments')

    const sts = generatePolicyYaml('max-replicas', 'replica', [], [],
      [{ resourceType: 'statefulsets', maxReplicas: 3, message: '' }])
    expect(tryParseBuilderPolicy(sts)?.replicaRules[0]?.resourceType).toBe('statefulsets')

    const both = generatePolicyYaml('max-replicas', 'replica', [], [],
      [{ resourceType: 'both', maxReplicas: 7, message: '' }])
    expect(tryParseBuilderPolicy(both)?.replicaRules[0]?.resourceType).toBe('both')
  })

  // Round-trips for the branches that had no coverage: annotation, resource
  // limits, security context (including the two-validation 'both'), host access.
  it('round-trips the remaining rule kinds', () => {
    const annotation = generatePolicyYaml('require-note', 'annotation',
      [{ key: 'owner', condition: '!=', value: 'platform', message: '' }], [], [], 'configmaps')
    const annParsed = tryParseBuilderPolicy(annotation)
    expect(annParsed?.ruleType).toBe('annotation')
    expect(annParsed?.applyTo).toBe('configmaps')

    for (const limitType of ['cpu', 'memory', 'both'] as const) {
      const raw = generatePolicyYaml('limits', 'resource-limits', [], [], [], 'workloads',
        [{ limitType, message: '' }])
      expect(tryParseBuilderPolicy(raw)?.resourceLimitRules[0]?.limitType, limitType).toBe(limitType)
      expect(tryParseBuilderPolicy(withServerDefaults(raw))).not.toBeNull()
    }

    for (const checkType of ['no-privileged', 'run-as-non-root', 'both'] as const) {
      const raw = generatePolicyYaml('sc', 'security-context', [], [], [], 'workloads', [],
        { checkType, message: '' })
      expect(tryParseBuilderPolicy(raw)?.securityContextRule.checkType, checkType).toBe(checkType)
      expect(raw).toContain('object.spec.?ephemeralContainers.orValue([])')
      expect(tryParseBuilderPolicy(withServerDefaults(raw))).not.toBeNull()
    }

    for (const checkType of ['all', 'no-host-network', 'no-host-pid', 'no-host-ipc'] as const) {
      const raw = generatePolicyYaml('host', 'host-access', [], [], [], 'workloads', [],
        undefined, { checkType, message: '' })
      expect(tryParseBuilderPolicy(raw)?.hostAccessRule.checkType, checkType).toBe(checkType)
      expect(tryParseBuilderPolicy(withServerDefaults(raw))).not.toBeNull()
    }
  })

  const cmSizePolicy = (message = '') => generatePolicyYaml(
    'configmap-size-limit', 'configmap-size', [], [], [], 'workloads',
    [], undefined, undefined, { totalKB: '64', message },
  )
  const secretSizePolicy = (message = '') => generatePolicyYaml(
    'secret-size-limit', 'secret-size', [], [], [], 'workloads',
    [], undefined, undefined, undefined, { totalKB: '64', message },
  )

  it('round-trips a ConfigMap size policy', () => {
    const raw = cmSizePolicy()
    // Scoped to configmaps; the cap lives in the totalLimit variable and counts
    // data and binaryData together; an existing oversized object may not grow;
    // a cost-budget guard skips maps with too many keys so they cannot become
    // permanently unwritable; the blank message becomes the concrete default.
    expect(raw).toContain('resources: ["configmaps"]')
    expect(raw).toContain('expression: "65536"')
    expect(raw).toContain('variables.newTotal <= variables.totalLimit')
    expect(raw).toContain('variables.isUpdate && variables.newTotal <= variables.oldTotal')
    expect(raw).toContain('skip-huge-maps')
    expect(raw).toContain('message: "ConfigMap total size exceeds 65536 bytes"')
    expect(raw).not.toContain('messageExpression')

    const parsed = tryParseBuilderPolicy(raw)
    expect(parsed?.ruleType).toBe('configmap-size')
    expect(parsed?.configMapSizeRule.totalKB).toBe('64')
    // The default message reads back as a blank field.
    expect(parsed?.configMapSizeRule.message).toBe('')
    // And as the apiserver returns it.
    expect(tryParseBuilderPolicy(withServerDefaults(raw))).not.toBeNull()
  })

  it('round-trips a Secret size policy', () => {
    const raw = secretSizePolicy()
    // Scoped to secrets; managed secret types whose size the user does not
    // control are exempt; data is base64 so totals are decoded as *3/4.
    expect(raw).toContain('resources: ["secrets"]')
    expect(raw).toContain('kubernetes.io/service-account-token')
    expect(raw).toContain('helm.sh/release.v1')
    expect(raw).toContain('(variables.newData[k].size() * 3) / 4')
    expect(raw).toContain('variables.newTotal <= variables.totalLimit')

    const parsed = tryParseBuilderPolicy(raw)
    expect(parsed?.ruleType).toBe('secret-size')
    expect(parsed?.secretSizeRule.totalKB).toBe('64')
    expect(parsed?.secretSizeRule.message).toBe('')
    expect(tryParseBuilderPolicy(withServerDefaults(raw))).not.toBeNull()
  })

  it('round-trips size policies with a custom message', () => {
    for (const raw of [cmSizePolicy('Too large'), secretSizePolicy('Too large')]) {
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
    expect(tryParseBuilderPolicy(cm.replace('expression: "65536"', 'expression: "65000"'))).toBeNull()
    // A hand-relaxed grandfather clause.
    expect(tryParseBuilderPolicy(cm.replace('(variables.isUpdate && variables.newTotal <= variables.oldTotal)', 'true'))).toBeNull()
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
