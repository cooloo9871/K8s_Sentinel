import { describe, it, expect } from 'vitest'
import { matchesScopeFilter, SCOPE_CLUSTER } from './ScopeFilter'

describe('matchesScopeFilter', () => {
  // An empty selection is "All namespaces" — the absence of a filter, not a
  // value to match against.
  it('lets everything through when nothing is selected', () => {
    expect(matchesScopeFilter('cluster', undefined, [])).toBe(true)
    expect(matchesScopeFilter('namespaced', 'demo', [])).toBe(true)
  })

  it('narrows to one namespace', () => {
    expect(matchesScopeFilter('namespaced', 'demo', ['demo'])).toBe(true)
    expect(matchesScopeFilter('namespaced', 'other', ['demo'])).toBe(false)
  })

  // The point of the control: comparing several namespaces without switching
  // back and forth between them.
  it('narrows to several namespaces at once', () => {
    const selected = ['demo', 'prod']
    expect(matchesScopeFilter('namespaced', 'demo', selected)).toBe(true)
    expect(matchesScopeFilter('namespaced', 'prod', selected)).toBe(true)
    expect(matchesScopeFilter('namespaced', 'staging', selected)).toBe(false)
  })

  it('narrows to cluster-scoped records', () => {
    expect(matchesScopeFilter('cluster', undefined, [SCOPE_CLUSTER])).toBe(true)
    expect(matchesScopeFilter('namespaced', 'demo', [SCOPE_CLUSTER])).toBe(false)
  })

  it('mixes cluster-scoped with named namespaces', () => {
    const selected = [SCOPE_CLUSTER, 'demo']
    expect(matchesScopeFilter('cluster', undefined, selected)).toBe(true)
    expect(matchesScopeFilter('namespaced', 'demo', selected)).toBe(true)
    expect(matchesScopeFilter('namespaced', 'prod', selected)).toBe(false)
  })

  // The two APIs spell the namespaced scope differently — 'namespaced' for
  // tracing policies, 'namespace' for network policies — so only the cluster
  // value is ever compared.
  it('narrows by namespace regardless of how the scope is spelled', () => {
    expect(matchesScopeFilter('namespaced', 'demo', ['demo'])).toBe(true)
    expect(matchesScopeFilter('namespace', 'demo', ['demo'])).toBe(true)
  })

  // A namespace can legitimately be called "cluster", which is why the sentinel
  // is not that word.
  it('treats a namespace named cluster as a namespace', () => {
    expect(matchesScopeFilter('namespaced', 'cluster', ['cluster'])).toBe(true)
    expect(matchesScopeFilter('namespaced', 'cluster', [SCOPE_CLUSTER])).toBe(false)
  })

  it('excludes a cluster-scoped record when only namespaces are picked', () => {
    expect(matchesScopeFilter('cluster', undefined, ['demo'])).toBe(false)
  })
})
