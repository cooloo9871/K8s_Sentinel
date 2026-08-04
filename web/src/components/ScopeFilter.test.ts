import { describe, it, expect } from 'vitest'
import { matchesScopeFilter, SCOPE_ALL, SCOPE_CLUSTER } from './ScopeFilter'

describe('matchesScopeFilter', () => {
  it('lets everything through by default', () => {
    expect(matchesScopeFilter('cluster', undefined, SCOPE_ALL)).toBe(true)
    expect(matchesScopeFilter('namespaced', 'demo', SCOPE_ALL)).toBe(true)
  })

  it('narrows to cluster-scoped policies', () => {
    expect(matchesScopeFilter('cluster', undefined, SCOPE_CLUSTER)).toBe(true)
    expect(matchesScopeFilter('namespaced', 'demo', SCOPE_CLUSTER)).toBe(false)
  })

  // The two APIs spell the namespaced scope differently — 'namespaced' for
  // tracing policies, 'namespace' for network policies — so only the cluster
  // value is compared, which is the same on both.
  it('narrows to one namespace regardless of how the scope is spelled', () => {
    expect(matchesScopeFilter('namespaced', 'demo', 'demo')).toBe(true)
    expect(matchesScopeFilter('namespace', 'demo', 'demo')).toBe(true)
    expect(matchesScopeFilter('namespace', 'other', 'demo')).toBe(false)
  })

  // A namespace can legitimately be called "all" or "cluster", which is why the
  // sentinels are not those words.
  it('treats a namespace named all or cluster as a namespace', () => {
    expect(matchesScopeFilter('namespaced', 'all', 'all')).toBe(true)
    expect(matchesScopeFilter('namespaced', 'cluster', 'cluster')).toBe(true)
    // ...and it does not pass the cluster-scope filter just because of its name.
    expect(matchesScopeFilter('namespaced', 'cluster', SCOPE_CLUSTER)).toBe(false)
  })

  it('excludes a cluster-scoped policy when a namespace is picked', () => {
    expect(matchesScopeFilter('cluster', undefined, 'demo')).toBe(false)
  })
})
