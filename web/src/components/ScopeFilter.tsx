import {
  Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'

// Tracing Policy and Network Policy both hold cluster-scoped and namespaced
// policies, and both filtered on them with two separate dropdowns. One does the
// job: picking a namespace narrows to that namespace, and the cluster entry
// narrows to the cluster-scoped ones.
//
// Shared as a component rather than copied into both pages, because the two
// filters have to behave identically and copies drift.

// Sentinel values, not 'all' and 'cluster': a Kubernetes namespace really can be
// named "all" or "cluster", and it would then be indistinguishable from these.
// Underscores cannot appear in a namespace name, so these cannot collide.
export const SCOPE_ALL = '__all__'
export const SCOPE_CLUSTER = '__cluster__'

/**
 * Whether a policy passes the filter. `scope` is the record's own scope field,
 * which is 'cluster' for cluster-scoped policies on both APIs.
 */
export function matchesScopeFilter(
  scope: string,
  namespace: string | undefined,
  filter: string,
): boolean {
  if (filter === SCOPE_ALL) return true
  if (filter === SCOPE_CLUSTER) return scope === 'cluster'
  return (namespace ?? '') === filter
}

export function ScopeFilter({ value, onChange, namespaces }: {
  value: string
  onChange: (v: string) => void
  namespaces: string[]
}) {
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger className="h-8 w-52 text-sm">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectGroup>
          <SelectItem value={SCOPE_ALL}>All Namespaces</SelectItem>
          <SelectItem value={SCOPE_CLUSTER}>Cluster-wide</SelectItem>
          {namespaces.map(ns => (
            <SelectItem key={ns} value={ns}>{ns}</SelectItem>
          ))}
        </SelectGroup>
      </SelectContent>
    </Select>
  )
}
