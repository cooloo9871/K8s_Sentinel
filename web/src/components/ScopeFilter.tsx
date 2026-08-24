import { IconChevronDown } from '@tabler/icons-react'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'

// Tracing Policy, Network Policy and Network Topology all filter by namespace,
// and all of them used to allow exactly one at a time — so comparing two
// namespaces meant switching back and forth. Selecting several is the point of
// this control, and it is shared so the three cannot drift apart again.

// Stands for the cluster-scoped policies, which have no namespace to select.
// Not the word "cluster": a namespace really can be called that, and it would
// then be indistinguishable. Underscores cannot appear in a namespace name.
export const SCOPE_CLUSTER = '__cluster__'

/**
 * Whether a record passes the filter. An empty selection means no filter at all,
 * which is what "All namespaces" is — not a value to be matched.
 */
export function matchesScopeFilter(
  scope: string,
  namespace: string | undefined,
  selected: string[],
): boolean {
  if (selected.length === 0) return true
  if (scope === 'cluster') return selected.includes(SCOPE_CLUSTER)
  return selected.includes(namespace ?? '')
}

/** What the trigger says, so a glance tells you whether a filter is active. */
function summarise(selected: string[]): string {
  if (selected.length === 0) return 'All namespaces'
  if (selected.length === 1) {
    return selected[0] === SCOPE_CLUSTER ? 'Cluster-wide' : selected[0]
  }
  return `${selected.length} selected`
}

export function ScopeFilter({
  value, onChange, namespaces, includeCluster = true, className,
}: {
  value: string[]
  onChange: (v: string[]) => void
  namespaces: string[]
  /** Offer the cluster-scoped entry. Off where every record has a namespace. */
  includeCluster?: boolean
  className?: string
}) {
  const toggle = (key: string) =>
    onChange(value.includes(key) ? value.filter(v => v !== key) : [...value, key])

  const entries = [
    ...(includeCluster ? [{ key: SCOPE_CLUSTER, label: 'Cluster-wide' }] : []),
    ...namespaces.map(ns => ({ key: ns, label: ns })),
  ]

  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          className={className ?? 'h-8 w-52 justify-between text-sm font-normal'}
        >
          <span className="truncate">{summarise(value)}</span>
          <IconChevronDown size={14} className="shrink-0 opacity-50" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-56 p-0">
        <div className="max-h-72 overflow-y-auto p-1">
          {entries.length === 0 ? (
            <p className="px-2 py-3 text-center text-xs text-muted-foreground">
              No namespaces
            </p>
          ) : entries.map(e => (
            <label
              key={e.key}
              className="flex cursor-pointer select-none items-center gap-2 rounded-sm px-2 py-1.5 text-sm hover:bg-accent"
            >
              <Checkbox
                checked={value.includes(e.key)}
                onCheckedChange={() => toggle(e.key)}
                className="size-3.5"
              />
              <span className="truncate">{e.label}</span>
            </label>
          ))}
        </div>
        {value.length > 0 && (
          <div className="border-t p-1">
            <Button
              variant="ghost"
              size="sm"
              className="h-7 w-full text-xs"
              onClick={() => onChange([])}
            >
              Clear
            </Button>
          </div>
        )}
      </PopoverContent>
    </Popover>
  )
}
