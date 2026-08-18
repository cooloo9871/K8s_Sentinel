import { useEffect, useState } from 'react'
import { selectorApi, type SelectorPreviewResult } from '../api/client'

// The most damaging policy mistake is a selector that matches something other
// than what the author meant: nothing (a typo selects no pods and the policy
// silently governs nothing) or everything. This line answers "which pods would
// this govern, right now" while the selector is being typed, which is the
// cheapest place to catch either.
export function SelectorPreview({ namespace, matchLabels }: {
  // "" means every namespace.
  namespace: string
  matchLabels: Record<string, string>
}) {
  const [result, setResult] = useState<SelectorPreviewResult | null>(null)
  const [failed, setFailed] = useState(false)

  const labelsKey = JSON.stringify(matchLabels)
  useEffect(() => {
    let stale = false
    const t = setTimeout(() => {
      selectorApi.preview(namespace, JSON.parse(labelsKey))
        .then(r => { if (!stale) { setResult(r); setFailed(false) } })
        .catch(() => { if (!stale) setFailed(true) })
    }, 400)
    return () => { stale = true; clearTimeout(t) }
  }, [namespace, labelsKey])

  if (failed || result === null) return null

  const hasLabels = Object.keys(matchLabels).length > 0
  const where = namespace ? `in ${namespace}` : 'in the cluster'

  if (result.total === 0) {
    return (
      <p className="text-[11px] text-destructive">
        Selects no pods {where} right now. A typo in a label selects nothing, silently.
      </p>
    )
  }
  const names = result.pods.map(p => (namespace ? p.name : `${p.namespace}/${p.name}`))
  const shown = names.slice(0, 5).join(', ')
  const more = result.total - Math.min(5, names.length)
  return (
    <p className={`text-[11px] ${hasLabels ? 'text-muted-foreground' : 'text-amber-600'}`}>
      {hasLabels
        ? `Selects ${result.total} pod${result.total === 1 ? '' : 's'} ${where}: `
        : `No labels: selects every pod ${where}, currently ${result.total}. `}
      {shown}{more > 0 ? ` and ${more} more` : ''}
    </p>
  )
}
