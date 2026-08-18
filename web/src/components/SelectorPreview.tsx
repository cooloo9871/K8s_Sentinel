import { useEffect, useRef, useState } from 'react'
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
  // The result is keyed by the request that produced it, so an answer for an
  // earlier selector is never rendered under the current one. Warnings here
  // point in opposite directions (red for nothing, amber for everything), and
  // a stale total showed the wrong one for the debounce-plus-roundtrip window.
  const [result, setResult] = useState<{ key: string; data: SelectorPreviewResult } | null>(null)
  const [failedKey, setFailedKey] = useState<string | null>(null)
  // The debounce is for typing, not for arriving: applied to the first render
  // it would leave the line blank for half a second every time the form opens.
  const rendered = useRef(false)

  const key = namespace + '\u0000' + JSON.stringify(matchLabels)
  const hasLabels = Object.keys(matchLabels).length > 0
  // Everything in the cluster needs no query to describe, and asking would
  // list every pod there is on each keystroke.
  const wholeCluster = !hasLabels && namespace === ''

  useEffect(() => {
    if (wholeCluster) return
    let stale = false
    const delay = rendered.current ? 400 : 0
    rendered.current = true
    const t = setTimeout(() => {
      selectorApi.preview(namespace, matchLabels)
        .then(r => { if (!stale) setResult({ key, data: r }) })
        .catch(() => { if (!stale) setFailedKey(key) })
    }, delay)
    return () => { stale = true; clearTimeout(t) }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key])

  const where = namespace ? `in ${namespace}` : 'in the cluster'

  if (wholeCluster) {
    return (
      <p className="text-[11px] text-amber-600">
        No labels: selects every pod in the cluster.
      </p>
    )
  }
  // A selector the apiserver refuses must not make the preview silently
  // vanish: the one time the line disappears is exactly when the input needs
  // a look.
  if (failedKey === key) {
    return (
      <p className="text-[11px] text-muted-foreground">
        Preview unavailable for this selector.
      </p>
    )
  }
  if (result?.key !== key) return null
  const { total, pods } = result.data

  if (total === 0) {
    return (
      <p className="text-[11px] text-destructive">
        Selects no pods {where} right now. A typo in a label selects nothing, silently.
      </p>
    )
  }
  const names = pods.map(p => (namespace ? p.name : `${p.namespace}/${p.name}`))
  const shown = names.slice(0, 5).join(', ')
  const more = total - Math.min(5, names.length)
  return (
    <p className={`text-[11px] ${hasLabels ? 'text-muted-foreground' : 'text-amber-600'}`}>
      {hasLabels
        ? `Selects ${total} pod${total === 1 ? '' : 's'} ${where}: `
        : `No labels: selects every pod ${where}, currently ${total}. `}
      {shown}{more > 0 ? ` and ${more} more` : ''}
    </p>
  )
}
