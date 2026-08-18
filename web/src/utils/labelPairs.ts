// The one conversion from label rows to a selector, shared by everything that
// renders or saves one. The preview and the save each had their own filter and
// disagreed on half-filled rows: the preview dropped them while the save wrote
// {app: ""}, so the preview described a selector the policy did not apply.
export interface LabelEntry {
  key: string
  value: string
}

/** Rows with both halves filled in, trimmed. A half row selects nothing a
 * person means, so it is not part of the selector until it is complete. */
export function completePairs(entries: LabelEntry[]): Record<string, string> {
  const out: Record<string, string> = {}
  for (const { key, value } of entries) {
    const k = key.trim()
    const v = value.trim()
    if (k && v) out[k] = v
  }
  return out
}
