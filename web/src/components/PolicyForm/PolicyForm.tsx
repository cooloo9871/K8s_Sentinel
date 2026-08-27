import { useEffect, useRef, useState } from 'react'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { policyApi } from '../../api/client'
import { NamespaceSelect } from '../NamespaceSelect'
import { SelectorPreview } from '../SelectorPreview'
import { completePairs } from '../../utils/labelPairs'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Button } from '@/components/ui/button'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { ProcessSection } from './ProcessSection'
import { FileSection } from './FileSection'
import type { PolicyFormInput } from '../../api/types'

type LabelEntry = { key: string; value: string }


interface Props {
  namespaces: string[]
  action: string
  value: PolicyFormInput
  onChange: (v: PolicyFormInput) => void
}

export function PolicyForm({ namespaces, action, value, onChange }: Props) {
  // Rendered by the server, with the same builder that applies the policy.
  // Generating it here as well meant two implementations of one thing, and when
  // they disagreed the YAML shown was not the YAML applied — the form submits
  // the form, and the server builds from that.
  //
  // Debounced, so typing does not fire a request per keystroke, and sequenced,
  // so a slow early response cannot overwrite a newer one.
  //
  // The debounce is for typing, not for arriving: applying it to the first
  // render left the panel blank for a third of a second every time the page was
  // opened, which read as the page being slow.
  const [yamlPreview, setYamlPreview] = useState('')
  const [previewError, setPreviewError] = useState('')
  const previewSeq = useRef(0)
  const rendered = useRef(false)

  useEffect(() => {
    if (!value.name) {
      setYamlPreview('')
      setPreviewError('')
      return
    }
    const seq = ++previewSeq.current
    const delay = rendered.current ? 300 : 0
    rendered.current = true
    const timer = setTimeout(() => {
      policyApi.preview(value, action)
        .then(yaml => {
          if (seq !== previewSeq.current) return
          setYamlPreview(yaml)
          setPreviewError('')
        })
        .catch((e: Error) => {
          if (seq !== previewSeq.current) return
          // The builder refuses some inputs — a relative binary path, say — and
          // saying so here is more use than a blank panel, since this is where
          // you are looking while typing it.
          setPreviewError(e.message || 'Could not render the policy')
          setYamlPreview('')
        })
    }, delay)
    return () => clearTimeout(timer)
  }, [value, action])

  const processBinaries = value.process?.map((p) => p.binaries[0] ?? '') ?? []
  const fileRules = value.file ?? []

  // Use local state for label entries so empty keys don't get discarded while typing
  const [localLabels, setLocalLabels] = useState<LabelEntry[]>(() =>
    Object.entries(value.podSelector ?? {}).map(([k, v]) => ({ key: k, value: v }))
  )

  // Sync when parent loads a different policy (e.g., switching from edit to new)
  useEffect(() => {
    setLocalLabels(
      Object.entries(value.podSelector ?? {}).map(([k, v]) => ({ key: k, value: v }))
    )
  // Sort keys before stringifying so that {b:2,a:1} and {a:1,b:2} produce
  // identical strings and don't trigger unnecessary resets mid-input.
  }, [JSON.stringify(Object.fromEntries(Object.entries(value.podSelector ?? {}).sort(([a], [b]) => a.localeCompare(b))))])

  const setProcessBinaries = (binaries: string[]) =>
    onChange({ ...value, process: binaries.map((b) => ({ binaries: [b] })) })

  const setFileRules = (rules: typeof fileRules) =>
    onChange({ ...value, file: rules })


  const syncLabelsToParent = (entries: LabelEntry[]) => {
    setLocalLabels(entries)
    // completePairs is also what the preview renders, so the two cannot
    // disagree about a half-filled row again.
    const selector = completePairs(entries)
    onChange({
      ...value,
      podSelector: Object.keys(selector).length > 0 ? selector : undefined,
    })
  }

  const addLabel = () => syncLabelsToParent([...localLabels, { key: '', value: '' }])
  const removeLabel = (i: number) => syncLabelsToParent(localLabels.filter((_, j) => j !== i))
  const updateLabel = (i: number, patch: Partial<LabelEntry>) => {
    const next = [...localLabels]
    next[i] = { ...next[i], ...patch }
    syncLabelsToParent(next)
  }

  return (
    <div className="grid grid-cols-2 gap-6">
      {/* Left: form cards */}
      <div className="flex flex-col gap-4">

        {/* Basic Info */}
        <Card>
          <CardHeader className="border-b pb-3">
            <CardTitle className="text-sm font-medium">Basic Information</CardTitle>
          </CardHeader>
          <CardContent className="pt-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="policy-name">
                  Policy Name <span className="text-destructive">*</span>
                </Label>
                <Input
                  id="policy-name"
                  value={value.name}
                  onChange={(e) => onChange({ ...value, name: e.target.value })}
                />
              </div>
              <div className="flex flex-col gap-1.5">
                <Label>Namespace</Label>
                {/* undefined, not '', is what selects the cluster-wide kind, so
                    the two are mapped at this boundary. */}
                <NamespaceSelect
                  value={value.namespace ?? ''}
                  onChange={(v) => onChange({ ...value, namespace: v || undefined })}
                  namespaces={namespaces}
                  noneLabel="cluster-wide"
                />
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Pod Selector */}
        <Card>
          <CardHeader className="border-b pb-3">
            <CardTitle className="text-sm font-medium">Pod Selector</CardTitle>
          </CardHeader>
          <CardContent className="pt-4">
            <p className="mb-3 text-xs text-muted-foreground">
              Target specific pods by label. Leave empty to apply to all pods in the namespace.
            </p>
            {/* Captioned above rather than joined by "=", matching the label
                rows on Network Policy. */}
            <div className="flex flex-col gap-2">
              {localLabels.map((entry, i) => (
                <div key={i} className="flex items-end gap-2">
                  <div className="flex flex-1 flex-col gap-1">
                    <span className="text-[11px] text-muted-foreground">Key</span>
                    <Input
                      value={entry.key}
                      onChange={(e) => updateLabel(i, { key: e.target.value })}
                      className="h-8 font-mono text-sm"
                    />
                  </div>
                  <div className="flex flex-1 flex-col gap-1">
                    <span className="text-[11px] text-muted-foreground">Value</span>
                    <Input
                      value={entry.value}
                      onChange={(e) => updateLabel(i, { value: e.target.value })}
                      className="h-8 font-mono text-sm"
                    />
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => removeLabel(i)}
                    className="h-8 shrink-0 px-2 text-xs text-destructive hover:text-destructive"
                  >
                    Remove
                  </Button>
                </div>
              ))}
              <SelectorPreview
                namespace={value.namespace ?? ''}
                matchLabels={completePairs(localLabels)}
              />
              <div>
                <Button variant="outline" size="sm" onClick={addLabel}>
                  + Add Label
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Process Rules */}
        <Card>
          <CardHeader className="border-b pb-3">
            <CardTitle className="text-sm font-medium">Process Rules</CardTitle>
          </CardHeader>
          <CardContent className="pt-4">
            <div className="mb-4 flex flex-col gap-1.5">
              <Label className="text-xs">Mode</Label>
              <Select
                value={value.processMode ?? 'whitelist'}
                onValueChange={(v) => onChange({ ...value, processMode: v as 'whitelist' | 'blacklist' })}
              >
                <SelectTrigger className="h-8 w-64 text-sm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectItem value="whitelist">
                      Whitelist
                    </SelectItem>
                    <SelectItem value="blacklist">
                      Blacklist
                    </SelectItem>
                  </SelectGroup>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {(value.processMode ?? 'whitelist') === 'whitelist'
                  ? 'Whitelist: only the binaries you list are allowed to run. Everything else is blocked.'
                  : 'Blacklist: only the binaries you list are blocked. Everything else is allowed.'}
              </p>
            </div>
            <ProcessSection binaries={processBinaries} onChange={setProcessBinaries} />
          </CardContent>
        </Card>

        {/* File Rules */}
        <Card>
          <CardHeader className="border-b pb-3">
            <CardTitle className="text-sm font-medium">File Rules</CardTitle>
          </CardHeader>
          <CardContent className="pt-4">
            <div className="mb-4 flex flex-col gap-1.5">
              <Label className="text-xs">Mode</Label>
              <Select
                value={value.fileMode ?? 'blacklist'}
                onValueChange={(v) => onChange({ ...value, fileMode: v as 'whitelist' | 'blacklist' })}
              >
                <SelectTrigger className="h-8 w-64 text-sm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectItem value="whitelist">Whitelist</SelectItem>
                    <SelectItem value="blacklist">Blacklist</SelectItem>
                  </SelectGroup>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {(value.fileMode ?? 'blacklist') === 'whitelist'
                  ? 'Whitelist: only the paths you list are allowed. Everything else is blocked.'
                  : 'Blacklist: only the paths you list are blocked. Everything else is allowed.'}
              </p>
            </div>
            <FileSection rules={fileRules} onChange={setFileRules} fileMode={value.fileMode ?? 'blacklist'} />
          </CardContent>
        </Card>

      </div>

      {/* Right: YAML preview. gap-0 py-0 so the code surface meets the frame:
          Card adds py-4 and gap-4 otherwise, insetting it. */}
      <Card className="gap-0 overflow-hidden py-0">
        <div className="flex items-center justify-between border-b px-4 py-3">
          <span className="text-sm font-medium">Generated YAML</span>
          <Badge variant="secondary" className="font-mono text-[10px]">
            {value.namespace ? 'TracingPolicyNamespaced' : 'TracingPolicy'}
          </Badge>
        </div>
        <CardContent className="min-h-0 flex-1 p-0">
          <pre className="h-full min-h-[420px] overflow-auto rounded-b-xl bg-[#1e1e1e] p-4 font-mono text-xs leading-relaxed text-[#d4d4d4]">
            {previewError
              ? <span className="text-red-400">{previewError}</span>
              : yamlPreview}
          </pre>
        </CardContent>
      </Card>
    </div>
  )
}
