import { useEffect, useMemo, useState } from 'react'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
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
import { NetworkSection } from './NetworkSection'
import { formToYaml } from '../../utils/formToYaml'
import type { PolicyFormInput, NetworkRule } from '../../api/types'

type LabelEntry = { key: string; value: string }

const CLUSTER_WIDE = '__cluster_wide__'

interface Props {
  namespaces: string[]
  action: string
  value: PolicyFormInput
  onChange: (v: PolicyFormInput) => void
}

export function PolicyForm({ namespaces, action, value, onChange }: Props) {
  const yamlPreview = useMemo(() => {
    if (!value.name) return ''
    try {
      return formToYaml(value, action)
    } catch {
      return ''
    }
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

  const setNetRules = (rules: NetworkRule[]) =>
    onChange({ ...value, network: rules })


  const syncLabelsToParent = (entries: LabelEntry[]) => {
    setLocalLabels(entries)
    const selector = entries.reduce<Record<string, string>>((acc, { key, value: v }) => {
      if (key.trim()) acc[key.trim()] = v.trim()
      return acc
    }, {})
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
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1fr_340px]">
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
                  placeholder="my-policy"
                  value={value.name}
                  onChange={(e) => onChange({ ...value, name: e.target.value })}
                />
              </div>
              <div className="flex flex-col gap-1.5">
                <Label>Namespace</Label>
                <Select
                  value={value.namespace ?? CLUSTER_WIDE}
                  onValueChange={(v) =>
                    onChange({ ...value, namespace: v === CLUSTER_WIDE ? undefined : v })
                  }
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      <SelectItem value={CLUSTER_WIDE}>cluster-wide</SelectItem>
                      {namespaces.map((n) => (
                        <SelectItem key={n} value={n}>{n}</SelectItem>
                      ))}
                    </SelectGroup>
                  </SelectContent>
                </Select>
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
            <div className="flex flex-col gap-2">
              {localLabels.map((entry, i) => (
                <div key={i} className="flex items-center gap-2">
                  <Input
                    placeholder="Key (e.g. app)"
                    value={entry.key}
                    onChange={(e) => updateLabel(i, { key: e.target.value })}
                    className="h-8 text-sm"
                  />
                  <span className="shrink-0 text-sm text-muted-foreground">=</span>
                  <Input
                    placeholder="Value (e.g. nginx)"
                    value={entry.value}
                    onChange={(e) => updateLabel(i, { value: e.target.value })}
                    className="h-8 text-sm"
                  />
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => removeLabel(i)}
                    className="shrink-0 text-muted-foreground hover:text-destructive"
                  >
                    ✕
                  </Button>
                </div>
              ))}
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
                      NotPostfix — Whitelist
                    </SelectItem>
                    <SelectItem value="blacklist">
                      Postfix — Blacklist
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
            <FileSection rules={fileRules} onChange={setFileRules} />
          </CardContent>
        </Card>

        {/* Network Rules */}
        <Card>
          <CardHeader className="border-b pb-3">
            <CardTitle className="text-sm font-medium">Network Rules</CardTitle>
          </CardHeader>
          <CardContent className="pt-4">
            {/* Mode selector */}
            <div className="mb-4 flex flex-col gap-1.5">
              <Label className="text-xs">Mode</Label>
              <Select
                value={value.networkMode ?? 'whitelist'}
                onValueChange={(v) =>
                  onChange({ ...value, networkMode: v as 'whitelist' | 'blacklist' })
                }
              >
                <SelectTrigger className="h-8 w-64 text-sm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectItem value="whitelist">
                      NotDAddr — Whitelist
                    </SelectItem>
                    <SelectItem value="blacklist">
                      DAddr — Blacklist
                    </SelectItem>
                  </SelectGroup>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {value.networkMode === 'blacklist'
                  ? 'Blacklist: connections to the listed addresses (and ports, if set) are blocked. Everything else is allowed.'
                  : 'Whitelist: only connections to the listed addresses (and ports, if set) are allowed. Everything else is blocked.'}
              </p>
            </div>
            {/* Address list */}
            <p className="mb-1 text-xs font-medium text-foreground">Addresses</p>
            <NetworkSection
              rules={value.network ?? []}
              onChange={setNetRules}
            />

            {/* Port list */}
            <div className="mt-4">
              <p className="mb-1 text-xs font-medium text-foreground">
                Ports
                <span className="ml-1 font-normal text-muted-foreground">
                  (optional — leave empty to match all ports)
                </span>
              </p>
              <p className="mb-2 text-xs text-muted-foreground">
                DPort: rule triggers only when destination port matches.
                ANDed with the address condition above.
              </p>
              <div className="flex flex-col gap-2">
                {(value.networkPorts ?? []).map((port, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <Input
                      placeholder="e.g. 6379"
                      value={port}
                      onChange={(e) => {
                        const next = [...(value.networkPorts ?? [])]
                        next[i] = e.target.value
                        onChange({ ...value, networkPorts: next })
                      }}
                      className="h-8 w-36 text-sm"
                      type="number"
                      min={1}
                      max={65535}
                    />
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() =>
                        onChange({
                          ...value,
                          networkPorts: (value.networkPorts ?? []).filter((_, j) => j !== i),
                        })
                      }
                      className="shrink-0 text-muted-foreground hover:text-destructive"
                    >
                      ✕
                    </Button>
                  </div>
                ))}
                <div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() =>
                      onChange({ ...value, networkPorts: [...(value.networkPorts ?? []), ''] })
                    }
                  >
                    + Add Port
                  </Button>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

      </div>

      {/* Right: YAML preview */}
      <div className="sticky top-20 self-start">
        <div className="overflow-hidden rounded-lg">
          <div
            className="flex items-center justify-between px-3 py-2"
            style={{ background: '#252526', borderBottom: '1px solid #3c3c3c' }}
          >
            <span className="font-mono text-xs" style={{ color: '#9cdcfe' }}>
              YAML Preview
            </span>
            <span
              className="rounded px-1.5 py-0.5 text-[10px]"
              style={{
                color: yamlPreview ? '#4ec94e' : '#6c757d',
                background: yamlPreview ? '#1a3a1a' : '#2a2a2a',
              }}
            >
              {yamlPreview ? '✓ valid' : '—'}
            </span>
          </div>
          <pre
            className="overflow-auto whitespace-pre-wrap p-3 font-mono text-xs leading-relaxed"
            style={{
              margin: 0,
              background: '#1e1e1e',
              color: '#d4d4d4',
              minHeight: 200,
              maxHeight: 500,
            }}
          >
            {yamlPreview || (
              <span style={{ color: '#555' }}>Enter a policy name to preview…</span>
            )}
          </pre>
        </div>
      </div>
    </div>
  )
}
