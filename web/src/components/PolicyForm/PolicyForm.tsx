import { useMemo } from 'react'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
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
import { formToYaml } from '../../utils/formToYaml'
import type { PolicyFormInput, FileRule } from '../../api/types'

type FileEntry = { path: string; operation: FileRule['operation'] }

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
  const fileEntries: FileEntry[] =
    value.file?.map((f) => ({ path: f.paths[0] ?? '', operation: f.operation })) ?? []

  const setProcessBinaries = (binaries: string[]) =>
    onChange({ ...value, process: binaries.map((b) => ({ binaries: [b] })) })

  const setFileEntries = (entries: FileEntry[]) =>
    onChange({
      ...value,
      file: entries.map((e) => ({ paths: [e.path], operation: e.operation })),
    })

  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1fr_340px]">
      {/* Left: form cards */}
      <div className="flex flex-col gap-4">

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

        <Card>
          <CardHeader className="border-b pb-3">
            <CardTitle className="text-sm font-medium">Process Rules</CardTitle>
          </CardHeader>
          <CardContent className="pt-4">
            <ProcessSection binaries={processBinaries} onChange={setProcessBinaries} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="border-b pb-3">
            <CardTitle className="text-sm font-medium">File Rules</CardTitle>
          </CardHeader>
          <CardContent className="pt-4">
            <FileSection rules={fileEntries} onChange={setFileEntries} />
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
