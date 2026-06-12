import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import {
  Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import type { FileRule } from '../../api/types'

interface Props {
  rules: FileRule[]
  onChange: (rules: FileRule[]) => void
}

export function FileSection({ rules, onChange }: Props) {
  const update = (i: number, patch: Partial<FileRule>) => {
    const next = [...rules]
    next[i] = { ...next[i], ...patch }
    onChange(next)
  }

  const add = () => onChange([...rules, { paths: [''], exceptBinaries: [], permission: 'all' }])
  const remove = (i: number) => onChange(rules.filter((_, j) => j !== i))

  const parseBinaries = (raw: string): string[] =>
    raw.split(',').map(s => s.trim()).filter(Boolean)

  const binariesString = (r: FileRule) => (r.exceptBinaries ?? []).join(', ')

  return (
    <div className="flex flex-col gap-3">
      {rules.map((r, i) => (
        <div key={i} className="flex flex-col gap-1.5 rounded-md border p-3">
          <div className="flex items-center gap-2">
            <div className="flex flex-1 flex-col gap-1">
              <span className="text-xs text-muted-foreground">Path</span>
              <Input
                placeholder="/etc/passwd"
                value={r.paths[0] ?? ''}
                onChange={e => update(i, { paths: [e.target.value] })}
                className="h-8 text-sm"
              />
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => remove(i)}
              className="mt-5 shrink-0 text-muted-foreground hover:text-destructive"
            >
              ✕
            </Button>
          </div>

          {/* Permission selector */}
          <div className="flex flex-col gap-1">
            <span className="text-xs text-muted-foreground">Permission</span>
            <Select
              value={r.permission ?? 'all'}
              onValueChange={(v) => update(i, { permission: v as FileRule['permission'] })}
            >
              <SelectTrigger className="h-8 w-48 text-sm">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value="all">Deny Read &amp; Write</SelectItem>
                  <SelectItem value="read">Only Deny Read</SelectItem>
                  <SelectItem value="write">Only Deny Write</SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>
          </div>

          {/* Exceptions */}
          <div className="flex flex-col gap-1">
            <span className="text-xs text-muted-foreground">
              Exceptions{' '}
              <span className="text-muted-foreground/60">
                (optional — these binaries bypass this rule, full path, comma-separated)
              </span>
            </span>
            <Input
              placeholder="/bin/bash, /usr/bin/cat"
              value={binariesString(r)}
              onChange={e => update(i, { exceptBinaries: parseBinaries(e.target.value) })}
              className="h-8 text-sm"
            />
            {(r.exceptBinaries ?? []).some(b => b && !b.startsWith('/')) && (
              <p className="text-xs text-amber-600">⚠ Binary paths must start with /</p>
            )}
          </div>
        </div>
      ))}
      <div>
        <Button variant="outline" size="sm" onClick={add}>+ Add</Button>
      </div>
    </div>
  )
}
