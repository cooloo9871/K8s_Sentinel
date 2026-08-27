import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import {
  Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import type { FileRule } from '../../api/types'

interface Props {
  rules: FileRule[]
  onChange: (rules: FileRule[]) => void
  fileMode: 'whitelist' | 'blacklist'
}

// A reusable editor for a list of absolute paths (used for excluded paths and
// exception processes), with the same "absolute paths required" hint.
function PathList({ label, hint, placeholder, values, onChange }: {
  label: string
  hint?: string
  placeholder: string
  values: string[]
  onChange: (v: string[]) => void
}) {
  const shown = values.length > 0 ? values : ['']
  const write = (next: string[]) => onChange(next)
  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-xs text-muted-foreground">
        {label}{hint && <span className="text-muted-foreground/60"> {hint}</span>}
      </span>
      {shown.map((v, i) => (
        <div key={i} className="flex items-center gap-2">
          <Input
            placeholder={placeholder}
            value={v}
            onChange={e => { const n = [...shown]; n[i] = e.target.value; write(n) }}
            className="h-8 text-sm"
          />
          {v && !v.startsWith('/') && (
            <span className="shrink-0 text-xs text-amber-600">Absolute paths required</span>
          )}
          <Button
            variant="ghost"
            size="sm"
            onClick={() => write(shown.filter((_, j) => j !== i))}
            className="shrink-0 text-muted-foreground hover:text-destructive"
          >
            ✕
          </Button>
        </div>
      ))}
      <div>
        <Button variant="outline" size="sm" onClick={() => write([...values, ''])}>+ Add</Button>
      </div>
    </div>
  )
}

function PermissionSelect({ value, onChange }: {
  value: FileRule['permission']
  onChange: (v: FileRule['permission']) => void
}) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs text-muted-foreground">Permission</span>
      <Select value={value ?? 'all'} onValueChange={(v) => onChange(v as FileRule['permission'])}>
        <SelectTrigger className="h-8 w-52 text-sm"><SelectValue /></SelectTrigger>
        <SelectContent>
          <SelectGroup>
            <SelectItem value="all">Read &amp; Write</SelectItem>
            <SelectItem value="read">Read only</SelectItem>
            <SelectItem value="write">Write only</SelectItem>
          </SelectGroup>
        </SelectContent>
      </Select>
    </div>
  )
}

export function FileSection({ rules, onChange, fileMode }: Props) {
  // Whitelist is ONE exclusion set (Tetragon OR-s separate selectors, which
  // breaks NotPrefix), so the form collapses everything into a single group:
  // one list of excluded paths, one permission, one list of exception processes.
  if (fileMode === 'whitelist') {
    const paths = rules.flatMap(r => r.paths ?? [])
    const except = rules.flatMap(r => r.exceptBinaries ?? [])
    const permission = rules.map(r => r.permission).find(p => p && p !== 'all') ?? 'all'
    const write = (patch: Partial<FileRule>) =>
      onChange([{ paths, exceptBinaries: except, permission, ...patch }])
    return (
      <div className="flex flex-col gap-3 rounded-md border p-3">
        <PathList
          label="Excluded paths"
          hint="(everything else is monitored)"
          placeholder="/etc/passwd"
          values={paths}
          onChange={(v) => write({ paths: v })}
        />
        <PermissionSelect value={permission} onChange={(v) => write({ permission: v })} />
        <PathList
          label="Exception processes"
          hint="(optional: their access is not monitored)"
          placeholder="/bin/bash"
          values={except}
          onChange={(v) => write({ exceptBinaries: v })}
        />
      </div>
    )
  }

  // Blacklist: multiple independent block rules, each with its own path,
  // permission and exception processes.
  const updateRule = (i: number, patch: Partial<FileRule>) => {
    const next = [...rules]
    next[i] = { ...next[i], ...patch }
    onChange(next)
  }
  const addRule = () => onChange([...rules, { paths: [''], exceptBinaries: [], permission: 'all' }])
  const removeRule = (i: number) => onChange(rules.filter((_, j) => j !== i))

  return (
    <div className="flex flex-col gap-3">
      {rules.map((r, i) => (
        <div key={i} className="flex flex-col gap-2 rounded-md border p-3">
          <div className="flex items-center gap-2">
            <div className="flex flex-1 flex-col gap-1">
              <span className="text-xs text-muted-foreground">Path</span>
              <Input
                placeholder="/etc/passwd"
                value={r.paths[0] ?? ''}
                onChange={e => updateRule(i, { paths: [e.target.value] })}
                className="h-8 text-sm"
              />
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => removeRule(i)}
              className="mt-5 shrink-0 text-muted-foreground hover:text-destructive"
            >
              ✕
            </Button>
          </div>
          <PermissionSelect value={r.permission} onChange={(v) => updateRule(i, { permission: v })} />
          <PathList
            label="Exceptions"
            hint="(optional: these processes bypass this rule)"
            placeholder="/bin/bash"
            values={r.exceptBinaries ?? []}
            onChange={(v) => updateRule(i, { exceptBinaries: v })}
          />
        </div>
      ))}
      <div>
        <Button variant="outline" size="sm" onClick={addRule}>+ Add</Button>
      </div>
    </div>
  )
}
