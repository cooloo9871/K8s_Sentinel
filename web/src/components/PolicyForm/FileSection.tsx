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
  const updateRule = (i: number, patch: Partial<FileRule>) => {
    const next = [...rules]
    next[i] = { ...next[i], ...patch }
    onChange(next)
  }

  const addRule = () => onChange([...rules, { paths: [''], exceptBinaries: [], permission: 'all' }])
  const removeRule = (i: number) => onChange(rules.filter((_, j) => j !== i))

  // Exceptions — individual entries
  const updateException = (ruleIdx: number, excIdx: number, val: string) => {
    const exc = [...(rules[ruleIdx].exceptBinaries ?? [])]
    exc[excIdx] = val
    updateRule(ruleIdx, { exceptBinaries: exc })
  }
  const addException = (ruleIdx: number) =>
    updateRule(ruleIdx, { exceptBinaries: [...(rules[ruleIdx].exceptBinaries ?? []), ''] })
  const removeException = (ruleIdx: number, excIdx: number) =>
    updateRule(ruleIdx, {
      exceptBinaries: (rules[ruleIdx].exceptBinaries ?? []).filter((_, j) => j !== excIdx),
    })

  return (
    <div className="flex flex-col gap-3">
      {rules.map((r, i) => (
        <div key={i} className="flex flex-col gap-2 rounded-md border p-3">
          {/* Path */}
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

          {/* Permission */}
          <div className="flex flex-col gap-1">
            <span className="text-xs text-muted-foreground">Permission</span>
            <Select
              value={r.permission ?? 'all'}
              onValueChange={(v) => updateRule(i, { permission: v as FileRule['permission'] })}
            >
              <SelectTrigger className="h-8 w-52 text-sm">
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
          <div className="flex flex-col gap-1.5">
            <span className="text-xs text-muted-foreground">
              Exceptions{' '}
              <span className="text-muted-foreground/60">
                (optional: these processes bypass this rule)
              </span>
            </span>
            {(r.exceptBinaries ?? []).map((bin, ei) => (
              <div key={ei} className="flex items-center gap-2">
                <Input
                  placeholder="/bin/bash"
                  value={bin}
                  onChange={e => updateException(i, ei, e.target.value)}
                  className="h-8 text-sm"
                />
                {bin && !bin.startsWith('/') && (
                  <span className="shrink-0 text-xs text-amber-600">Absolute paths required</span>
                )}
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => removeException(i, ei)}
                  className="shrink-0 text-muted-foreground hover:text-destructive"
                >
                  ✕
                </Button>
              </div>
            ))}
            <div>
              <Button variant="outline" size="sm" onClick={() => addException(i)}>
                + Add Exception
              </Button>
            </div>
          </div>
        </div>
      ))}
      <div>
        <Button variant="outline" size="sm" onClick={addRule}>+ Add</Button>
      </div>
    </div>
  )
}
