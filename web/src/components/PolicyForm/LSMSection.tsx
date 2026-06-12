import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import type { LSMRule } from '../../api/types'

interface Props {
  rules: LSMRule[]
  onChange: (rules: LSMRule[]) => void
}

export function LSMSection({ rules, onChange }: Props) {
  const updateRule = (i: number, patch: Partial<LSMRule>) => {
    const next = [...rules]
    next[i] = { ...next[i], ...patch }
    onChange(next)
  }

  const addRule = () => onChange([...rules, { paths: [''], exceptBinaries: [] }])
  const removeRule = (i: number) => onChange(rules.filter((_, j) => j !== i))

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

          <div className="flex flex-col gap-1.5">
            <span className="text-xs text-muted-foreground">
              Exceptions{' '}
              <span className="text-muted-foreground/60">
                (optional — these processes can still open the file)
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
                  <span className="shrink-0 text-xs text-amber-600">full path required</span>
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
