import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import type { FileRule } from '../../api/types'

interface Props {
  rules: FileRule[]
  onChange: (rules: FileRule[]) => void
}

export function FileSection({ rules, onChange }: Props) {
  const update = (i: number, path: string) => {
    const next = [...rules]
    next[i] = { paths: [path] }
    onChange(next)
  }
  const add = () => onChange([...rules, { paths: [''] }])
  const remove = (i: number) => onChange(rules.filter((_, j) => j !== i))

  return (
    <div className="flex flex-col gap-2">
      {rules.map((r, i) => (
        <div key={i} className="flex items-center gap-2">
          <Input
            placeholder="/etc/shadow"
            value={r.paths[0] ?? ''}
            onChange={e => update(i, e.target.value)}
            className="h-8 text-sm"
          />
          <Button
            variant="ghost"
            size="sm"
            onClick={() => remove(i)}
            className="shrink-0 text-muted-foreground hover:text-destructive"
          >
            ✕
          </Button>
        </div>
      ))}
      <div>
        <Button variant="outline" size="sm" onClick={add}>+ Add</Button>
      </div>
    </div>
  )
}
