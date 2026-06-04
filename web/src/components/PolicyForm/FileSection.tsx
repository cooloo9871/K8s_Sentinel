import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import type { FileRule } from '../../api/types'

type FileEntry = { path: string; operation: FileRule['operation'] }

interface Props {
  rules: FileEntry[]
  onChange: (rules: FileEntry[]) => void
}

export function FileSection({ rules, onChange }: Props) {
  const update = (i: number, patch: Partial<FileEntry>) => {
    const next = [...rules]
    next[i] = { ...next[i], ...patch }
    onChange(next)
  }
  const add = () => onChange([...rules, { path: '', operation: 'read' }])
  const remove = (i: number) => onChange(rules.filter((_, j) => j !== i))

  return (
    <div className="flex flex-col gap-2">
      {rules.map((r, i) => (
        <div key={i} className="flex items-center gap-2">
          <Input
            placeholder="/etc/nginx/nginx.conf"
            value={r.path}
            onChange={(e) => update(i, { path: e.target.value })}
            className="h-8 flex-[2] text-sm"
          />
          <Select
            value={r.operation}
            onValueChange={(v) => update(i, { operation: v as FileRule['operation'] })}
          >
            <SelectTrigger className="h-8 w-28 text-sm">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="read">read</SelectItem>
                <SelectItem value="write">write</SelectItem>
                <SelectItem value="open">open</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>
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
        <Button variant="outline" size="sm" onClick={add}>
          + Add
        </Button>
      </div>
    </div>
  )
}
