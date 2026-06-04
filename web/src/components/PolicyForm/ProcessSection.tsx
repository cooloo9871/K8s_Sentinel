import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'

interface Props {
  binaries: string[]
  onChange: (binaries: string[]) => void
}

export function ProcessSection({ binaries, onChange }: Props) {
  const update = (i: number, val: string) => {
    const next = [...binaries]
    next[i] = val
    onChange(next)
  }
  const add = () => onChange([...binaries, ''])
  const remove = (i: number) => onChange(binaries.filter((_, j) => j !== i))

  return (
    <div className="flex flex-col gap-2">
      {binaries.map((b, i) => (
        <div key={i} className="flex items-center gap-2">
          <Input
            placeholder="/usr/bin/nginx"
            value={b}
            onChange={(e) => update(i, e.target.value)}
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
        <Button variant="outline" size="sm" onClick={add}>
          + Add
        </Button>
      </div>
    </div>
  )
}
