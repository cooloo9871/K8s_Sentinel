import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import type { NetworkRule } from '../../api/types'

interface Props {
  rules: NetworkRule[]
  onChange: (rules: NetworkRule[]) => void
}

export function NetworkSection({ rules, onChange }: Props) {
  const update = (i: number, address: string) => {
    const next = [...rules]
    next[i] = { address }
    onChange(next)
  }
  const add = () => onChange([...rules, { address: '' }])
  const remove = (i: number) => onChange(rules.filter((_, j) => j !== i))

  return (
    <div className="flex flex-col gap-2">
      {rules.map((r, i) => (
        <div key={i} className="flex items-center gap-2">
          <Input
            placeholder="e.g. 127.0.0.1 or 10.0.0.0/8"
            value={r.address}
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
