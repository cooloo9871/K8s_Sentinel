import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import type { NetworkRule } from '../../api/types'

interface Props {
  rules: NetworkRule[]
  onChange: (rules: NetworkRule[]) => void
}

export function NetworkSection({ rules, onChange }: Props) {
  const update = (i: number, patch: Partial<NetworkRule>) => {
    const next = [...rules]
    next[i] = { ...next[i], ...patch }
    onChange(next)
  }
  const add = () => onChange([...rules, { cidr: '', port: '' }])
  const remove = (i: number) => onChange(rules.filter((_, j) => j !== i))

  return (
    <div className="flex flex-col gap-2">
      {rules.map((r, i) => (
        <div key={i} className="flex items-center gap-2">
          <Input
            placeholder="Destination CIDR (e.g. 192.168.0.0/16)"
            value={r.cidr}
            onChange={(e) => update(i, { cidr: e.target.value })}
            className="h-8 flex-[2] text-sm"
          />
          <Input
            placeholder="Port (e.g. 6379)"
            value={r.port}
            onChange={(e) => update(i, { port: e.target.value })}
            className="h-8 w-28 shrink-0 text-sm"
            type="number"
            min={1}
            max={65535}
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
