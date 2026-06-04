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
import type { NetworkRule } from '../../api/types'

type NetEntry = { protocol: NetworkRule['protocol']; cidr: string; port: string }

interface Props {
  rules: NetEntry[]
  onChange: (rules: NetEntry[]) => void
}

export function NetworkSection({ rules, onChange }: Props) {
  const update = (i: number, patch: Partial<NetEntry>) => {
    const next = [...rules]
    next[i] = { ...next[i], ...patch }
    onChange(next)
  }
  const add = () => onChange([...rules, { protocol: 'TCP', cidr: '', port: '' }])
  const remove = (i: number) => onChange(rules.filter((_, j) => j !== i))

  return (
    <div className="flex flex-col gap-2">
      {rules.map((r, i) => (
        <div key={i} className="flex items-center gap-2">
          <Select
            value={r.protocol}
            onValueChange={(v) => update(i, { protocol: v as NetworkRule['protocol'] })}
          >
            <SelectTrigger className="h-8 w-20 shrink-0 text-sm">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="TCP">TCP</SelectItem>
                <SelectItem value="UDP">UDP</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>
          <Input
            placeholder="10.0.0.0/8"
            value={r.cidr}
            onChange={(e) => update(i, { cidr: e.target.value })}
            className="h-8 flex-[2] text-sm"
          />
          <Input
            placeholder="Port"
            value={r.port}
            onChange={(e) => update(i, { port: e.target.value })}
            className="h-8 w-20 shrink-0 text-sm"
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
