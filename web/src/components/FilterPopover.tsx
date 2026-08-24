import { IconAdjustmentsHorizontal } from '@tabler/icons-react'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'

// Security Events and Admission Events each had their filters spread across two
// or three separate dropdowns in the toolbar, each holding one choice at a time.
// This gathers them into one panel of checkbox groups, the way Network Topology
// already works, and it is shared so the two cannot drift apart.

export type FilterSection = {
  /** Heading above the group. */
  label: string
  options: { key: string; label: string }[]
  /** Selected keys. Empty means no filter — see matchesFilter. */
  value: string[]
  onChange: (v: string[]) => void
}

/**
 * Whether a value passes one section's filter. An empty selection is the absence
 * of a filter, not a value to match — the same rule the namespace filter uses,
 * so "nothing ticked" means "everything" everywhere.
 */
export function matchesFilter(selected: string[], value: string | null): boolean {
  return selected.length === 0 || (value !== null && selected.includes(value))
}

export function FilterPopover({ sections, label = 'Filter' }: {
  sections: FilterSection[]
  label?: string
}) {
  const active = sections.reduce((n, s) => n + s.value.length, 0)

  const toggle = (s: FilterSection, key: string) =>
    s.onChange(s.value.includes(key) ? s.value.filter(v => v !== key) : [...s.value, key])

  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" className="h-8 text-sm font-normal">
          <IconAdjustmentsHorizontal size={14} className="mr-1.5" />
          {label}
          {active > 0 && <span className="ml-1.5 size-1.5 rounded-full bg-primary" />}
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-56 p-1">
        {sections.map((s, i) => (
          <div key={s.label} className={i > 0 ? 'mt-1 border-t pt-1' : undefined}>
            <p className="px-2 py-1 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
              {s.label}
            </p>
            {s.options.map(o => (
              <label
                key={o.key}
                className="flex cursor-pointer select-none items-center gap-2 rounded-sm px-2 py-1.5 text-sm hover:bg-accent"
              >
                <Checkbox
                  checked={s.value.includes(o.key)}
                  onCheckedChange={() => toggle(s, o.key)}
                  className="size-3.5"
                />
                {o.label}
              </label>
            ))}
          </div>
        ))}
        {active > 0 && (
          <div className="mt-1 border-t p-1">
            <Button
              variant="ghost"
              size="sm"
              className="h-7 w-full text-xs"
              onClick={() => sections.forEach(s => s.onChange([]))}
            >
              Clear
            </Button>
          </div>
        )}
      </PopoverContent>
    </Popover>
  )
}
