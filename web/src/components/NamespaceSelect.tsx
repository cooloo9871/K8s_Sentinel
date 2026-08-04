import {
  Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'

// Picking a namespace from the cluster rather than typing one, which is the
// difference between a policy that lands where you meant and one that silently
// governs nothing. Shared by every form that asks for a namespace so the three
// do not drift.

// Stands in for "no namespace" — cluster-wide, or every namespace, depending on
// the form. Not '' because Radix reserves the empty string, and not a real word
// because a namespace could be called it; underscores cannot appear in a
// namespace name, so this cannot collide.
const NONE = '__none__'

export function NamespaceSelect({
  value, onChange, namespaces, noneLabel, disabled, className,
}: {
  /** The chosen namespace. Empty means the noneLabel option. */
  value: string
  onChange: (v: string) => void
  namespaces: string[]
  /** Adds an option meaning "no namespace". Omit to require a real one. */
  noneLabel?: string
  disabled?: boolean
  className?: string
}) {
  return (
    <Select
      value={value || (noneLabel ? NONE : '')}
      onValueChange={v => onChange(v === NONE ? '' : v)}
      disabled={disabled}
    >
      <SelectTrigger className={className ?? 'h-9 w-full'}>
        <SelectValue placeholder="Select a namespace" />
      </SelectTrigger>
      <SelectContent>
        <SelectGroup>
          {noneLabel && <SelectItem value={NONE}>{noneLabel}</SelectItem>}
          {namespaces.map(ns => (
            <SelectItem key={ns} value={ns}>{ns}</SelectItem>
          ))}
        </SelectGroup>
      </SelectContent>
    </Select>
  )
}
