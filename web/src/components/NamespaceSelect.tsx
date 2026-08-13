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
  value, onChange, namespaces, noneLabel, clearLabel, disabled, className,
}: {
  /** The chosen namespace. Empty means the noneLabel or clearLabel option. */
  value: string
  onChange: (v: string) => void
  namespaces: string[]
  /**
   * Adds an option meaning "no namespace", and shows it in the field as the
   * choice it is — cluster-wide, or every namespace. Omit to require a real one.
   */
  noneLabel?: string
  /**
   * Adds an option that clears the field back to the placeholder. For a field
   * where unset is the starting state rather than a decision: showing what unset
   * would fall back to reads as though the field were already filled in.
   */
  clearLabel?: string
  disabled?: boolean
  className?: string
}) {
  const noneOption = noneLabel ?? clearLabel
  // A cluster always has namespaces, so an empty list means the lookup failed.
  // Left unsaid, the picker is simply empty and there is no way to tell why —
  // and for a required namespace, no way to continue either.
  if (namespaces.length === 0 && !noneOption) {
    return (
      <div className="flex flex-col gap-1">
        <Select value="" disabled>
          <SelectTrigger className={className ?? 'h-9 w-full'}>
            <SelectValue placeholder="No namespaces available" />
          </SelectTrigger>
          <SelectContent />
        </Select>
        <p className="text-[11px] text-destructive">
          The cluster namespace list could not be loaded.
        </p>
      </div>
    )
  }

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
          {noneOption && <SelectItem value={NONE}>{noneOption}</SelectItem>}
          {namespaces.map(ns => (
            <SelectItem key={ns} value={ns}>{ns}</SelectItem>
          ))}
        </SelectGroup>
      </SelectContent>
    </Select>
  )
}
