import { useState } from 'react'
import { Input } from '@/components/ui/input'

// A text field for a comma-separated list. The text is kept as typed and only
// read as a list on the way out: deriving the text from the list on every
// keystroke swallowed a trailing comma the moment it was typed, so a second
// value could not be entered by hand.
export function CommaListInput({ value, onChange, className, placeholder }: {
  value: string[]
  onChange: (list: string[]) => void
  className?: string
  placeholder?: string
}) {
  const [text, setText] = useState(value.join(', '))
  return (
    <Input className={className} value={text} placeholder={placeholder}
      onChange={e => {
        setText(e.target.value)
        onChange(e.target.value.split(',').map(s => s.trim()).filter(Boolean))
      }} />
  )
}
