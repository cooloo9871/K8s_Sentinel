import { CFormInput, CButton } from '@coreui/react'

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
    <div className="mb-3">
      {binaries.map((b, i) => (
        <div key={i} className="d-flex align-items-center gap-2 mb-2">
          <CFormInput
            placeholder="/usr/bin/nginx"
            value={b}
            onChange={(e) => update(i, e.target.value)}
            size="sm"
          />
          <CButton color="danger" variant="ghost" size="sm" onClick={() => remove(i)} style={{ flexShrink: 0 }}>
            ✕
          </CButton>
        </div>
      ))}
      <CButton color="primary" variant="outline" size="sm" onClick={add}>
        + Add
      </CButton>
    </div>
  )
}
