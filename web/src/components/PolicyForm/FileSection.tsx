import { CFormInput, CFormSelect, CButton } from '@coreui/react'
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
    <div className="mb-3">
      {rules.map((r, i) => (
        <div key={i} className="d-flex align-items-center gap-2 mb-2">
          <CFormInput
            placeholder="/etc/nginx/nginx.conf"
            value={r.path}
            onChange={(e) => update(i, { path: e.target.value })}
            size="sm"
            style={{ flex: 2 }}
          />
          <CFormSelect
            value={r.operation}
            onChange={(e) => update(i, { operation: e.target.value as FileRule['operation'] })}
            size="sm"
            style={{ flex: 1 }}
          >
            <option value="read">read</option>
            <option value="write">write</option>
            <option value="open">open</option>
          </CFormSelect>
          <CButton color="danger" variant="ghost" size="sm" onClick={() => remove(i)}>✕</CButton>
        </div>
      ))}
      <CButton color="primary" variant="outline" size="sm" onClick={add}>+ Add</CButton>
    </div>
  )
}
