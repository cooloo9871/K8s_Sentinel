import { CFormInput, CFormSelect, CButton } from '@coreui/react'
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
    <div className="mb-3">
      {rules.map((r, i) => (
        <div key={i} className="d-flex align-items-center gap-2 mb-2">
          <CFormSelect
            value={r.protocol}
            onChange={(e) => update(i, { protocol: e.target.value as NetworkRule['protocol'] })}
            size="sm"
            style={{ width: 80, flexShrink: 0 }}
          >
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
          </CFormSelect>
          <CFormInput
            placeholder="10.0.0.0/8"
            value={r.cidr}
            onChange={(e) => update(i, { cidr: e.target.value })}
            size="sm"
            style={{ flex: 2 }}
          />
          <CFormInput
            placeholder="Port"
            value={r.port}
            onChange={(e) => update(i, { port: e.target.value })}
            size="sm"
            style={{ width: 80, flexShrink: 0 }}
            type="number"
            min={1}
            max={65535}
          />
          <CButton color="danger" variant="ghost" size="sm" onClick={() => remove(i)}>✕</CButton>
        </div>
      ))}
      <CButton color="primary" variant="outline" size="sm" onClick={add}>+ Add</CButton>
    </div>
  )
}
