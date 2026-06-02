import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  CTable,
  CTableHead,
  CTableBody,
  CTableRow,
  CTableHeaderCell,
  CTableDataCell,
  CBadge,
  CButton,
  CFormInput,
  CFormSelect,
  CModal,
  CModalHeader,
  CModalTitle,
  CModalBody,
  CModalFooter,
  CSpinner,
  CCard,
  CCardBody,
} from '@coreui/react'
import { policyApi } from '../api/client'
import { useToast } from '../layout/AppToaster'
import type { PolicyRecord } from '../api/types'

export function PolicyListPage() {
  const navigate = useNavigate()
  const toast = useToast()
  const [policies, setPolicies] = useState<PolicyRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [scopeFilter, setScopeFilter] = useState('all')
  const [deleteTarget, setDeleteTarget] = useState<PolicyRecord | null>(null)
  const [deleting, setDeleting] = useState(false)

  const fetchPolicies = async () => {
    setLoading(true)
    try {
      setPolicies(await policyApi.list())
    } catch {
      toast.error('Failed to load policies')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchPolicies() }, [])

  const handleDelete = async () => {
    if (!deleteTarget) return
    setDeleting(true)
    try {
      await policyApi.delete(deleteTarget.name, deleteTarget.namespace)
      toast.success('Policy deleted')
      setDeleteTarget(null)
      fetchPolicies()
    } catch {
      toast.error('Failed to delete policy')
    } finally {
      setDeleting(false)
    }
  }

  const filtered = policies.filter((p) => {
    const matchName = p.name.toLowerCase().includes(search.toLowerCase())
    const matchScope = scopeFilter === 'all' || p.scope === scopeFilter
    return matchName && matchScope
  })

  return (
    <>
      <div className="d-flex justify-content-between align-items-center mb-3">
        <div>
          <h4 className="mb-0" style={{ color: '#1b2a3b', fontWeight: 600 }}>TracingPolicy</h4>
          <div className="text-muted" style={{ fontSize: '0.75rem' }}>Cilium 追蹤策略管理</div>
        </div>
        <CButton color="primary" onClick={() => navigate('/policies/tracing/new')}>
          + New Policy
        </CButton>
      </div>

      <CCard>
        <CCardBody className="p-0">
          <div className="d-flex align-items-center gap-2 px-3 py-2" style={{ borderBottom: '1px solid #dee2e6' }}>
            <CFormInput
              placeholder="搜尋 Policy 名稱…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{ width: 220 }}
              size="sm"
            />
            <CFormSelect
              value={scopeFilter}
              onChange={(e) => setScopeFilter(e.target.value)}
              style={{ width: 140 }}
              size="sm"
            >
              <option value="all">所有 Scope</option>
              <option value="namespaced">namespace</option>
              <option value="cluster">cluster</option>
            </CFormSelect>
            <span className="ms-auto text-muted" style={{ fontSize: '0.75rem' }}>共 {filtered.length} 筆</span>
          </div>

          {loading ? (
            <div className="d-flex justify-content-center py-5">
              <CSpinner color="primary" />
            </div>
          ) : (
            <CTable hover responsive className="mb-0">
              <CTableHead>
                <CTableRow style={{ background: '#f8f9fa' }}>
                  <CTableHeaderCell>Name</CTableHeaderCell>
                  <CTableHeaderCell>Scope</CTableHeaderCell>
                  <CTableHeaderCell>Namespace</CTableHeaderCell>
                  <CTableHeaderCell>Created</CTableHeaderCell>
                  <CTableHeaderCell className="text-center">Actions</CTableHeaderCell>
                </CTableRow>
              </CTableHead>
              <CTableBody>
                {filtered.length === 0 ? (
                  <CTableRow>
                    <CTableDataCell colSpan={5} className="text-center text-muted py-4">
                      No policies found
                    </CTableDataCell>
                  </CTableRow>
                ) : (
                  filtered.map((p) => (
                    <CTableRow key={`${p.scope}-${p.namespace ?? ''}-${p.name}`}>
                      <CTableDataCell
                        style={{ color: '#2d7dd2', fontWeight: 500, cursor: 'pointer' }}
                        onClick={() => navigate(`/policies/tracing/${p.name}/edit?namespace=${p.namespace ?? ''}`)}
                      >
                        {p.name}
                      </CTableDataCell>
                      <CTableDataCell>
                        <CBadge color={p.scope === 'cluster' ? 'danger' : 'primary'}>{p.scope}</CBadge>
                      </CTableDataCell>
                      <CTableDataCell className="text-muted">{p.namespace ?? '—'}</CTableDataCell>
                      <CTableDataCell className="text-muted">{p.createdAt}</CTableDataCell>
                      <CTableDataCell className="text-center">
                        <CButton
                          color="primary" variant="outline" size="sm" className="me-1"
                          onClick={() => navigate(`/policies/tracing/${p.name}/edit?namespace=${p.namespace ?? ''}`)}
                        >
                          Edit
                        </CButton>
                        <CButton color="danger" variant="outline" size="sm" onClick={() => setDeleteTarget(p)}>
                          Delete
                        </CButton>
                      </CTableDataCell>
                    </CTableRow>
                  ))
                )}
              </CTableBody>
            </CTable>
          )}
        </CCardBody>
      </CCard>

      <CModal visible={!!deleteTarget} onClose={() => setDeleteTarget(null)}>
        <CModalHeader>
          <CModalTitle>刪除 Policy</CModalTitle>
        </CModalHeader>
        <CModalBody>
          確定要刪除 <strong>{deleteTarget?.name}</strong> 嗎？此操作無法復原。
        </CModalBody>
        <CModalFooter>
          <CButton color="secondary" variant="outline" onClick={() => setDeleteTarget(null)}>取消</CButton>
          <CButton color="danger" onClick={handleDelete} disabled={deleting}>
            {deleting ? '刪除中…' : '確認刪除'}
          </CButton>
        </CModalFooter>
      </CModal>
    </>
  )
}
