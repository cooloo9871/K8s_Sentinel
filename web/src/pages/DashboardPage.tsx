import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  CRow,
  CCol,
  CCard,
  CCardHeader,
  CCardBody,
  CTable,
  CTableHead,
  CTableBody,
  CTableRow,
  CTableHeaderCell,
  CTableDataCell,
  CBadge,
  CButton,
  CSpinner,
  CModal,
  CModalHeader,
  CModalTitle,
  CModalBody,
  CModalFooter,
} from '@coreui/react'
import { policyApi, modeApi, namespaceApi } from '../api/client'
import { useToast } from '../layout/AppToaster'
import { StatCard } from '../components/StatCard'
import type { PolicyRecord, Mode } from '../api/types'

export function DashboardPage() {
  const navigate = useNavigate()
  const toast = useToast()
  const [policies, setPolicies] = useState<PolicyRecord[]>([])
  const [mode, setMode] = useState<Mode>('Monitoring')
  const [namespaceCount, setNamespaceCount] = useState(0)
  const [loading, setLoading] = useState(true)
  const [switchModal, setSwitchModal] = useState(false)
  const [switching, setSwitching] = useState(false)

  useEffect(() => {
    Promise.all([policyApi.list(), modeApi.get(), namespaceApi.list()])
      .then(([p, m, ns]) => {
        setPolicies(p)
        setMode(m)
        setNamespaceCount(ns.length)
      })
      .catch(() => toast.error('Failed to load dashboard'))
      .finally(() => setLoading(false))
  }, [])

  const handleModeSwitch = async () => {
    const next: 'Monitoring' | 'Protect' = mode === 'Protect' ? 'Monitoring' : 'Protect'
    setSwitching(true)
    try {
      await modeApi.set(next)
      setMode(next)
      toast.success(`Mode switched to ${next}`)
    } catch {
      toast.error('Failed to switch mode')
    } finally {
      setSwitching(false)
      setSwitchModal(false)
    }
  }

  const clusterCount = policies.filter((p) => p.scope === 'cluster').length
  const recent = policies.slice(0, 5)
  const modeColor = mode === 'Protect' ? '#dc3545' : mode === 'Mixed' ? '#fd7e14' : '#28a745'
  const nextMode: 'Monitoring' | 'Protect' = mode === 'Protect' ? 'Monitoring' : 'Protect'

  if (loading) {
    return (
      <div className="d-flex justify-content-center py-5">
        <CSpinner color="primary" />
      </div>
    )
  }

  return (
    <>
      <h4 className="mb-4" style={{ color: '#1b2a3b', fontWeight: 600 }}>
        Dashboard
      </h4>

      <CRow className="mb-4 g-3">
        <CCol sm={6} xl={3}>
          <StatCard title="Total Policies" value={policies.length} subtitle="TracingPolicy" borderColor="#2d7dd2" />
        </CCol>
        <CCol sm={6} xl={3}>
          <StatCard
            title="Current Mode"
            value={mode.toUpperCase()}
            subtitle={mode === 'Protect' ? '攔截違規行為' : '觀測模式，不攔截'}
            borderColor={modeColor}
          />
        </CCol>
        <CCol sm={6} xl={3}>
          <StatCard title="Namespaces" value={namespaceCount} subtitle="已列管的命名空間" borderColor="#28a745" />
        </CCol>
        <CCol sm={6} xl={3}>
          <StatCard title="Cluster-scoped" value={clusterCount} subtitle="跨命名空間 Policy" borderColor="#dc3545" />
        </CCol>
      </CRow>

      <CRow className="g-3">
        <CCol xl={8}>
          <CCard>
            <CCardHeader className="d-flex justify-content-between align-items-center">
              <strong>Recent Policies</strong>
              <CButton color="link" size="sm" onClick={() => navigate('/policies/tracing')}>
                View All →
              </CButton>
            </CCardHeader>
            <CCardBody className="p-0">
              <CTable hover responsive className="mb-0">
                <CTableHead>
                  <CTableRow style={{ background: '#f8f9fa' }}>
                    <CTableHeaderCell>Name</CTableHeaderCell>
                    <CTableHeaderCell>Scope</CTableHeaderCell>
                    <CTableHeaderCell>Namespace</CTableHeaderCell>
                    <CTableHeaderCell>Created</CTableHeaderCell>
                  </CTableRow>
                </CTableHead>
                <CTableBody>
                  {recent.length === 0 ? (
                    <CTableRow>
                      <CTableDataCell colSpan={4} className="text-center text-muted py-4">
                        No policies yet
                      </CTableDataCell>
                    </CTableRow>
                  ) : (
                    recent.map((p) => (
                      <CTableRow
                        key={`${p.scope}-${p.namespace ?? ''}-${p.name}`}
                        style={{ cursor: 'pointer' }}
                        onClick={() =>
                          navigate(`/policies/tracing/${p.name}/edit?namespace=${p.namespace ?? ''}`)
                        }
                      >
                        <CTableDataCell style={{ color: '#2d7dd2', fontWeight: 500 }}>
                          {p.name}
                        </CTableDataCell>
                        <CTableDataCell>
                          <CBadge color={p.scope === 'cluster' ? 'danger' : 'primary'}>{p.scope}</CBadge>
                        </CTableDataCell>
                        <CTableDataCell className="text-muted">{p.namespace ?? '—'}</CTableDataCell>
                        <CTableDataCell className="text-muted">{p.createdAt}</CTableDataCell>
                      </CTableRow>
                    ))
                  )}
                </CTableBody>
              </CTable>
            </CCardBody>
          </CCard>
        </CCol>

        <CCol xl={4}>
          <CCard>
            <CCardHeader><strong>Enforcement Mode</strong></CCardHeader>
            <CCardBody className="text-center">
              <div
                style={{ border: `2px solid ${modeColor}`, borderRadius: 6, padding: '0.75rem', marginBottom: '0.75rem' }}
              >
                <div className="text-muted mb-1" style={{ fontSize: '0.7rem' }}>目前模式</div>
                <div style={{ fontWeight: 700, color: modeColor, fontSize: '1.1rem' }}>{mode.toUpperCase()}</div>
              </div>
              <CButton
                color={nextMode === 'Protect' ? 'danger' : 'success'}
                variant="outline"
                size="sm"
                className="w-100"
                onClick={() => setSwitchModal(true)}
              >
                切換至 {nextMode.toUpperCase()}
              </CButton>
              {nextMode === 'Protect' && (
                <p className="text-danger mt-2 mb-0" style={{ fontSize: '0.7rem' }}>
                  ⚠ 啟用後將攔截違規行為
                </p>
              )}
            </CCardBody>
          </CCard>
        </CCol>
      </CRow>

      <CModal visible={switchModal} onClose={() => setSwitchModal(false)}>
        <CModalHeader>
          <CModalTitle>切換模式</CModalTitle>
        </CModalHeader>
        <CModalBody>
          確定要將模式切換為 <strong>{nextMode.toUpperCase()}</strong> 嗎？
          {nextMode === 'Protect' && (
            <p className="text-danger mt-2 mb-0">警告：Protect 模式將攔截違規行為。</p>
          )}
        </CModalBody>
        <CModalFooter>
          <CButton color="secondary" variant="outline" onClick={() => setSwitchModal(false)}>取消</CButton>
          <CButton color={nextMode === 'Protect' ? 'danger' : 'success'} onClick={handleModeSwitch} disabled={switching}>
            {switching ? '切換中…' : `切換至 ${nextMode}`}
          </CButton>
        </CModalFooter>
      </CModal>
    </>
  )
}
