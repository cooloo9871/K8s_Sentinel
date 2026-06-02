import { useEffect, useState } from 'react'
import {
  CTable,
  CTableHead,
  CTableBody,
  CTableRow,
  CTableHeaderCell,
  CTableDataCell,
  CSpinner,
  CCard,
  CCardBody,
} from '@coreui/react'
import { namespaceApi, policyApi } from '../api/client'
import { useToast } from '../layout/AppToaster'
import type { PolicyRecord } from '../api/types'

export function NamespacesPage() {
  const toast = useToast()
  const [namespaces, setNamespaces] = useState<string[]>([])
  const [policies, setPolicies] = useState<PolicyRecord[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([namespaceApi.list(), policyApi.list()])
      .then(([ns, p]) => {
        setNamespaces(ns)
        setPolicies(p)
      })
      .catch(() => toast.error('Failed to load namespaces'))
      .finally(() => setLoading(false))
  }, [])

  const policyCountByNs = (ns: string) =>
    policies.filter((p) => p.namespace === ns).length

  return (
    <>
      <h4 className="mb-3" style={{ color: '#1b2a3b', fontWeight: 600 }}>Namespaces</h4>

      <CCard>
        <CCardBody className="p-0">
          {loading ? (
            <div className="d-flex justify-content-center py-5">
              <CSpinner color="primary" />
            </div>
          ) : (
            <CTable hover responsive className="mb-0">
              <CTableHead>
                <CTableRow style={{ background: '#f8f9fa' }}>
                  <CTableHeaderCell>Namespace</CTableHeaderCell>
                  <CTableHeaderCell className="text-center">Policies</CTableHeaderCell>
                </CTableRow>
              </CTableHead>
              <CTableBody>
                {namespaces.length === 0 ? (
                  <CTableRow>
                    <CTableDataCell colSpan={2} className="text-center text-muted py-4">
                      No namespaces found
                    </CTableDataCell>
                  </CTableRow>
                ) : (
                  namespaces.map((ns) => (
                    <CTableRow key={ns}>
                      <CTableDataCell style={{ fontWeight: 500 }}>{ns}</CTableDataCell>
                      <CTableDataCell className="text-center">{policyCountByNs(ns)}</CTableDataCell>
                    </CTableRow>
                  ))
                )}
              </CTableBody>
            </CTable>
          )}
        </CCardBody>
      </CCard>
    </>
  )
}
