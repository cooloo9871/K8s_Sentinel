import { useMemo } from 'react'
import {
  CCard,
  CCardHeader,
  CCardBody,
  CFormInput,
  CFormLabel,
  CFormSelect,
  CRow,
  CCol,
} from '@coreui/react'
import { ProcessSection } from './ProcessSection'
import { FileSection } from './FileSection'
import { NetworkSection } from './NetworkSection'
import { formToYaml } from '../../utils/formToYaml'
import type { PolicyFormInput, FileRule, NetworkRule } from '../../api/types'

type FileEntry = { path: string; operation: FileRule['operation'] }
type NetEntry = { protocol: NetworkRule['protocol']; cidr: string; port: string }

interface Props {
  namespaces: string[]
  action: string
  value: PolicyFormInput
  onChange: (v: PolicyFormInput) => void
}

export function PolicyForm({ namespaces, action, value, onChange }: Props) {
  const yamlPreview = useMemo(() => {
    if (!value.name) return ''
    try {
      return formToYaml(value, action)
    } catch {
      return ''
    }
  }, [value, action])

  const processBinaries = value.process?.map((p) => p.binaries[0] ?? '') ?? []
  const fileEntries: FileEntry[] =
    value.file?.map((f) => ({ path: f.paths[0] ?? '', operation: f.operation })) ?? []
  const netEntries: NetEntry[] =
    value.network?.map((n) => ({
      protocol: n.protocol,
      cidr: n.cidr,
      port: n.port?.toString() ?? '',
    })) ?? []

  const setProcessBinaries = (binaries: string[]) =>
    onChange({ ...value, process: binaries.map((b) => ({ binaries: [b] })) })

  const setFileEntries = (entries: FileEntry[]) =>
    onChange({
      ...value,
      file: entries.map((e) => ({ paths: [e.path], operation: e.operation })),
    })

  const setNetEntries = (entries: NetEntry[]) =>
    onChange({
      ...value,
      network: entries.map((e) => ({
        protocol: e.protocol,
        cidr: e.cidr,
        port: e.port ? parseInt(e.port, 10) : undefined,
      })),
    })

  return (
    <CRow className="g-3">
      <CCol lg={8}>
        <CCard className="mb-3">
          <CCardHeader>
            <strong style={{ fontSize: '0.85rem' }}>Basic Information</strong>
          </CCardHeader>
          <CCardBody>
            <CRow className="g-3">
              <CCol md={6}>
                <CFormLabel>Policy Name <span className="text-danger">*</span></CFormLabel>
                <CFormInput
                  placeholder="my-policy"
                  value={value.name}
                  onChange={(e) => onChange({ ...value, name: e.target.value })}
                />
              </CCol>
              <CCol md={6}>
                <CFormLabel>Namespace</CFormLabel>
                <CFormSelect
                  value={value.namespace ?? ''}
                  onChange={(e) => onChange({ ...value, namespace: e.target.value || undefined })}
                >
                  <option value="">cluster-wide</option>
                  {namespaces.map((n) => (
                    <option key={n} value={n}>{n}</option>
                  ))}
                </CFormSelect>
              </CCol>
            </CRow>
          </CCardBody>
        </CCard>

        <CCard className="mb-3">
          <CCardHeader>
            <strong style={{ fontSize: '0.85rem' }}>Process Rules</strong>
          </CCardHeader>
          <CCardBody>
            <ProcessSection binaries={processBinaries} onChange={setProcessBinaries} />
          </CCardBody>
        </CCard>

        <CCard className="mb-3">
          <CCardHeader>
            <strong style={{ fontSize: '0.85rem' }}>File Rules</strong>
          </CCardHeader>
          <CCardBody>
            <FileSection rules={fileEntries} onChange={setFileEntries} />
          </CCardBody>
        </CCard>

        <CCard>
          <CCardHeader>
            <strong style={{ fontSize: '0.85rem' }}>Network Rules</strong>
          </CCardHeader>
          <CCardBody>
            <NetworkSection rules={netEntries} onChange={setNetEntries} />
          </CCardBody>
        </CCard>
      </CCol>

      <CCol lg={4}>
        <div style={{ position: 'sticky', top: '5rem' }}>
          <div style={{ background: '#1e1e1e', borderRadius: 6, overflow: 'hidden' }}>
            <div
              style={{
                padding: '0.5rem 0.85rem',
                background: '#252526',
                borderBottom: '1px solid #3c3c3c',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <span style={{ fontSize: '0.75rem', color: '#9cdcfe', fontFamily: 'monospace' }}>
                YAML Preview
              </span>
              <span
                style={{
                  fontSize: '0.65rem',
                  color: yamlPreview ? '#4ec94e' : '#6c757d',
                  background: yamlPreview ? '#1a3a1a' : '#2a2a2a',
                  padding: '1px 6px',
                  borderRadius: 3,
                }}
              >
                {yamlPreview ? '✓ valid' : '—'}
              </span>
            </div>
            <pre
              style={{
                margin: 0,
                padding: '0.75rem',
                fontFamily: 'monospace',
                fontSize: '0.7rem',
                lineHeight: 1.6,
                color: '#d4d4d4',
                minHeight: 200,
                maxHeight: 500,
                overflow: 'auto',
                whiteSpace: 'pre-wrap',
              }}
            >
              {yamlPreview || (
                <span style={{ color: '#555' }}>Enter a policy name to preview…</span>
              )}
            </pre>
          </div>
        </div>
      </CCol>
    </CRow>
  )
}
