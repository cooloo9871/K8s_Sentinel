import { useEffect, useState } from 'react'
import {
  CCard,
  CCardHeader,
  CCardBody,
  CButton,
  CSpinner,
  CModal,
  CModalHeader,
  CModalTitle,
  CModalBody,
  CModalFooter,
  CAlert,
} from '@coreui/react'
import { modeApi } from '../api/client'
import { useToast } from '../layout/AppToaster'
import type { Mode } from '../api/types'

const MODE_DESCRIPTIONS: Record<Mode, string> = {
  Monitoring: '觀測模式：記錄所有行為但不進行攔截，適合初期策略驗證與行為分析。',
  Protect: '保護模式：主動攔截違反策略的行為（Sigkill），適合生產環境強制執行。',
  Mixed: '混合模式：部分策略為 Monitoring，部分為 Protect，切換模式將統一套用。',
}

export function ModePage() {
  const toast = useToast()
  const [mode, setMode] = useState<Mode>('Monitoring')
  const [loading, setLoading] = useState(true)
  const [switchModal, setSwitchModal] = useState(false)
  const [switching, setSwitching] = useState(false)

  useEffect(() => {
    modeApi
      .get()
      .then(setMode)
      .catch(() => toast.error('Failed to load mode'))
      .finally(() => setLoading(false))
  }, [])

  const nextMode: 'Monitoring' | 'Protect' = mode === 'Protect' ? 'Monitoring' : 'Protect'

  const handleSwitch = async () => {
    setSwitching(true)
    try {
      await modeApi.set(nextMode)
      setMode(nextMode)
      toast.success(`Mode switched to ${nextMode}`)
    } catch {
      toast.error('Failed to switch mode')
    } finally {
      setSwitching(false)
      setSwitchModal(false)
    }
  }

  const modeColor = mode === 'Protect' ? '#dc3545' : mode === 'Mixed' ? '#fd7e14' : '#28a745'

  if (loading) {
    return (
      <div className="d-flex justify-content-center py-5">
        <CSpinner color="primary" />
      </div>
    )
  }

  return (
    <>
      <h4 className="mb-4" style={{ color: '#1b2a3b', fontWeight: 600 }}>Mode Control</h4>

      <CCard style={{ maxWidth: 480 }}>
        <CCardHeader><strong>Enforcement Mode</strong></CCardHeader>
        <CCardBody>
          <div
            style={{
              border: `2px solid ${modeColor}`,
              borderRadius: 8,
              padding: '1.25rem',
              textAlign: 'center',
              marginBottom: '1rem',
            }}
          >
            <div className="text-muted mb-1" style={{ fontSize: '0.75rem' }}>目前模式</div>
            <div style={{ fontSize: '1.8rem', fontWeight: 700, color: modeColor }}>
              {mode.toUpperCase()}
            </div>
          </div>

          <p className="text-muted mb-3" style={{ fontSize: '0.85rem' }}>
            {MODE_DESCRIPTIONS[mode]}
          </p>

          {mode === 'Mixed' && (
            <CAlert color="warning" className="mb-3" style={{ fontSize: '0.8rem' }}>
              混合模式：切換後所有 Policy 將統一套用新模式。
            </CAlert>
          )}

          <CButton
            color={nextMode === 'Protect' ? 'danger' : 'success'}
            variant="outline"
            className="w-100"
            onClick={() => setSwitchModal(true)}
          >
            切換至 {nextMode.toUpperCase()}
          </CButton>
        </CCardBody>
      </CCard>

      <CModal visible={switchModal} onClose={() => setSwitchModal(false)}>
        <CModalHeader>
          <CModalTitle>切換執行模式</CModalTitle>
        </CModalHeader>
        <CModalBody>
          確定要將模式從 <strong>{mode.toUpperCase()}</strong> 切換為{' '}
          <strong>{nextMode.toUpperCase()}</strong> 嗎？
          {nextMode === 'Protect' && (
            <p className="text-danger mt-2 mb-0" style={{ fontSize: '0.85rem' }}>
              ⚠ 警告：Protect 模式將主動攔截（Sigkill）違規行為，請確認策略正確後再切換。
            </p>
          )}
        </CModalBody>
        <CModalFooter>
          <CButton color="secondary" variant="outline" onClick={() => setSwitchModal(false)}>取消</CButton>
          <CButton
            color={nextMode === 'Protect' ? 'danger' : 'success'}
            onClick={handleSwitch}
            disabled={switching}
          >
            {switching ? '切換中…' : `切換至 ${nextMode}`}
          </CButton>
        </CModalFooter>
      </CModal>
    </>
  )
}
