import { useEffect, useState } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import {
  CTabs,
  CTabList,
  CTab,
  CTabContent,
  CTabPanel,
  CButton,
  CSpinner,
} from '@coreui/react'
import { policyApi, namespaceApi, modeApi } from '../api/client'
import { useToast } from '../layout/AppToaster'
import { PolicyForm } from '../components/PolicyForm/PolicyForm'
import { YamlEditor } from '../components/YamlEditor'
import type { PolicyFormInput, Mode } from '../api/types'

const EMPTY_FORM: PolicyFormInput = {
  name: '',
  namespace: undefined,
  process: [],
  file: [],
  network: [],
}

export function PolicyEditPage() {
  const { name } = useParams<{ name: string }>()
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const toast = useToast()
  const namespace = searchParams.get('namespace') || undefined
  const isNew = !name

  const [namespaces, setNamespaces] = useState<string[]>([])
  const [mode, setMode] = useState<Mode>('Monitoring')
  const [initialYaml, setInitialYaml] = useState('')
  const [formValues, setFormValues] = useState<PolicyFormInput>(EMPTY_FORM)
  const [yamlValue, setYamlValue] = useState('')
  const [yamlValid, setYamlValid] = useState(true)
  const [activeTab, setActiveTab] = useState<string>('form')
  const [loading, setLoading] = useState(false)
  const [pageLoading, setPageLoading] = useState(!isNew)

  useEffect(() => {
    const work: Promise<void>[] = [
      namespaceApi.list().then(setNamespaces),
      modeApi.get().then(setMode),
    ]
    if (!isNew && name) {
      work.push(
        policyApi.get(name, namespace).then((r) => {
          setInitialYaml(r.rawYaml)
          setYamlValue(r.rawYaml)
        })
      )
    }
    Promise.all(work).finally(() => setPageLoading(false))
  }, [name, namespace, isNew])

  const action = mode === 'Protect' ? 'Sigkill' : 'Post'

  const handleSave = async () => {
    if (activeTab === 'form') {
      if (!formValues.name.trim()) {
        toast.error('Policy name is required')
        return
      }
      setLoading(true)
      try {
        const payload = { source: 'form' as const, form: formValues, action }
        if (isNew) await policyApi.create(payload)
        else await policyApi.update(name!, payload)
        toast.success('Policy applied')
        navigate('/policies/tracing')
      } catch {
        toast.error('Failed to apply policy')
      } finally {
        setLoading(false)
      }
    } else {
      if (!yamlValid) {
        toast.error('Fix YAML errors before saving')
        return
      }
      setLoading(true)
      try {
        const payload = { source: 'yaml' as const, rawYaml: yamlValue }
        if (isNew) await policyApi.create(payload)
        else await policyApi.update(name!, payload)
        toast.success('Policy applied')
        navigate('/policies/tracing')
      } catch {
        toast.error('Failed to apply YAML')
      } finally {
        setLoading(false)
      }
    }
  }

  if (pageLoading) {
    return (
      <div className="d-flex justify-content-center py-5">
        <CSpinner color="primary" />
      </div>
    )
  }

  return (
    <>
      <div className="d-flex justify-content-between align-items-start mb-3">
        <div>
          <h4 className="mb-0" style={{ color: '#1b2a3b', fontWeight: 600 }}>
            {isNew ? 'New Policy' : 'Edit Policy'}
          </h4>
          {!isNew && (
            <div className="text-muted" style={{ fontSize: '0.75rem' }}>{name}</div>
          )}
        </div>
        <div className="d-flex gap-2">
          <CButton color="secondary" variant="outline" onClick={() => navigate('/policies/tracing')}>
            Cancel
          </CButton>
          <CButton color="primary" onClick={handleSave} disabled={loading}>
            {loading ? 'Saving…' : 'Save Changes'}
          </CButton>
        </div>
      </div>

      <CTabs activeItemKey={activeTab}>
        <CTabList variant="underline-border" className="mb-3">
          <CTab itemKey="form" onClick={() => setActiveTab('form')}>Form</CTab>
          <CTab itemKey="yaml" onClick={() => setActiveTab('yaml')}>YAML</CTab>
        </CTabList>
        <CTabContent>
          <CTabPanel itemKey="form">
            <PolicyForm
              namespaces={namespaces}
              action={action}
              value={formValues}
              onChange={setFormValues}
            />
          </CTabPanel>
          <CTabPanel itemKey="yaml">
            <YamlEditor
              initialValue={initialYaml}
              onValueChange={(v, valid) => {
                setYamlValue(v)
                setYamlValid(valid)
              }}
            />
          </CTabPanel>
        </CTabContent>
      </CTabs>
    </>
  )
}
