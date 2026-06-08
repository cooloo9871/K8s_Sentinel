import { useEffect, useState } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { policyApi, namespaceApi } from '../api/client'
import { useToast } from '../layout/AppToaster'
import { PolicyForm } from '../components/PolicyForm/PolicyForm'
import { YamlEditor } from '../components/YamlEditor'
import { formToYaml } from '../utils/formToYaml'
import { yamlToForm } from '../utils/yamlToForm'
import type { PolicyFormInput } from '../api/types'

const EMPTY_FORM: PolicyFormInput = {
  name: '',
  namespace: 'default',
  process: [],
  file: [],
}

export function PolicyEditPage() {
  const { name } = useParams<{ name: string }>()
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const toast = useToast()
  const namespace = searchParams.get('namespace') || undefined
  const isNew = !name

  const [namespaces, setNamespaces] = useState<string[]>([])
  const [policyMode, setPolicyMode] = useState<'Monitoring' | 'Protect'>('Monitoring')
  const [formValues, setFormValues] = useState<PolicyFormInput>(EMPTY_FORM)
  const [yamlContent, setYamlContent] = useState('')
  const [yamlEditorKey, setYamlEditorKey] = useState(0)
  const [yamlValid, setYamlValid] = useState(true)
  const [activeTab, setActiveTab] = useState('form')
  const [loading, setLoading] = useState(false)
  const [pageLoading, setPageLoading] = useState(!isNew)

  const action = policyMode === 'Protect' ? 'Sigkill' : 'Post'

  useEffect(() => {
    const work: Promise<void>[] = [namespaceApi.list().then(setNamespaces)]
    if (!isNew && name) {
      work.push(
        policyApi.get(name, namespace).then((r) => {
          setYamlContent(r.rawYaml)
          setPolicyMode(r.mode === 'Protect' ? 'Protect' : 'Monitoring')
          // Pre-populate form from existing policy YAML
          const parsed = yamlToForm(r.rawYaml)
          if (parsed) setFormValues(parsed)
        })
      )
    }
    Promise.all(work).finally(() => setPageLoading(false))
  }, [name, namespace, isNew])

  const handleTabChange = (tab: string) => {
    if (tab === 'yaml' && activeTab === 'form' && formValues.name.trim()) {
      // Form → YAML: regenerate YAML from current form state
      try {
        const generated = formToYaml(formValues, action)
        setYamlContent(generated)
        setYamlValid(true)
        setYamlEditorKey((k) => k + 1)
      } catch {
        setYamlEditorKey((k) => k + 1)
      }
    } else if (tab === 'form' && activeTab === 'yaml' && yamlValid) {
      // YAML → Form: back-parse current YAML into form so Form-tab saves
      // reflect the user's YAML edits rather than the stale pre-YAML form state.
      const parsed = yamlToForm(yamlContent)
      if (parsed) {
        setFormValues(parsed)
        if (parsed.namespace !== undefined) {
          setPolicyMode(
            yamlContent.toLowerCase().includes('sigkill') ? 'Protect' : 'Monitoring'
          )
        }
      }
    }
    setActiveTab(tab)
  }

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
        const payload = { source: 'yaml' as const, rawYaml: yamlContent }
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
      <div className="flex flex-col gap-4">
        <Skeleton className="h-10 w-64" />
        <Skeleton className="h-[600px] w-full rounded-xl" />
      </div>
    )
  }

  return (
    <>
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h4 className="text-lg font-semibold">
            {isNew ? 'New Policy' : 'Edit Policy'}
          </h4>
          {!isNew && (
            <p className="text-sm text-muted-foreground">{name}</p>
          )}
        </div>
        <div className="flex items-center gap-3">
          {/* Per-policy mode selector */}
          <div className="flex items-center gap-2">
            <Label className="text-sm text-muted-foreground">Mode</Label>
            <Select
              value={policyMode}
              onValueChange={(v) => setPolicyMode(v as 'Monitoring' | 'Protect')}
            >
              <SelectTrigger className="h-9 w-36">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value="Monitoring">Monitoring</SelectItem>
                  <SelectItem value="Protect">Protect</SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>
          </div>
          <Button variant="outline" onClick={() => navigate('/policies/tracing')}>
            Cancel
          </Button>
          <Button onClick={handleSave} disabled={loading}>
            {loading ? 'Saving...' : 'Save Changes'}
          </Button>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={handleTabChange}>
        <TabsList variant="line" className="mb-4 w-full justify-start rounded-none border-b bg-transparent p-0">
          <TabsTrigger
            value="form"
            className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent data-[state=active]:shadow-none"
          >
            Form
          </TabsTrigger>
          <TabsTrigger
            value="yaml"
            className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent data-[state=active]:shadow-none"
          >
            YAML
          </TabsTrigger>
        </TabsList>
        <TabsContent value="form">
          <PolicyForm
            namespaces={namespaces}
            action={action}
            value={formValues}
            onChange={setFormValues}
          />
        </TabsContent>
        <TabsContent value="yaml">
          <YamlEditor
            key={yamlEditorKey}
            initialValue={yamlContent}
            onValueChange={(v, valid) => {
              setYamlContent(v)
              setYamlValid(valid)
            }}
          />
        </TabsContent>
      </Tabs>
    </>
  )
}
