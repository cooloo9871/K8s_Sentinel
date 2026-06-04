import { useEffect, useState } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
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
  const [activeTab, setActiveTab] = useState('form')
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
      <div className="flex flex-col gap-4">
        <Skeleton className="h-10 w-64" />
        <Skeleton className="h-[600px] w-full rounded-xl" />
      </div>
    )
  }

  return (
    <>
      {/* Page header */}
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h4 className="text-lg font-semibold">
            {isNew ? 'New Policy' : 'Edit Policy'}
          </h4>
          {!isNew && (
            <p className="text-sm text-muted-foreground">{name}</p>
          )}
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={() => navigate('/policies/tracing')}
          >
            Cancel
          </Button>
          <Button onClick={handleSave} disabled={loading}>
            {loading ? 'Saving…' : 'Save Changes'}
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
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
            initialValue={initialYaml}
            onValueChange={(v, valid) => {
              setYamlValue(v)
              setYamlValid(valid)
            }}
          />
        </TabsContent>
      </Tabs>
    </>
  )
}
