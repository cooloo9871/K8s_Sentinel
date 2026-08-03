import { useEffect, useState } from 'react'
import { useNavigate, useParams, useSearchParams, useLocation } from 'react-router-dom'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import { Alert, AlertDescription } from '@/components/ui/alert'
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
import { useAuth } from '../layout/AuthContext'
import { PolicyForm } from '../components/PolicyForm/PolicyForm'
import { YamlEditor } from '../components/YamlEditor'
import { formToYaml } from '../utils/formToYaml'
import { yamlToForm } from '../utils/yamlToForm'
import type { PolicyFormInput } from '../api/types'

const EMPTY_FORM: PolicyFormInput = {
  name: '',
  namespace: 'default',
  processMode: 'whitelist',
  process: [],
  file: [],
}

export function PolicyEditPage() {
  const { user } = useAuth()
  const { name } = useParams<{ name: string }>()
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const location = useLocation()
  const toast = useToast()
  const namespace = searchParams.get('namespace') || undefined
  const isNew = !name
  const isAdmin = user?.role === 'admin'

  // Pre-fill from Behavior Discovery "Create Policy" navigation.
  // Read prefill once from location.state, then immediately clear the history
  // entry so that navigating back to /new again doesn't re-apply stale data.
  const prefill = (location.state as { prefill?: PolicyFormInput } | null)?.prefill

  // All hooks must be declared before any conditional return (React Rules of Hooks).
  const [namespaces, setNamespaces] = useState<string[]>([])
  const [policyMode, setPolicyMode] = useState<'Monitoring' | 'Protect'>('Monitoring')
  const [formValues, setFormValues] = useState<PolicyFormInput>(
    isNew && prefill ? { ...EMPTY_FORM, ...prefill } : EMPTY_FORM
  )
  const [yamlContent, setYamlContent] = useState('')
  const [yamlEditorKey, setYamlEditorKey] = useState(0)
  const [yamlValid, setYamlValid] = useState(true)
  const [activeTab, setActiveTab] = useState('form')
  const [loading, setLoading] = useState(false)
  const [pageLoading, setPageLoading] = useState(!isNew)
  // True when the loaded policy uses rules the form cannot represent (network
  // kprobes). The Form tab is then locked so a save cannot silently drop them.
  const [formUnsupported, setFormUnsupported] = useState(false)

  const action = policyMode === 'Protect' ? 'Sigkill' : 'Post'

  // Clear the prefill from browser history after consuming it once.
  useEffect(() => {
    if (isNew && prefill) {
      window.history.replaceState(null, '')
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Viewers cannot create new policies — redirect via effect to preserve hook order.
  useEffect(() => {
    if (!isAdmin && isNew) {
      navigate('/policies/tracing', { replace: true })
    }
  }, [isAdmin, isNew, navigate])

  useEffect(() => {
    const work: Promise<void>[] = [namespaceApi.list().then(setNamespaces)]
    if (!isNew && name) {
      work.push(
        policyApi.get(name, namespace).then((r) => {
          setYamlContent(r.rawYaml)
          setPolicyMode(r.mode === 'Protect' ? 'Protect' : 'Monitoring')
          // Pre-populate form from existing policy YAML
          const parsed = yamlToForm(r.rawYaml)
          if (parsed) {
            setFormValues(parsed)
          } else {
            setFormUnsupported(true)
            setActiveTab('yaml')
          }
        })
      )
    }
    Promise.all(work).finally(() => setPageLoading(false))
  }, [name, namespace, isNew])

  if (!isAdmin && isNew) return null

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
        // Always sync policyMode — the old namespace guard incorrectly skipped
        // cluster-wide policies (namespace === undefined) causing mode to stay stale.
        setPolicyMode(
          yamlContent.toLowerCase().includes('sigkill') ? 'Protect' : 'Monitoring'
        )
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

  // Viewer: read-only YAML view
  if (!isAdmin) {
    return (
      <>
        <div className="mb-6 flex items-start justify-between">
          <div>
            <h4 className="text-xl font-semibold">View Policy</h4>
            <p className="text-sm text-muted-foreground">{name}</p>
          </div>
          <Button variant="outline" onClick={() => navigate('/policies/tracing')}>
            ← Back
          </Button>
        </div>
        <YamlEditor initialValue={yamlContent} readOnly />
      </>
    )
  }

  return (
    <>
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h4 className="text-xl font-semibold">
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
            disabled={formUnsupported}
            title={formUnsupported ? 'This policy has network rules the form does not manage' : undefined}
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
        {formUnsupported && (
          <Alert className="mb-4">
            <AlertDescription className="text-xs">
              This policy contains network rules, which are now managed as{' '}
              <span className="font-medium">CiliumNetworkPolicy</span> rather than in this form.
              Edit it as YAML here — the form is disabled so a save cannot drop those rules.
            </AlertDescription>
          </Alert>
        )}
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
