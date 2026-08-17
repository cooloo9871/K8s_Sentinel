import { useEffect, useState } from 'react'
import { useNavigate, useParams, useSearchParams, useLocation } from 'react-router-dom'
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
  const [yamlValid, setYamlValid] = useState(true)
  // Which editor this page opened in. "+ New YAML" on the list asks for the raw
  // editor; everything else starts on the form. An existing policy the form
  // cannot represent is switched over once that is known, below.
  const [mode, setMode] = useState<'form' | 'yaml'>(
    searchParams.get('mode') === 'yaml' ? 'yaml' : 'form'
  )
  const [loading, setLoading] = useState(false)
  const [pageLoading, setPageLoading] = useState(!isNew)
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
          // A manifest applied with kubectl opens as the YAML its author wrote,
          // the same way Admission Policy and Network Policy treat anything not
          // built here — even when the form could show it, a save from the form
          // would rewrite an externally managed file into the builder's shape.
          if (r.createdBy === 'k8s-apply') {
            setMode('yaml')
            return
          }
          // Pre-populate form from existing policy YAML
          const parsed = yamlToForm(r.rawYaml)
          if (parsed) {
            setFormValues(parsed)
          } else {
            // The form cannot represent every policy — a network kprobe, or an
            // execve rule matching everything. Opening as YAML is how a save is
            // kept from writing back only the part the form could show.
            setMode('yaml')
          }
        })
      )
    }
    Promise.all(work).finally(() => setPageLoading(false))
  }, [name, namespace, isNew])

  if (!isAdmin && isNew) return null

  const handleSave = async () => {
    if (mode === 'form') {
      if (!formValues.name.trim()) {
        toast.error('Policy name is required')
        return
      }
      setLoading(true)
      try {
        const payload = { source: 'form' as const, form: formValues, action }
        if (isNew) await policyApi.create(payload)
        else await policyApi.update(name!, payload, namespace)
        toast.success('Policy applied')
        navigate('/policies/tracing')
      } catch (e) {
        // The builder refuses some forms — no rules, a relative binary path —
        // and says which. The interceptor puts that on the error; reporting a
        // fixed string instead leaves the reason on the floor.
        toast.error(e instanceof Error && e.message ? e.message : 'Failed to apply policy')
      } finally {
        setLoading(false)
      }
    } else {
      // An empty document parses cleanly, so validity alone would let a blank
      // editor be submitted. The other two policy pages guard on content too.
      if (!yamlContent.trim()) {
        toast.error('Write or paste a manifest before saving')
        return
      }
      if (!yamlValid) {
        toast.error('Fix YAML errors before saving')
        return
      }
      setLoading(true)
      try {
        const payload = { source: 'yaml' as const, rawYaml: yamlContent }
        if (isNew) await policyApi.create(payload)
        else await policyApi.update(name!, payload, namespace)
        toast.success('Policy applied')
        navigate('/policies/tracing')
      } catch (e) {
        toast.error(e instanceof Error && e.message ? e.message : 'Failed to apply YAML')
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
            {loading ? 'Applying...' : 'Apply'}
          </Button>
        </div>
      </div>

      {mode === 'form' ? (
        <PolicyForm
          namespaces={namespaces}
          action={action}
          value={formValues}
          onChange={setFormValues}
        />
      ) : (
        <YamlEditor
          key={name ?? 'new'}
          initialValue={yamlContent}
          onValueChange={(v, valid) => {
            setYamlContent(v)
            setYamlValid(valid)
          }}
        />
      )}
    </>
  )
}
