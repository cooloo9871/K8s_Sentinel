import { useCallback, useEffect, useState } from 'react'
import { Card, CardHeader, CardTitle, CardContent, CardAction } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { YamlEditor } from '../components/YamlEditor'
import { policyApi, templateApi, clusterApi, type CustomTemplatePayload } from '../api/client'
import { useToast } from '../layout/AppToaster'
import { useAuth } from '../layout/AuthContext'
import { POLICY_TEMPLATES, type PolicyTemplate } from '../data/policyTemplates'

function templateScope(yaml: string): 'cluster' | 'namespace' {
  return /^metadata:\s*\n(?:\s+\S.*\n)*\s+namespace:\s*\S/m.test(yaml) ? 'namespace' : 'cluster'
}

function substituteCIDRs(yaml: string, podCIDRs: string[], serviceCIDRs: string[], nodeIPs: string[] = []): string {
  let result = yaml
  result = result.replace(/^(\s*)- "\$\{PODCIDR\}"$/gm, (_, indent) =>
    podCIDRs.length > 0 ? podCIDRs.map(c => `${indent}- "${c}"`).join('\n') : `${indent}- "# PODCIDR not detected"`)
  result = result.replace(/^(\s*)- "\$\{SVCCIDR\}"$/gm, (_, indent) =>
    serviceCIDRs.length > 0 ? serviceCIDRs.map(c => `${indent}- "${c}"`).join('\n') : `${indent}- "# SVCCIDR not detected"`)
  result = result.replace(/^(\s*)- "\$\{NODEIPS\}"$/gm, (_, indent) =>
    nodeIPs.length > 0 ? nodeIPs.map(ip => `${indent}- "${ip}"`).join('\n') : `${indent}- "# Node IPs not detected"`)
  return result
}

const DEFAULT_YAML = ''

function apiToTemplate(t: CustomTemplatePayload): PolicyTemplate {
  return { ...t, tags: t.tags ?? [], description: t.description ?? '', custom: true }
}

export function PolicyTemplatesPage() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const toast = useToast()
  const [customTemplates, setCustomTemplates] = useState<PolicyTemplate[]>([])

  const loadCustom = useCallback(async () => {
    try {
      const { templates } = await templateApi.list()
      setCustomTemplates(templates.map(apiToTemplate))
    } catch { /* ignore — server might not have any */ }
  }, [])

  useEffect(() => { loadCustom() }, [loadCustom])

  const allTemplates = [...POLICY_TEMPLATES, ...customTemplates]

  // Search & filter
  const [search, setSearch] = useState('')
  const [scopeFilter, setScopeFilter] = useState<'all' | 'cluster' | 'namespace'>('all')

  const filteredTemplates = allTemplates.filter(t => {
    if (search && !t.name.toLowerCase().includes(search.toLowerCase())) return false
    if (scopeFilter !== 'all' && templateScope(t.yaml) !== scopeFilter) return false
    return true
  })

  // Use-template dialog
  const [selected, setSelected] = useState<PolicyTemplate | null>(null)
  const [policyName, setPolicyName] = useState('')
  const [creating, setCreating] = useState(false)
  const [dialogLoading, setDialogLoading] = useState(false)

  // Inline YAML editor
  const [editingTemplate, setEditingTemplate] = useState<PolicyTemplate | null>(null)
  const [editorYaml, setEditorYaml] = useState('')
  const [editorValid, setEditorValid] = useState(true)
  const [editorKey, setEditorKey] = useState(0)

  // New template form
  const [showNewForm, setShowNewForm] = useState(false)
  const [newName, setNewName] = useState('')
  const [newDesc, setNewDesc] = useState('')
  const [newTags, setNewTags] = useState('')
  const [newYaml, setNewYaml] = useState(DEFAULT_YAML)
  const [newYamlValid, setNewYamlValid] = useState(true)
  const [savingNew, setSavingNew] = useState(false)

  // Delete dialog
  const [deleteTarget, setDeleteTarget] = useState<PolicyTemplate | null>(null)

  /* ── use template ── */
  const openDialog = async (t: PolicyTemplate) => {
    if (dialogLoading) return
    const slug = t.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '')
    const suffix = Math.random().toString(36).slice(2, 6)
    setPolicyName(`${slug}-${suffix}`)

    if (t.yaml.includes('${PODCIDR}') || t.yaml.includes('${SVCCIDR}')) {
      setDialogLoading(true)
      try {
        const { podCIDRs, serviceCIDRs, nodeIPs } = await clusterApi.cidr()
        const substituted = substituteCIDRs(t.yaml, podCIDRs, serviceCIDRs, nodeIPs)
        setSelected({ ...t, yaml: substituted })
      } catch {
        setSelected(t)
        toast.error('Could not detect cluster CIDRs. Edit the YAML manually before creating.')
      } finally {
        setDialogLoading(false)
      }
    } else {
      setSelected(t)
    }
  }

  const handleCreate = async () => {
    if (!selected || !policyName.trim()) return
    const yaml = selected.yaml.replace(/^(\s*name:\s*).+$/m, `$1${policyName.trim()}`)
    if (yaml.includes('${')) {
      toast.error('YAML contains unresolved placeholders. Edit the values manually before creating.')
      return
    }
    setCreating(true)
    try {
      await policyApi.create({ source: 'yaml', rawYaml: yaml })
      toast.success(`Policy "${policyName.trim()}" created.`)
      setSelected(null)
    } catch {
      toast.error('Failed to create policy')
    } finally { setCreating(false) }
  }

  /* ── inline editor ── */
  const openEditor = (t: PolicyTemplate) => {
    setEditingTemplate(t); setEditorYaml(t.yaml)
    setEditorValid(true); setEditorKey(k => k + 1)
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }
  const closeEditor = () => setEditingTemplate(null)


  // Save: update existing custom template
  const handleSave = async () => {
    if (!editingTemplate || !editingTemplate.custom) return
    try {
      await templateApi.update(editingTemplate.id, {
        id: editingTemplate.id, name: editingTemplate.name,
        description: editingTemplate.description, tags: editingTemplate.tags, yaml: editorYaml,
      })
      await loadCustom()
      toast.success('Template saved.')
      closeEditor()
    } catch { toast.error('Failed to save template') }
  }


  /* ── new template form ── */
  const resetNewForm = () => {
    setNewName(''); setNewDesc(''); setNewTags('')
    setNewYaml(DEFAULT_YAML); setNewYamlValid(true)
    setShowNewForm(false)
  }

  const handleSaveTemplate = async () => {
    if (!newName.trim() || !newYaml.trim() || !newYamlValid) return
    setSavingNew(true)
    const payload: CustomTemplatePayload = {
      id: `custom-${Date.now()}`,
      name: newName.trim(), description: newDesc.trim(),
      tags: newTags.split(',').map(t => t.trim()).filter(Boolean),
      yaml: newYaml,
    }
    try {
      await templateApi.create(payload)
      await loadCustom()
      toast.success('Template saved.')
      resetNewForm()
    } catch {
      toast.error('Failed to save template')
    } finally {
      setSavingNew(false)
    }
  }

  /* ── delete ── */
  const handleDelete = async () => {
    if (!deleteTarget?.id) return
    try {
      await templateApi.delete(deleteTarget.id)
      await loadCustom()
      toast.success('Template deleted.')
      setDeleteTarget(null)
    } catch { toast.error('Failed to delete template') }
  }

  /* ── inline editor view ── */
  /* ── new template view ── */
  if (showNewForm) {
    return (
      <>
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h4 className="text-xl font-semibold">New Template</h4>
            <p className="text-sm text-muted-foreground">
              A custom template is stored in K8s Sentinel and applied only when you create a policy from it.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" onClick={resetNewForm}>Cancel</Button>
            <Button
              onClick={handleSaveTemplate}
              disabled={savingNew || !newName.trim() || !newYaml.trim() || !newYamlValid}
            >
              {savingNew ? 'Applying...' : 'Apply'}
            </Button>
          </div>
        </div>

        <Card className="mb-4">
          <CardContent className="flex flex-col gap-5 p-6">
            <div className="grid grid-cols-2 gap-4">
              <div className="flex flex-col gap-1.5">
                <Label className="text-xs">Name <span className="text-destructive">*</span></Label>
                <Input value={newName} onChange={e => setNewName(e.target.value)} className="h-9" />
              </div>
              <div className="flex flex-col gap-1.5">
                <Label className="text-xs">
                  Tags <span className="font-normal text-muted-foreground">(comma-separated)</span>
                </Label>
                <Input value={newTags} onChange={e => setNewTags(e.target.value)} className="h-9" />
              </div>
            </div>
            <div className="flex flex-col gap-1.5">
              <Label className="text-xs">Description</Label>
              <Input value={newDesc} onChange={e => setNewDesc(e.target.value)} className="h-9" />
            </div>
          </CardContent>
        </Card>

        <YamlEditor
          key="new-template"
          initialValue={newYaml}
          onValueChange={(v, valid) => { setNewYaml(v); setNewYamlValid(valid) }}
        />
      </>
    )
  }

  if (editingTemplate) {
    return (
      <>
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h4 className="text-xl font-semibold">{isAdmin && editingTemplate?.custom ? 'Edit Template' : 'View Template'}</h4>
            <p className="text-sm text-muted-foreground">{editingTemplate.name}</p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" onClick={closeEditor}>Cancel</Button>
            {isAdmin && editingTemplate?.custom && (
              <Button onClick={handleSave} disabled={!editorValid}>Apply</Button>
            )}
          </div>
        </div>
        <YamlEditor key={editorKey} initialValue={editorYaml} readOnly={!isAdmin || !editingTemplate?.custom}
          onValueChange={(v, valid) => { setEditorYaml(v); setEditorValid(valid) }} />
      </>
    )
  }

  /* ── template list ── */
  return (
    <>
      <div className="mb-4 flex items-start justify-between">
        <div>
          <h4 className="text-xl font-semibold">Policy Templates</h4>
          <p className="text-sm text-muted-foreground">Pre-built and custom Tracing Policy templates.</p>
        </div>
      </div>

      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Input
            placeholder="Search by name..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="h-8 w-56 text-sm"
          />
          {/* Not the shared ScopeFilter: that one lists the cluster's namespaces,
              and a template belongs to none — its scope is whichever kind its
              manifest declares. Same control and size, options that are true
              here. */}
          <Select value={scopeFilter} onValueChange={v => setScopeFilter(v as typeof scopeFilter)}>
            <SelectTrigger className="h-8 w-52 text-sm">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="all">All scopes</SelectItem>
                <SelectItem value="cluster">Cluster-wide</SelectItem>
                <SelectItem value="namespace">Namespaced</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>
        </div>
        {isAdmin && (
          <Button size="sm" onClick={() => setShowNewForm(true)}>+ New Template</Button>
        )}
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {filteredTemplates.length === 0 && (
          <p className="col-span-full py-10 text-center text-sm text-muted-foreground">No templates found</p>
        )}
        {filteredTemplates.map(t => (
          <Card key={t.id}>
            <CardHeader className="border-b pb-3">
              <div>
                <CardTitle className="text-sm font-semibold">{t.name}</CardTitle>
                <div className="mt-1 flex flex-wrap gap-1">
                  {t.custom && <Badge className="text-[10px] bg-violet-500/15 text-violet-700">Custom</Badge>}
                  {t.tags.map(tag => <Badge key={tag} variant="secondary" className="text-[10px]">{tag}</Badge>)}
                </div>
              </div>
              {isAdmin && <CardAction><Button size="sm" onClick={() => openDialog(t)} disabled={dialogLoading}>{dialogLoading ? 'Loading...' : 'Use Template'}</Button></CardAction>}
            </CardHeader>
            <CardContent className="pt-3">
              {t.description && <p className="text-xs text-muted-foreground mb-3">{t.description}</p>}
              <pre className="rounded bg-muted px-3 py-2 text-[10px] font-mono overflow-x-auto max-h-48">{t.yaml.trim()}</pre>
              <div className="mt-2 flex gap-2">
                <Button variant="ghost" size="sm" className="flex-1 text-xs" onClick={() => openEditor(t)}>{isAdmin && t.custom ? 'Open in Editor' : 'View YAML'}</Button>
                {isAdmin && t.custom && (
                  <Button variant="ghost" size="sm" className="text-xs text-destructive hover:text-destructive" onClick={() => setDeleteTarget(t)}>Delete</Button>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <AlertDialog open={!!selected} onOpenChange={(open: boolean) => !open && setSelected(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Create from Template</AlertDialogTitle>
            <AlertDialogDescription>{selected?.name}: set a name for the new policy.</AlertDialogDescription>
          </AlertDialogHeader>
          {selected?.yaml.includes('${') && (
            <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
              Cluster CIDRs could not be detected. Replace all <code className="font-mono">{'${...}'}</code> placeholders in the YAML manually before creating, or update the ClusterRole and retry.
            </div>
          )}
          <div className="flex flex-col gap-1.5 py-2">
            <Label htmlFor="tpl-policy-name">Policy Name</Label>
            <Input id="tpl-policy-name" value={policyName} onChange={e => setPolicyName(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleCreate()} placeholder="my-policy" />
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setSelected(null)}>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleCreate} disabled={creating || !policyName.trim() || !!selected?.yaml.includes('${')}>
              {creating ? 'Creating...' : 'Create'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog open={!!deleteTarget} onOpenChange={(open: boolean) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Template</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete <strong>{deleteTarget?.name}</strong>?
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setDeleteTarget(null)}>Cancel</AlertDialogCancel>
            <AlertDialogAction variant="destructive" onClick={handleDelete}>Delete</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
