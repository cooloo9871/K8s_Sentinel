import { useCallback, useEffect, useState } from 'react'
import { Card, CardHeader, CardTitle, CardContent, CardAction } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { YamlEditor } from '../components/YamlEditor'
import { policyApi, templateApi, type CustomTemplatePayload } from '../api/client'
import { useToast } from '../layout/AppToaster'
import { useAuth } from '../layout/AuthContext'
import { POLICY_TEMPLATES, type PolicyTemplate } from '../data/policyTemplates'

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

  // Use-template dialog
  const [selected, setSelected] = useState<PolicyTemplate | null>(null)
  const [policyName, setPolicyName] = useState('')
  const [creating, setCreating] = useState(false)

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

  // Delete dialog
  const [deleteTarget, setDeleteTarget] = useState<PolicyTemplate | null>(null)

  /* ── use template ── */
  const openDialog = (t: PolicyTemplate) => {
    setSelected(t)
    const slug = t.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '')
    const suffix = Math.random().toString(36).slice(2, 6)
    setPolicyName(`${slug}-${suffix}`)
  }

  const handleCreate = async () => {
    if (!selected || !policyName.trim()) return
    const yaml = selected.yaml.replace(/^(\s*name:\s*).+$/m, `$1${policyName.trim()}`)
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

  const handleCreateFromEditor = async () => {
    if (!editorValid || !editorYaml.trim()) return
    setCreating(true)
    try {
      await policyApi.create({ source: 'yaml', rawYaml: editorYaml })
      toast.success('Policy created.')
      closeEditor()
    } catch {
      toast.error('Failed to create policy')
    } finally { setCreating(false) }
  }

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
  const resetNewForm = () => { setNewName(''); setNewDesc(''); setNewTags(''); setNewYaml(DEFAULT_YAML); setShowNewForm(false) }

  const handleSaveTemplate = async () => {
    if (!newName.trim() || !newYaml.trim()) return
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
    } catch { toast.error('Failed to save template') }
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
  if (editingTemplate) {
    return (
      <>
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h4 className="text-xl font-semibold">{isAdmin ? 'Edit Template' : 'View Template'}</h4>
            <p className="text-sm text-muted-foreground">{editingTemplate.name}</p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" onClick={closeEditor}>← Back</Button>
            {isAdmin && editingTemplate?.custom && (
              <Button variant="outline" onClick={handleSave} disabled={!editorValid}>
                Save
              </Button>
            )}
            {isAdmin && (
              <Button onClick={handleCreateFromEditor} disabled={!editorValid || creating}>
                {creating ? 'Creating...' : 'Create Policy'}
              </Button>
            )}
          </div>
        </div>
        <YamlEditor key={editorKey} initialValue={editorYaml} readOnly={!isAdmin}
          onValueChange={(v, valid) => { setEditorYaml(v); setEditorValid(valid) }} />
      </>
    )
  }

  /* ── template list ── */
  return (
    <>
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h4 className="text-xl font-semibold">Policy Templates</h4>
          <p className="text-sm text-muted-foreground">Pre-built and custom TracingPolicy templates.</p>
        </div>
        {isAdmin && <Button onClick={() => setShowNewForm(v => !v)}>{showNewForm ? 'Cancel' : '+ New Template'}</Button>}
      </div>

      {showNewForm && (
        <Card className="mb-6 border-primary/40">
          <CardHeader className="border-b pb-3">
            <CardTitle className="text-sm font-medium">New Custom Template</CardTitle>
          </CardHeader>
          <CardContent className="pt-4 flex flex-col gap-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="flex flex-col gap-1">
                <Label className="text-xs">Name <span className="text-destructive">*</span></Label>
                <Input placeholder="My Template" value={newName} onChange={e => setNewName(e.target.value)} className="h-8 text-sm" />
              </div>
              <div className="flex flex-col gap-1">
                <Label className="text-xs">Tags <span className="text-muted-foreground font-normal">(comma-separated)</span></Label>
                <Input placeholder="namespace, process" value={newTags} onChange={e => setNewTags(e.target.value)} className="h-8 text-sm" />
              </div>
            </div>
            <div className="flex flex-col gap-1">
              <Label className="text-xs">Description</Label>
              <Input placeholder="What does this template do?" value={newDesc} onChange={e => setNewDesc(e.target.value)} className="h-8 text-sm" />
            </div>
            <div className="flex flex-col gap-1">
              <Label className="text-xs">YAML <span className="text-destructive">*</span></Label>
              <textarea className="min-h-[200px] w-full rounded-md border bg-muted px-3 py-2 font-mono text-xs focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                value={newYaml} onChange={e => setNewYaml(e.target.value)} />
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="outline" size="sm" onClick={resetNewForm}>Cancel</Button>
              <Button size="sm" onClick={handleSaveTemplate} disabled={!newName.trim() || !newYaml.trim()}>Save Template</Button>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {allTemplates.map(t => (
          <Card key={t.id}>
            <CardHeader className="border-b pb-3">
              <div>
                <CardTitle className="text-sm font-semibold">{t.name}</CardTitle>
                <div className="mt-1 flex flex-wrap gap-1">
                  {t.custom && <Badge className="text-[10px] bg-violet-500/15 text-violet-700">Custom</Badge>}
                  {t.tags.map(tag => <Badge key={tag} variant="secondary" className="text-[10px]">{tag}</Badge>)}
                </div>
              </div>
              {isAdmin && <CardAction><Button size="sm" onClick={() => openDialog(t)}>Use Template</Button></CardAction>}
            </CardHeader>
            <CardContent className="pt-3">
              {t.description && <p className="text-xs text-muted-foreground mb-3">{t.description}</p>}
              <pre className="rounded bg-muted px-3 py-2 text-[10px] font-mono overflow-x-auto max-h-48">{t.yaml.trim()}</pre>
              <div className="mt-2 flex gap-2">
                <Button variant="ghost" size="sm" className="flex-1 text-xs" onClick={() => openEditor(t)}>{isAdmin ? 'Open in Editor' : 'View YAML'}</Button>
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
            <AlertDialogDescription>{selected?.name} — set a name for the new policy.</AlertDialogDescription>
          </AlertDialogHeader>
          <div className="flex flex-col gap-1.5 py-2">
            <Label htmlFor="tpl-policy-name">Policy Name</Label>
            <Input id="tpl-policy-name" value={policyName} onChange={e => setPolicyName(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleCreate()} placeholder="my-policy" />
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setSelected(null)}>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleCreate} disabled={creating || !policyName.trim()}>
              {creating ? 'Creating...' : 'Create'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog open={!!deleteTarget} onOpenChange={(open: boolean) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Template</AlertDialogTitle>
            <AlertDialogDescription>Delete "{deleteTarget?.name}"? This cannot be undone.</AlertDialogDescription>
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
