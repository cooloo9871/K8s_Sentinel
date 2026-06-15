import { useCallback, useEffect, useState } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { YamlEditor } from '../components/YamlEditor'
import { admissionRulesApi, type AdmissionRule } from '../api/client'
import { useAuth } from '../layout/AuthContext'
import { useToast } from '../layout/AppToaster'
import { formatTWTime } from '../utils/time'

const TEMPLATE = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: my-admission-rule
spec:
  matchConstraints:
    resourceRules:
    - apiGroups: ["apps"]
      apiVersions: ["v1"]
      operations: ["CREATE", "UPDATE"]
      resources: ["deployments"]
  validations:
  - expression: "object.spec.replicas <= 5"
    message: "Replicas must be <= 5"
`

type EditorState = { id?: string; yaml: string; readOnly: boolean }

export function AdmissionRulesPage() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const toast = useToast()

  const [rules, setRules] = useState<AdmissionRule[]>([])
  const [editor, setEditor] = useState<EditorState | null>(null)
  const [editorYaml, setEditorYaml] = useState('')
  const [editorValid, setEditorValid] = useState(true)
  const [saving, setSaving] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<AdmissionRule | null>(null)

  const load = useCallback(async () => {
    try { setRules(await admissionRulesApi.list()) } catch { }
  }, [])

  useEffect(() => { load() }, [load])

  const openNew = () => {
    setEditorYaml(TEMPLATE)
    setEditorValid(true)
    setEditor({ yaml: TEMPLATE, readOnly: false })
  }

  const openEdit = (rule: AdmissionRule, readOnly: boolean) => {
    setEditorYaml(rule.rawYaml)
    setEditorValid(true)
    setEditor({ id: rule.id, yaml: rule.rawYaml, readOnly })
  }

  const handleSave = async () => {
    if (!editor || !editorValid) return
    setSaving(true)
    try {
      if (editor.id) {
        await admissionRulesApi.update(editor.id, editorYaml)
        toast.success('Rule updated.')
      } else {
        await admissionRulesApi.create(editorYaml)
        toast.success('Rule created.')
      }
      setEditor(null)
      load()
    } catch (e: unknown) {
      toast.error((e as { response?: { data?: string } })?.response?.data || 'Failed to save rule')
    } finally { setSaving(false) }
  }

  const handleToggle = async (rule: AdmissionRule) => {
    try {
      await admissionRulesApi.toggle(rule.id, !rule.enabled)
      load()
    } catch { toast.error('Failed to toggle rule') }
  }

  const handleDelete = async () => {
    if (!deleteTarget) return
    try {
      await admissionRulesApi.delete(deleteTarget.id)
      toast.success('Rule deleted.')
      setDeleteTarget(null)
      load()
    } catch { toast.error('Failed to delete rule') }
  }

  if (editor) {
    const title = editor.id
      ? (editor.readOnly ? 'View Rule' : 'Edit Rule')
      : 'New Admission Rule'
    return (
      <>
        <div className="mb-4 flex items-center justify-between">
          <h4 className="text-xl font-semibold">{title}</h4>
          <div className="flex items-center gap-2">
            <Button variant="outline" onClick={() => setEditor(null)}>← Back</Button>
            {isAdmin && !editor.readOnly && (
              <Button onClick={handleSave} disabled={!editorValid || saving}>
                {saving ? 'Saving...' : 'Save'}
              </Button>
            )}
          </div>
        </div>
        <YamlEditor
          key={editor.id ?? 'new'}
          initialValue={editorYaml}
          readOnly={editor.readOnly}
          onValueChange={(v, valid) => { setEditorYaml(v); setEditorValid(valid) }}
        />
      </>
    )
  }

  return (
    <>
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h4 className="text-xl font-semibold">Admission Rules</h4>
          <p className="text-sm text-muted-foreground">
            Sentinel-managed admission rules enforced via webhook. Uses VAP-compatible YAML format.
          </p>
        </div>
        {isAdmin && <Button onClick={openNew}>+ New Rule</Button>}
      </div>

      {rules.length === 0 && (
        <p className="py-10 text-center text-sm text-muted-foreground">No admission rules configured.</p>
      )}

      <div className="flex flex-col gap-3">
        {rules.map(rule => (
          <Card key={rule.id} className={rule.enabled ? '' : 'opacity-60'}>
            <CardContent className="flex items-center justify-between py-3">
              <div className="flex items-center gap-3 min-w-0">
                <span className="font-medium text-sm truncate">{rule.name}</span>
                <Badge variant={rule.enabled ? 'default' : 'secondary'} className="text-[10px] shrink-0">
                  {rule.enabled ? 'Enabled' : 'Disabled'}
                </Badge>
                <span className="text-xs text-muted-foreground shrink-0">{formatTWTime(rule.createdAt)}</span>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <Button variant="ghost" size="sm" className="h-7 text-xs"
                  onClick={() => openEdit(rule, !isAdmin)}>
                  {isAdmin ? 'Edit' : 'View'}
                </Button>
                {isAdmin && (
                  <>
                    <Button variant="ghost" size="sm" className="h-7 text-xs"
                      onClick={() => handleToggle(rule)}>
                      {rule.enabled ? 'Disable' : 'Enable'}
                    </Button>
                    <Button variant="ghost" size="sm" className="h-7 text-xs text-destructive hover:text-destructive"
                      onClick={() => setDeleteTarget(rule)}>
                      Delete
                    </Button>
                  </>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <AlertDialog open={!!deleteTarget} onOpenChange={open => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Rule</AlertDialogTitle>
            <AlertDialogDescription>Delete "{deleteTarget?.name}"? This cannot be undone.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction variant="destructive" onClick={handleDelete}>Delete</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
