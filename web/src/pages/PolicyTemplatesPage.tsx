import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Card, CardHeader, CardTitle, CardContent, CardAction } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { policyApi } from '../api/client'
import { useToast } from '../layout/AppToaster'
import { POLICY_TEMPLATES, type PolicyTemplate } from '../data/policyTemplates'

export function PolicyTemplatesPage() {
  const navigate = useNavigate()
  const toast = useToast()
  const [selected, setSelected] = useState<PolicyTemplate | null>(null)
  const [policyName, setPolicyName] = useState('')
  const [creating, setCreating] = useState(false)

  const openDialog = (t: PolicyTemplate) => {
    setSelected(t)
    setPolicyName(t.id)
  }

  const handleCreate = async () => {
    if (!selected || !policyName.trim()) return
    const yaml = selected.yaml.replace(
      /^(\s*name:\s*).+$/m,
      `$1${policyName.trim()}`
    )
    setCreating(true)
    try {
      await policyApi.create({ source: 'yaml', rawYaml: yaml })
      toast.success(`Policy "${policyName.trim()}" created.`)
      setSelected(null)
      navigate('/policies/tracing')
    } catch {
      toast.error('Failed to create policy')
    } finally {
      setCreating(false)
    }
  }

  const openInEditor = (t: PolicyTemplate) => {
    navigate('/policies/tracing/new', { state: { yamlContent: t.yaml } })
  }

  return (
    <>
      <div className="mb-6">
        <h4 className="text-xl font-semibold">Policy Templates</h4>
        <p className="text-sm text-muted-foreground">
          Pre-built TracingPolicy templates. Use directly or open in the editor to customise.
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {POLICY_TEMPLATES.map(t => (
          <Card key={t.id}>
            <CardHeader className="border-b pb-3">
              <div>
                <CardTitle className="text-sm font-semibold">{t.name}</CardTitle>
                <div className="mt-1 flex flex-wrap gap-1">
                  {t.tags.map(tag => (
                    <Badge key={tag} variant="secondary" className="text-[10px]">{tag}</Badge>
                  ))}
                </div>
              </div>
              <CardAction>
                <Button size="sm" onClick={() => openDialog(t)}>Use Template</Button>
              </CardAction>
            </CardHeader>
            <CardContent className="pt-3">
              <p className="text-xs text-muted-foreground mb-3">{t.description}</p>
              <pre className="rounded bg-muted px-3 py-2 text-[10px] font-mono overflow-x-auto max-h-48">
                {t.yaml.trim()}
              </pre>
              <Button
                variant="ghost"
                size="sm"
                className="mt-2 w-full text-xs"
                onClick={() => openInEditor(t)}
              >
                Open in Editor
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Name input dialog */}
      <AlertDialog open={!!selected} onOpenChange={(open: boolean) => !open && setSelected(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Create from Template</AlertDialogTitle>
            <AlertDialogDescription>
              {selected?.name} — set a name for the new policy.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="flex flex-col gap-1.5 py-2">
            <Label htmlFor="tpl-policy-name">Policy Name</Label>
            <Input
              id="tpl-policy-name"
              value={policyName}
              onChange={e => setPolicyName(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleCreate()}
              placeholder="my-policy"
            />
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setSelected(null)}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleCreate}
              disabled={creating || !policyName.trim()}
            >
              {creating ? 'Creating...' : 'Create'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
