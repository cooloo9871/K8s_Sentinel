import { useCallback, useEffect, useState } from 'react'
import { Card, CardHeader, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { alertsApi, type AlertRule } from '../api/client'
import { useAuth } from '../layout/AuthContext'
import { useToast } from '../layout/AppToaster'

const EMPTY_RULE: Omit<AlertRule, 'id'> = {
  name: '',
  webhookURL: '',
  eventTypes: ['security', 'admission'],
  severities: ['warning', 'critical'],
  namespaces: [],
  policies: [],
  cooldownMin: 5,
  enabled: true,
}

function RuleForm({
  initial, onSave, onCancel, saving,
}: {
  initial: Omit<AlertRule, 'id'>
  onSave: (r: Omit<AlertRule, 'id'>) => void
  onCancel: () => void
  saving: boolean
}) {
  const [form, setForm] = useState(initial)
  const set = (k: keyof typeof form, v: unknown) => setForm(f => ({ ...f, [k]: v }))

  const toggleSeverity = (s: string) => {
    set('severities', form.severities.includes(s)
      ? form.severities.filter(x => x !== s)
      : [...form.severities, s])
  }

  const toggleEventType = (t: string) => {
    set('eventTypes', form.eventTypes.includes(t)
      ? form.eventTypes.filter(x => x !== t)
      : [...form.eventTypes, t])
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-cols-2 gap-3">
        <div className="flex flex-col gap-1">
          <Label className="text-xs">Name <span className="text-destructive">*</span></Label>
          <Input className="h-8 text-sm" value={form.name} onChange={e => set('name', e.target.value)} placeholder="My Alert" />
        </div>
        <div className="flex flex-col gap-1">
          <Label className="text-xs">Cooldown (minutes)</Label>
          <Input className="h-8 text-sm" type="number" min="0" value={form.cooldownMin}
            onChange={e => set('cooldownMin', parseInt(e.target.value) || 0)} />
        </div>
      </div>
      <div className="flex flex-col gap-1">
        <Label className="text-xs">Webhook URL <span className="text-destructive">*</span></Label>
        <Input className="h-8 text-sm font-mono" value={form.webhookURL}
          onChange={e => set('webhookURL', e.target.value)} placeholder="https://hooks.slack.com/..." />
      </div>
      <div className="flex flex-col gap-1">
        <Label className="text-xs">Event Type</Label>
        <div className="flex gap-4">
          {(['security', 'admission'] as const).map(t => (
            <label key={t} className="flex items-center gap-1.5 cursor-pointer select-none text-sm capitalize">
              <input type="checkbox" className="h-4 w-4 accent-primary cursor-pointer"
                checked={form.eventTypes.includes(t)} onChange={() => toggleEventType(t)} />
              {t === 'security' ? 'Security Events' : 'Admission Events'}
            </label>
          ))}
        </div>
      </div>
      <div className="flex flex-col gap-1">
        <Label className="text-xs">Severity</Label>
        <div className="flex gap-4">
          {(['warning', 'critical'] as const).map(s => (
            <label key={s} className="flex items-center gap-1.5 cursor-pointer select-none text-sm capitalize">
              <input
                type="checkbox"
                className="h-4 w-4 rounded border-border accent-primary cursor-pointer"
                checked={form.severities.includes(s)}
                onChange={() => toggleSeverity(s)}
              />
              {s}
            </label>
          ))}
        </div>
      </div>
      <div className="flex flex-col gap-1">
        <Label className="text-xs">Namespaces <span className="text-muted-foreground font-normal">(comma-separated, empty = all)</span></Label>
        <Input className="h-8 text-sm" value={form.namespaces.join(',')}
          onChange={e => set('namespaces', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
          placeholder="default, kube-system" />
      </div>
      <div className="flex flex-col gap-1">
        <Label className="text-xs">Policies <span className="text-muted-foreground font-normal">(comma-separated, empty = all)</span></Label>
        <Input className="h-8 text-sm" value={form.policies.join(',')}
          onChange={e => set('policies', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
          placeholder="monitor-all-exec, monitor-all-file" />
      </div>
      <div className="flex justify-end gap-2 pt-1">
        <Button variant="outline" size="sm" onClick={onCancel} disabled={saving}>Cancel</Button>
        <Button size="sm" onClick={() => onSave(form)} disabled={saving || !form.name.trim() || !form.webhookURL.trim()}>
          {saving ? 'Saving...' : 'Save'}
        </Button>
      </div>
    </div>
  )
}

export function AlertsPage() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const toast = useToast()

  const [rules, setRules] = useState<AlertRule[]>([])
  // Which screen is up: the list (null), the create form ('new'), or the edit
  // form for one rule. One value, so the two forms cannot both be "open".
  const [formTarget, setFormTarget] = useState<AlertRule | 'new' | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<AlertRule | null>(null)
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState<string | null>(null)

  const load = useCallback(async () => {
    try { setRules(await alertsApi.list()) } catch { /* ignore */ }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const handleCreate = async (form: Omit<AlertRule, 'id'>) => {
    setSaving(true)
    try {
      await alertsApi.create(form)
      toast.success('Alert rule created.')
      setFormTarget(null)
      load()
    } catch { toast.error('Failed to create alert rule') }
    finally { setSaving(false) }
  }

  const handleUpdate = async (form: Omit<AlertRule, 'id'>) => {
    if (!formTarget || formTarget === 'new') return
    setSaving(true)
    try {
      await alertsApi.update(formTarget.id, { ...form, id: formTarget.id })
      toast.success('Alert rule updated.')
      setFormTarget(null)
      load()
    } catch { toast.error('Failed to update alert rule') }
    finally { setSaving(false) }
  }

  const handleToggle = async (rule: AlertRule) => {
    try {
      await alertsApi.update(rule.id, { ...rule, enabled: !rule.enabled })
      load()
    } catch { toast.error('Failed to toggle rule') }
  }

  const handleDelete = async () => {
    if (!deleteTarget) return
    try {
      await alertsApi.delete(deleteTarget.id)
      toast.success('Alert rule deleted.')
      setDeleteTarget(null)
      load()
    } catch { toast.error('Failed to delete alert rule') }
  }

  const handleTest = async (rule: AlertRule) => {
    setTesting(rule.id)
    try {
      await alertsApi.test(rule.webhookURL)
      toast.success('Test payload sent successfully.')
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Test failed'
      toast.error(msg)
    } finally { setTesting(null) }
  }

  // Creating and editing happen on a screen of their own — the list comes back
  // on save or cancel, the same way the Network Policy editor does it.
  if (isAdmin && formTarget) {
    const editing = formTarget === 'new' ? null : formTarget
    return (
      <>
        <div className="mb-6">
          <h4 className="text-xl font-semibold">
            {editing ? `Edit ${editing.name}` : 'New Alert Rule'}
          </h4>
        </div>
        <Card className="max-w-2xl">
          <CardContent className="pt-4">
            <RuleForm
              initial={editing ?? EMPTY_RULE}
              onSave={editing ? handleUpdate : handleCreate}
              onCancel={() => setFormTarget(null)}
              saving={saving}
            />
          </CardContent>
        </Card>
      </>
    )
  }

  return (
    <>
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h4 className="text-xl font-semibold">Alerts</h4>
          <p className="text-sm text-muted-foreground">Send webhook notifications for Security Events and Admission Events.</p>
        </div>
        {isAdmin && (
          <Button onClick={() => setFormTarget('new')}>+ New Rule</Button>
        )}
      </div>

      {rules.length === 0 && (
        <p className="py-10 text-center text-sm text-muted-foreground">No alert rules configured.</p>
      )}

      <div className="flex flex-col gap-3">
        {rules.map(rule => (
          <Card key={rule.id} className={rule.enabled ? '' : 'opacity-60'}>
            <CardHeader className="border-b pb-3">
              <div className="flex items-center gap-2 min-w-0">
                <span className="font-medium text-sm">{rule.name}</span>
                <Badge variant={rule.enabled ? 'default' : 'secondary'} className="text-[10px]">
                  {rule.enabled ? 'Enabled' : 'Disabled'}
                </Badge>
                {rule.severities.map(s => (
                  <Badge key={s} variant={s === 'critical' ? 'destructive' : 'outline'} className="text-[10px] capitalize">{s}</Badge>
                ))}
              </div>
              {isAdmin && (
                <div className="ml-auto flex items-center gap-2 shrink-0">
                  <Button variant="ghost" size="sm" className="h-7 text-xs"
                    onClick={() => handleTest(rule)} disabled={testing === rule.id}>
                    {testing === rule.id ? 'Sending...' : 'Test'}
                  </Button>
                  <Button variant="ghost" size="sm" className="h-7 text-xs"
                    onClick={() => setFormTarget(rule)}>Edit</Button>
                  <Button variant="ghost" size="sm" className="h-7 text-xs"
                    onClick={() => handleToggle(rule)}>
                    {rule.enabled ? 'Disable' : 'Enable'}
                  </Button>
                  <Button variant="ghost" size="sm" className="h-7 text-xs text-destructive hover:text-destructive"
                    onClick={() => setDeleteTarget(rule)}>Delete</Button>
                </div>
              )}
            </CardHeader>
            <CardContent className="pt-3 text-xs text-muted-foreground flex flex-col gap-1">
              <p className="font-mono truncate" title={rule.webhookURL}>{rule.webhookURL}</p>
              <div className="flex gap-4">
                <span>Namespaces: {rule.namespaces.length ? rule.namespaces.join(', ') : 'all'}</span>
                <span>Policies: {rule.policies.length ? rule.policies.join(', ') : 'all'}</span>
                <span>Cooldown: {rule.cooldownMin ? `${rule.cooldownMin} min` : 'none'}</span>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <AlertDialog open={!!deleteTarget} onOpenChange={open => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Alert Rule</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete <strong>{deleteTarget?.name}</strong>?
            </AlertDialogDescription>
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
