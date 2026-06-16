import { useCallback, useEffect, useState } from 'react'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
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
  eventTypes: [],
  severities: [],
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
        <Label className="text-xs">Event Type <span className="text-muted-foreground font-normal">(empty = all)</span></Label>
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
        <Label className="text-xs">Severity <span className="text-muted-foreground font-normal">(empty = all)</span></Label>
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
        <Button variant="outline" size="sm" onClick={onCancel}>Cancel</Button>
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
  const [showForm, setShowForm] = useState(false)
  const [editTarget, setEditTarget] = useState<AlertRule | null>(null)
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
      setShowForm(false)
      load()
    } catch { toast.error('Failed to create alert rule') }
    finally { setSaving(false) }
  }

  const handleUpdate = async (form: Omit<AlertRule, 'id'>) => {
    if (!editTarget) return
    setSaving(true)
    try {
      await alertsApi.update(editTarget.id, { ...form, id: editTarget.id })
      toast.success('Alert rule updated.')
      setEditTarget(null)
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

  return (
    <>
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h4 className="text-xl font-semibold">Alerts</h4>
          <p className="text-sm text-muted-foreground">Webhook notifications for Security Events.</p>
        </div>
        {isAdmin && !showForm && (
          <Button onClick={() => { setShowForm(true); setEditTarget(null) }}>+ New Rule</Button>
        )}
      </div>

      {isAdmin && showForm && !editTarget && (
        <Card className="mb-6 border-primary/40">
          <CardHeader className="border-b pb-3">
            <CardTitle className="text-sm font-medium">New Alert Rule</CardTitle>
          </CardHeader>
          <CardContent className="pt-4">
            <RuleForm initial={EMPTY_RULE}              onSave={handleCreate} onCancel={() => setShowForm(false)} saving={saving} />
          </CardContent>
        </Card>
      )}

      {rules.length === 0 && !showForm && (
        <p className="py-10 text-center text-sm text-muted-foreground">No alert rules configured.</p>
      )}

      <div className="flex flex-col gap-3">
        {rules.map(rule => (
          <Card key={rule.id} className={rule.enabled ? '' : 'opacity-60'}>
            {isAdmin && editTarget?.id === rule.id ? (
              <CardContent className="pt-4">
                <RuleForm initial={editTarget}                  onSave={handleUpdate} onCancel={() => setEditTarget(null)} saving={saving} />
              </CardContent>
            ) : (
              <>
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
                        onClick={() => { setEditTarget(rule); setShowForm(false) }}>Edit</Button>
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
              </>
            )}
          </Card>
        ))}
      </div>

      <AlertDialog open={!!deleteTarget} onOpenChange={open => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Alert Rule</AlertDialogTitle>
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
