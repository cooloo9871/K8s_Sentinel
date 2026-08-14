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
import { rsyslogApi, type RsyslogConfig } from '../api/client'
import { useAuth } from '../layout/AuthContext'
import { useToast } from '../layout/AppToaster'


const EMPTY: Omit<RsyslogConfig, 'id'> = {
  name: '', host: '', port: 514, protocol: 'udp',
  facility: 16, // fixed: local0
  eventTypes: ['security', 'admission'], severities: ['warning', 'critical'], namespaces: [], policies: [], enabled: true,
}

function ConfigForm({
  initial, onSave, onCancel, saving,
}: {
  initial: Omit<RsyslogConfig, 'id'>
  onSave: (c: Omit<RsyslogConfig, 'id'>) => void
  onCancel: () => void
  saving: boolean
}) {
  const [form, setForm] = useState(initial)
  const set = <K extends keyof typeof form>(k: K, v: (typeof form)[K]) =>
    setForm(f => ({ ...f, [k]: v }))

  const toggleSeverity = (s: string) =>
    set('severities', form.severities.includes(s)
      ? form.severities.filter(x => x !== s)
      : [...form.severities, s])

  const toggleEventType = (t: string) =>
    set('eventTypes', form.eventTypes.includes(t)
      ? form.eventTypes.filter(x => x !== t)
      : [...form.eventTypes, t])

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-col gap-1">
        <Label className="text-xs">Name <span className="text-destructive">*</span></Label>
        <Input className="h-8 text-sm" value={form.name} onChange={e => set('name', e.target.value)} placeholder="My Syslog" />
      </div>

      <div className="grid grid-cols-3 gap-3">
        <div className="col-span-2 flex flex-col gap-1">
          <Label className="text-xs">Host <span className="text-destructive">*</span></Label>
          <Input className="h-8 text-sm font-mono" value={form.host}
            onChange={e => set('host', e.target.value)} placeholder="192.168.1.1" />
        </div>
        <div className="flex flex-col gap-1">
          <Label className="text-xs">Port</Label>
          <Input className="h-8 text-sm" type="number" value={form.port}
            onChange={e => set('port', parseInt(e.target.value) || 514)} />
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="flex flex-col gap-1">
          <Label className="text-xs">Protocol</Label>
          <div className="flex gap-2">
            {(['udp', 'tcp'] as const).map(p => (
              <Button key={p} size="sm" variant={form.protocol === p ? 'default' : 'outline'}
                className="h-7 text-xs uppercase" onClick={() => set('protocol', p)}>{p}</Button>
            ))}
          </div>
        </div>
        <div className="flex flex-col gap-1">
          <Label className="text-xs">Event Type</Label>
          <div className="flex gap-3">
            {(['security', 'admission'] as const).map(t => (
              <label key={t} className="flex items-center gap-1.5 cursor-pointer text-xs">
                <input type="checkbox" className="h-4 w-4 accent-primary cursor-pointer"
                  checked={form.eventTypes.includes(t)} onChange={() => toggleEventType(t)} />
                {t === 'security' ? 'Security' : 'Admission'}
              </label>
            ))}
          </div>
        </div>
        <div className="flex flex-col gap-1">
          <Label className="text-xs">Severity</Label>
          <div className="flex gap-4">
            {(['warning', 'critical'] as const).map(s => (
              <label key={s} className="flex items-center gap-1.5 cursor-pointer text-sm capitalize">
                <input type="checkbox" className="h-4 w-4 accent-primary cursor-pointer"
                  checked={form.severities.includes(s)} onChange={() => toggleSeverity(s)} />
                {s}
              </label>
            ))}
          </div>
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
        <Button size="sm" onClick={() => onSave(form)}
          disabled={saving || !form.name.trim() || !form.host.trim()}>
          {saving ? 'Saving...' : 'Save'}
        </Button>
      </div>
    </div>
  )
}

export function RsyslogPage() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const toast = useToast()

  const [configs, setConfigs] = useState<RsyslogConfig[]>([])
  const [showForm, setShowForm] = useState(false)
  const [editTarget, setEditTarget] = useState<RsyslogConfig | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<RsyslogConfig | null>(null)
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState<string | null>(null)

  const load = useCallback(async () => {
    try { setConfigs(await rsyslogApi.list()) } catch { }
  }, [])

  useEffect(() => { load() }, [load])

  const handleCreate = async (form: Omit<RsyslogConfig, 'id'>) => {
    setSaving(true)
    try {
      await rsyslogApi.create(form)
      toast.success('rsyslog config created.')
      setShowForm(false); load()
    } catch { toast.error('Failed to create rsyslog config') }
    finally { setSaving(false) }
  }

  const handleUpdate = async (form: Omit<RsyslogConfig, 'id'>) => {
    if (!editTarget) return
    setSaving(true)
    try {
      await rsyslogApi.update(editTarget.id, { ...form, id: editTarget.id })
      toast.success('rsyslog config updated.')
      setEditTarget(null); load()
    } catch { toast.error('Failed to update rsyslog config') }
    finally { setSaving(false) }
  }

  const handleToggle = async (cfg: RsyslogConfig) => {
    try {
      await rsyslogApi.update(cfg.id, { ...cfg, enabled: !cfg.enabled })
      load()
    } catch { toast.error('Failed to toggle config') }
  }

  const handleDelete = async () => {
    if (!deleteTarget) return
    try {
      await rsyslogApi.delete(deleteTarget.id)
      toast.success('rsyslog config deleted.')
      setDeleteTarget(null); load()
    } catch { toast.error('Failed to delete rsyslog config') }
  }

  const handleTest = async (cfg: RsyslogConfig) => {
    setTesting(cfg.id)
    try {
      const { message } = await rsyslogApi.test({ host: cfg.host, port: cfg.port, protocol: cfg.protocol, facility: cfg.facility })
      toast.success(message)
    } catch (e: unknown) {
      const msg =
        (e as { response?: { data?: string } })?.response?.data?.trim() ||
        (e instanceof Error ? e.message : 'Connection failed')
      toast.error(msg)
    } finally { setTesting(null) }
  }

  // Creating and editing happen on a screen of their own — the list comes back
  // on save or cancel, the same way the policy pages do it.
  if (isAdmin && (showForm || editTarget)) {
    return (
      <>
        <div className="mb-6">
          <h4 className="text-xl font-semibold">
            {editTarget ? `Edit ${editTarget.name}` : 'New rsyslog Config'}
          </h4>
        </div>
        <Card className="max-w-2xl">
          <CardContent className="pt-4">
            <ConfigForm
              initial={editTarget ?? EMPTY}
              onSave={editTarget ? handleUpdate : handleCreate}
              onCancel={() => { setShowForm(false); setEditTarget(null) }}
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
          <h4 className="text-xl font-semibold">Syslog</h4>
          <p className="text-sm text-muted-foreground">Forward Security Events and Admission Events to syslog servers.</p>
        </div>
        {isAdmin && (
          <Button onClick={() => setShowForm(true)}>+ New Config</Button>
        )}
      </div>

      {configs.length === 0 && (
        <p className="py-10 text-center text-sm text-muted-foreground">No rsyslog configs configured.</p>
      )}

      <div className="flex flex-col gap-3">
        {configs.map(cfg => (
          <Card key={cfg.id} className={cfg.enabled ? '' : 'opacity-60'}>
            <CardHeader className="border-b pb-3">
              <div className="flex items-center gap-2 min-w-0">
                <span className="font-medium text-sm">{cfg.name}</span>
                <Badge variant={cfg.enabled ? 'default' : 'secondary'} className="text-[10px]">
                  {cfg.enabled ? 'Enabled' : 'Disabled'}
                </Badge>
                <Badge variant="outline" className="text-[10px] uppercase">{cfg.protocol}</Badge>
                {cfg.severities.map(s => (
                  <Badge key={s} variant={s === 'critical' ? 'destructive' : 'outline'} className="text-[10px] capitalize">{s}</Badge>
                ))}
              </div>
              {isAdmin && (
                <div className="ml-auto flex items-center gap-2 shrink-0">
                  <Button variant="ghost" size="sm" className="h-7 text-xs"
                    onClick={() => handleTest(cfg)} disabled={testing === cfg.id}>
                    {testing === cfg.id ? 'Sending...' : 'Test'}
                  </Button>
                  <Button variant="ghost" size="sm" className="h-7 text-xs"
                    onClick={() => { setEditTarget(cfg); setShowForm(false) }}>Edit</Button>
                  <Button variant="ghost" size="sm" className="h-7 text-xs"
                    onClick={() => handleToggle(cfg)}>
                    {cfg.enabled ? 'Disable' : 'Enable'}
                  </Button>
                  <Button variant="ghost" size="sm" className="h-7 text-xs text-destructive hover:text-destructive"
                    onClick={() => setDeleteTarget(cfg)}>Delete</Button>
                </div>
              )}
            </CardHeader>
            <CardContent className="pt-3 text-xs text-muted-foreground flex flex-col gap-1">
              <p className="font-mono">{cfg.host}:{cfg.port}</p>
              <div className="flex gap-4">
                <span>Namespaces: {cfg.namespaces.length ? cfg.namespaces.join(', ') : 'all'}</span>
                <span>Policies: {cfg.policies.length ? cfg.policies.join(', ') : 'all'}</span>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <AlertDialog open={!!deleteTarget} onOpenChange={open => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Syslog Config</AlertDialogTitle>
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
