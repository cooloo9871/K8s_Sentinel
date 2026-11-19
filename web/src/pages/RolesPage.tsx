import { useCallback, useEffect, useState } from 'react'
import { useMatch, useNavigate, useParams } from 'react-router-dom'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { roleApi, AREAS, type Area, type Level, type Permissions, type RoleRecord } from '../api/client'
import { useAuth } from '../layout/AuthContext'
import { useToast } from '../layout/AppToaster'

const BASE = '/settings/roles'

// What each area is called and which pages it covers. The pages are named
// because the area's own name does not say all of them.
const AREA_INFO: Record<Area, { label: string; pages: string }> = {
  tracing: { label: 'Tracing Policy', pages: 'Tracing Policy, Templates, Behavior Discovery' },
  network: { label: 'Network Policy', pages: 'Network Policy, Network Topology' },
  admission: { label: 'Admission Policy', pages: 'Admission Policy, Bindings' },
  quarantine: { label: 'Quarantine', pages: 'Quarantine and release of pods' },
  events: { label: 'Events', pages: 'Security Events, Admission Events, Event Sources' },
  vulnerabilities: { label: 'Vulnerabilities', pages: 'Workloads, Registries' },
  notifications: { label: 'Notifications', pages: 'Alerts, Syslog' },
  system: { label: 'System', pages: 'Users, Roles, Audit Log, Event Retention, Session Timeout' },
}

const LEVELS: { value: Level; label: string }[] = [
  { value: 'none', label: 'None' },
  { value: 'view', label: 'View' },
  { value: 'manage', label: 'Manage' },
]

const NOTHING = Object.fromEntries(AREAS.map(a => [a, 'none'])) as Permissions

// What the server said, when it said something a person can act on.
function reason(err: unknown, fallback: string): string {
  const data = (err as { response?: { data?: unknown } }).response?.data
  if (typeof data === 'string' && data.trim()) return data.trim()
  const msg = (data as { error?: string } | undefined)?.error
  return msg || fallback
}

function summary(p: Permissions): string {
  const manage = AREAS.filter(a => p[a] === 'manage').map(a => AREA_INFO[a].label)
  const view = AREAS.filter(a => p[a] === 'view').map(a => AREA_INFO[a].label)
  if (manage.length === AREAS.length) return 'Manages everything'
  const parts = []
  if (manage.length) parts.push(`Manages ${manage.join(', ')}`)
  if (view.length) parts.push(`Views ${view.join(', ')}`)
  return parts.join(' · ') || 'No permissions'
}

function RoleForm({ initial, readOnly, onSave, onCancel }: {
  initial: RoleRecord | null
  readOnly: boolean
  onSave: (name: string, permissions: Permissions) => Promise<void>
  onCancel: () => void
}) {
  const [name, setName] = useState(initial?.name ?? '')
  const [perms, setPerms] = useState<Permissions>({ ...NOTHING, ...initial?.permissions })
  const [saving, setSaving] = useState(false)

  const save = async () => {
    setSaving(true)
    try { await onSave(name.trim(), perms) } finally { setSaving(false) }
  }

  return (
    <Card className="max-w-3xl">
      <CardContent className="flex flex-col gap-4 pt-4">
        {!initial && (
          <div className="flex flex-col gap-1">
            <Label className="text-xs">Name <span className="text-destructive">*</span></Label>
            <Input className="h-8 w-72 text-sm" value={name} maxLength={40} onChange={e => setName(e.target.value)} />
          </div>
        )}
        <div className="flex flex-col divide-y rounded-lg border">
          {AREAS.map(area => (
            <div key={area} className="flex items-center justify-between gap-4 px-3 py-2.5">
              <div className="min-w-0">
                <p className="text-sm font-medium">{AREA_INFO[area].label}</p>
                <p className="text-xs text-muted-foreground">{AREA_INFO[area].pages}</p>
              </div>
              <div className="flex shrink-0 gap-1" role="radiogroup" aria-label={AREA_INFO[area].label}>
                {LEVELS.map(l => (
                  <Button
                    key={l.value}
                    size="sm"
                    role="radio"
                    aria-checked={perms[area] === l.value}
                    variant={perms[area] === l.value ? 'default' : 'outline'}
                    disabled={readOnly}
                    className="h-7 w-20 text-xs"
                    onClick={() => setPerms(p => ({ ...p, [area]: l.value }))}
                  >
                    {l.label}
                  </Button>
                ))}
              </div>
            </div>
          ))}
        </div>
        {!readOnly && perms.system === 'manage' && (
          <p className="text-xs text-amber-600">
            Managing System includes giving any account any role, this one's holders included.
          </p>
        )}
        <div className="flex justify-end gap-2">
          <Button variant="outline" size="sm" onClick={onCancel} disabled={saving}>{readOnly ? 'Back' : 'Cancel'}</Button>
          {!readOnly && (
            <Button size="sm" onClick={save} disabled={saving || (!initial && !name.trim())}>
              {saving ? 'Saving...' : initial ? 'Save' : 'Create'}
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  )
}

export function RolesPage() {
  const { can } = useAuth()
  const canManage = can('system', 'manage')
  const toast = useToast()
  const navigate = useNavigate()
  const isNew = !!useMatch(`${BASE}/new`)
  const { name: editName } = useParams()
  const [roles, setRoles] = useState<RoleRecord[] | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<RoleRecord | null>(null)

  const load = useCallback(async () => {
    try { setRoles(await roleApi.list()) } catch { toast.error('Failed to load roles') }
  }, [])

  useEffect(() => { load() }, [load])

  // A deep link from an account that cannot create roles goes back.
  useEffect(() => {
    if (isNew && !canManage) navigate(BASE, { replace: true })
  }, [isNew, canManage, navigate])

  const handleCreate = async (name: string, permissions: Permissions) => {
    try {
      await roleApi.create(name, permissions)
      toast.success(`Role "${name}" created.`)
      await load()
      navigate(BASE)
    } catch (err) { toast.error(reason(err, 'Failed to create role')) }
  }

  const handleUpdate = async (name: string, permissions: Permissions) => {
    try {
      await roleApi.update(name, permissions)
      toast.success(`Role "${name}" updated.`)
      await load()
      navigate(BASE)
    } catch (err) { toast.error(reason(err, 'Failed to update role')) }
  }

  const handleDelete = async () => {
    if (!deleteTarget) return
    try {
      await roleApi.delete(deleteTarget.name)
      toast.success(`Role "${deleteTarget.name}" deleted.`)
    } catch (err) { toast.error(reason(err, 'Failed to delete role')) }
    setDeleteTarget(null)
    load()
  }

  if (isNew && canManage) {
    return (
      <>
        <div className="mb-6"><h4 className="text-xl font-semibold">New Role</h4></div>
        <RoleForm initial={null} readOnly={false} onSave={handleCreate} onCancel={() => navigate(BASE)} />
      </>
    )
  }

  if (editName) {
    // A deep-linked edit needs the list before it can show the role.
    if (!roles) return null
    const target = roles.find(r => r.name === editName)
    if (!target) {
      return <p className="py-10 text-center text-sm text-muted-foreground">There is no role named "{editName}".</p>
    }
    const readOnly = target.builtIn || !canManage
    return (
      <>
        <div className="mb-6">
          <h4 className={`text-xl font-semibold ${target.builtIn ? 'capitalize' : ''}`}>
            {readOnly ? 'View' : 'Edit'} {target.name}
          </h4>
        </div>
        <RoleForm key={target.name} initial={target} readOnly={readOnly} onSave={handleUpdate} onCancel={() => navigate(BASE)} />
      </>
    )
  }

  return (
    <>
      <div className="mb-6 flex items-start justify-between">
        <h4 className="text-xl font-semibold">Roles</h4>
        {canManage && <Button onClick={() => navigate(`${BASE}/new`)}>+ New Role</Button>}
      </div>
      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Permissions</TableHead>
                <TableHead>Accounts</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(roles ?? []).map(r => (
                <TableRow key={r.name}>
                  <TableCell className="font-medium">
                    <span className={r.builtIn ? 'capitalize' : ''}>{r.name}</span>
                    {r.builtIn && <Badge variant="outline" className="ml-2 text-[10px]">Built-in</Badge>}
                  </TableCell>
                  <TableCell className="max-w-md whitespace-normal text-sm text-muted-foreground">{summary(r.permissions)}</TableCell>
                  <TableCell>{r.users}</TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-2">
                      <Button variant="outline" size="sm" onClick={() => navigate(`${BASE}/${encodeURIComponent(r.name)}/edit`)}>
                        {r.builtIn || !canManage ? 'View' : 'Edit'}
                      </Button>
                      {canManage && !r.builtIn && (
                        <Button variant="destructive" size="sm" onClick={() => setDeleteTarget(r)}>Delete</Button>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Role</AlertDialogTitle>
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
