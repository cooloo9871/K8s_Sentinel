import { useCallback, useEffect, useState } from 'react'
import { useMatch, useNavigate } from 'react-router-dom'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import { userApi, roleApi, settingsApi, namespaceApi, type UserRecord } from '../api/client'
import { useAuth } from '../layout/AuthContext'
import { useToast } from '../layout/AppToaster'

const MIN_PASSWORD_LENGTH = 8

// What an account may reach: the whole cluster, or some namespaces. Limited to
// namespaces it sees only what is in them and nothing that is the cluster's
// (cluster-wide policies, admission policies, settings, other accounts).
// The roles are few and their names are the user's own, so a built-in one is
// shown with a capital and the rest as they were typed.
const BUILT_IN = ['admin', 'viewer']

function RoleSelect({ value, onChange, roles }: { value: string; onChange: (v: string) => void; roles: string[] }) {
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger className="h-8 w-56 text-sm"><SelectValue /></SelectTrigger>
      <SelectContent>
        <SelectGroup>
          {roles.map(r => (
            <SelectItem key={r} value={r} className={BUILT_IN.includes(r) ? 'capitalize' : ''}>{r}</SelectItem>
          ))}
        </SelectGroup>
      </SelectContent>
    </Select>
  )
}

function AccessPicker({ limited, onLimited, chosen, onChosen, namespaces }: {
  limited: boolean
  onLimited: (v: boolean) => void
  chosen: string[]
  onChosen: (v: string[]) => void
  namespaces: string[]
}) {
  // A namespace the account was given and that has since been deleted is
  // still listed, so it can be seen and unticked.
  const all = [...new Set([...namespaces, ...chosen])].sort()
  return (
    <div className="flex flex-col gap-2">
      <div className="flex gap-2">
        <Button size="sm" variant={!limited ? 'default' : 'outline'} onClick={() => onLimited(false)}>Whole cluster</Button>
        <Button size="sm" variant={limited ? 'default' : 'outline'} onClick={() => onLimited(true)}>Selected namespaces</Button>
      </div>
      {limited && (
        <>
          <div className="max-h-48 overflow-y-auto rounded-md border p-2">
            {all.length === 0 && <p className="text-xs text-muted-foreground">No namespaces available</p>}
            {all.map(ns => (
              <label key={ns} className="flex cursor-pointer items-center gap-2 py-1 text-sm">
                <Checkbox
                  checked={chosen.includes(ns)}
                  onCheckedChange={on => onChosen(on ? [...chosen, ns] : chosen.filter(x => x !== ns))}
                />
                <span className="font-mono text-xs">{ns}</span>
              </label>
            ))}
          </div>
          <p className="text-[11px] text-muted-foreground">
            Sees and manages only what is in these namespaces. Cluster-wide policies, admission
            policies, registries, settings and other accounts are hidden. The Network Topology
            stays whole.
          </p>
        </>
      )}
    </div>
  )
}

export function UsersPage() {
  const { user: me, can } = useAuth()
  const canManage = can('system', 'manage')
  const toast = useToast()
  const navigate = useNavigate()
  // The create screen is a route, so Back returns to the list, F5 stays on the
  // form, and the sidebar link works while it is open.
  const showForm = !!useMatch('/settings/users/new')
  const [users, setUsers] = useState<UserRecord[]>([])
  const [newUsername, setNewUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newRole, setNewRole] = useState('viewer')
  const [roles, setRoles] = useState<string[]>(BUILT_IN)
  const [newLimited, setNewLimited] = useState(false)
  const [newNamespaces, setNewNamespaces] = useState<string[]>([])
  const [namespaces, setNamespaces] = useState<string[]>([])
  const [creating, setCreating] = useState(false)

  // Access dialog: which account, and the choice being made for it.
  const [accessTarget, setAccessTarget] = useState<string | null>(null)
  const [accessRole, setAccessRole] = useState('viewer')
  const [accessLimited, setAccessLimited] = useState(false)
  const [accessNamespaces, setAccessNamespaces] = useState<string[]>([])
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null)

  // Change password dialog
  const [pwTarget, setPwTarget] = useState<string | null>(null)
  const [newPw, setNewPw] = useState('')
  const [currentPw, setCurrentPw] = useState('')

  // Session TTL
  const [, setSessionTTL] = useState<number>(3600)
  const [ttlInput, setTtlInput] = useState<string>('3600')

  const load = useCallback(async () => {
    try { setUsers(await userApi.list()) } catch { /* ignore */ }
  }, [])

  useEffect(() => {
    load()
    namespaceApi.list().then(setNamespaces).catch(() => {})
    roleApi.list().then(rs => setRoles(rs.map(r => r.name))).catch(() => {})
    settingsApi.getSessionTTL().then(({ sessionTTL: ttl }) => {
      setSessionTTL(ttl)
      setTtlInput(String(ttl))
    }).catch(() => {})
  }, [load])

  const handleSaveTTL = async () => {
    const val = parseInt(ttlInput, 10)
    if (isNaN(val) || val <= 0) { toast.error('Please enter a valid number of seconds'); return }
    try {
      await settingsApi.setSessionTTL(val)
      setSessionTTL(val)
      toast.success('Session timeout updated. Takes effect on next login.')
    } catch { toast.error('Failed to update session timeout') }
  }

  // The one place the form closes, so the typed password never outlives it;
  // cancelling must not leave credentials sitting in component state.
  const closeForm = () => {
    setNewUsername(''); setNewPassword(''); setNewRole('viewer')
    setNewLimited(false); setNewNamespaces([])
    navigate('/settings/users')
  }

  // A deep link from an account that cannot create users goes back.
  useEffect(() => {
    if (showForm && me && !canManage) {
      navigate('/settings/users', { replace: true })
    }
  }, [showForm, me, canManage, navigate])

  const handleCreate = async () => {
    if (!newUsername.trim() || !newPassword || creating) return
    if (newPassword.length < MIN_PASSWORD_LENGTH) {
      toast.error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`); return
    }
    setCreating(true)
    try {
      await userApi.create(newUsername.trim(), newPassword, newRole, newLimited ? newNamespaces : [])
      toast.success(`User "${newUsername.trim()}" created.`)
      closeForm()
      load()
    } catch { toast.error('Failed to create user') }
    finally { setCreating(false) }
  }

  const handleDelete = async () => {
    if (!deleteTarget) return
    try {
      await userApi.delete(deleteTarget)
      toast.success(`User "${deleteTarget}" deleted.`)
      setDeleteTarget(null); load()
    } catch (err: unknown) {
      const data = (err as { response?: { data?: unknown } }).response?.data
      toast.error(typeof data === 'string' && data.trim() ? data.trim() : 'Failed to delete user')
    }
  }

  const handleSaveAccess = async () => {
    if (!accessTarget) return
    const before = users.find(u => u.username === accessTarget)
    try {
      if (before?.role !== accessRole) await userApi.setRole(accessTarget, accessRole)
      await userApi.setNamespaces(accessTarget, accessLimited ? accessNamespaces : [])
      toast.success(`Access of "${accessTarget}" updated.`)
      setAccessTarget(null)
    } catch (err: unknown) {
      // The server says why, for one: the last full admin has to stay one.
      const data = (err as { response?: { data?: unknown } }).response?.data
      toast.error(typeof data === 'string' && data.trim() ? data.trim() : 'Failed to update access')
    }
    load()
  }

  // Changing your own password requires the current one; an admin resetting
  // someone else's does not. The backend enforces both — this mirrors it.
  const changingOwn = pwTarget === me?.username

  const handleChangePassword = async () => {
    if (!pwTarget || !newPw) return
    if (newPw.length < MIN_PASSWORD_LENGTH) {
      toast.error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`); return
    }
    if (changingOwn && !currentPw) {
      toast.error('Enter your current password.'); return
    }
    try {
      await userApi.changePassword(pwTarget, newPw, changingOwn ? currentPw : undefined)
      toast.success('Password updated.')
      setPwTarget(null); setNewPw(''); setCurrentPw('')
    } catch (err: unknown) {
      const status = (err as { response?: { status?: number } }).response?.status
      toast.error(status === 403 ? 'Current password is incorrect.' : 'Failed to update password')
    }
  }

  // Creating happens on a screen of its own — the list comes back on save or
  // cancel, the same way the Network Policy editor does it.
  if (showForm) {
    return (
      <>
        <div className="mb-6">
          <h4 className="text-xl font-semibold">New User</h4>
        </div>
        <Card className="max-w-2xl">
          <CardContent className="pt-4 flex flex-col gap-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="flex flex-col gap-1">
                <Label className="text-xs">Username <span className="text-destructive">*</span></Label>
                <Input className="h-8 text-sm" value={newUsername} onChange={e => setNewUsername(e.target.value)} />
              </div>
              <div className="flex flex-col gap-1">
                <Label className="text-xs">Password <span className="text-destructive">*</span></Label>
                <Input className="h-8 text-sm" type="password" autoComplete="new-password" value={newPassword} onChange={e => setNewPassword(e.target.value)} />
                <p className="text-[11px] text-muted-foreground">At least {MIN_PASSWORD_LENGTH} characters.</p>
              </div>
            </div>
            <div className="flex flex-col gap-1">
              <Label className="text-xs">Role</Label>
              <RoleSelect value={newRole} onChange={setNewRole} roles={roles} />
            </div>
            <div className="flex flex-col gap-1">
              <Label className="text-xs">Access</Label>
              <AccessPicker limited={newLimited} onLimited={setNewLimited}
                chosen={newNamespaces} onChosen={setNewNamespaces} namespaces={namespaces} />
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="outline" size="sm" onClick={closeForm} disabled={creating}>Cancel</Button>
              <Button size="sm" onClick={handleCreate}
                disabled={creating || !newUsername.trim() || !newPassword || (newLimited && newNamespaces.length === 0)}>
                {creating ? 'Creating...' : 'Create'}
              </Button>
            </div>
          </CardContent>
        </Card>
      </>
    )
  }

  return (
    <>
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h4 className="text-xl font-semibold">Users</h4>
        </div>
        {canManage && (
          <Button onClick={() => navigate('/settings/users/new')}>+ New User</Button>
        )}
      </div>

      <div className="flex flex-col gap-2">
        {users.map(u => (
          <Card key={u.username}>
            <CardContent className="flex items-center justify-between py-3">
              <div className="flex items-center gap-3">
                <span className="font-medium text-sm">{u.username}</span>
                <Badge variant={u.role === 'admin' ? 'default' : 'secondary'} className={`text-[10px] ${BUILT_IN.includes(u.role) ? 'capitalize' : ''}`}>{u.role}</Badge>
                {u.username === me?.username && (
                  <Badge variant="outline" className="text-[10px]">You</Badge>
                )}
                {u.namespaces.map(ns => (
                  <Badge key={ns} variant="outline" className="font-mono text-[10px]">{ns}</Badge>
                ))}
              </div>
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <span>{new Date(u.createdAt).toLocaleDateString()}</span>
                {(canManage || u.username === me?.username) && (
                  <Button variant="ghost" size="sm" className="text-xs h-7"
                    onClick={() => { setPwTarget(u.username); setNewPw('') }}>
                    Change Password
                  </Button>
                )}
                {canManage && u.username !== me?.username && (
                  <Button variant="ghost" size="sm" className="text-xs h-7"
                    onClick={() => {
                      setAccessTarget(u.username)
                      setAccessRole(u.role)
                      setAccessLimited(u.namespaces.length > 0)
                      setAccessNamespaces(u.namespaces)
                    }}>
                    Access
                  </Button>
                )}
                {canManage && u.username !== me?.username && (
                  <Button variant="ghost" size="sm" className="text-xs h-7 text-destructive hover:text-destructive"
                    onClick={() => setDeleteTarget(u.username)}>
                    Delete
                  </Button>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Session Timeout */}
      <Card className="mt-6">
        <CardHeader className="border-b pb-3">
          <CardTitle className="text-sm font-medium">Session Timeout</CardTitle>
        </CardHeader>
        <CardContent className="pt-4">
          <div className="flex items-center gap-3">
            <div className="flex flex-col gap-1">
              <Label className="text-xs text-muted-foreground">Timeout (seconds)</Label>
              <div className="flex items-center gap-2">
                <Input
                  className="h-8 text-sm w-32"
                  value={ttlInput}
                  onChange={e => setTtlInput(e.target.value)}
                  disabled={!canManage}
                  onKeyDown={e => e.key === 'Enter' && handleSaveTTL()}
                />
              </div>
            </div>
            {canManage && (
              <Button size="sm" className="mt-4" onClick={handleSaveTTL}>Save</Button>
            )}
          </div>
          <p className="mt-2 text-xs text-muted-foreground">Changes take effect on the next login. Active sessions are not affected.</p>
        </CardContent>
      </Card>

      {/* Delete confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete User</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete <strong>{deleteTarget}</strong>?
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction variant="destructive" onClick={handleDelete}>Delete</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Access dialog */}
      <AlertDialog open={!!accessTarget} onOpenChange={(open) => !open && setAccessTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Access</AlertDialogTitle>
            <AlertDialogDescription>What "{accessTarget}" may reach. Takes effect at once.</AlertDialogDescription>
          </AlertDialogHeader>
          <div className="flex flex-col gap-1">
            <Label className="text-xs">Role</Label>
            <RoleSelect value={accessRole} onChange={setAccessRole} roles={roles} />
          </div>
          <AccessPicker limited={accessLimited} onLimited={setAccessLimited}
            chosen={accessNamespaces} onChosen={setAccessNamespaces} namespaces={namespaces} />
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleSaveAccess}
              disabled={accessLimited && accessNamespaces.length === 0}>Save</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Change password dialog */}
      <AlertDialog open={!!pwTarget} onOpenChange={(open) => { if (!open) { setPwTarget(null); setNewPw(''); setCurrentPw('') } }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Change Password</AlertDialogTitle>
            <AlertDialogDescription>Set a new password for "{pwTarget}".</AlertDialogDescription>
          </AlertDialogHeader>
          {changingOwn && (
            <div className="flex flex-col gap-1.5 py-2">
              <Label>Current Password</Label>
              <Input type="password" autoComplete="current-password" value={currentPw} onChange={e => setCurrentPw(e.target.value)} />
            </div>
          )}
          <div className="flex flex-col gap-1.5 py-2">
            <Label>New Password</Label>
            <Input type="password" autoComplete="new-password" value={newPw} onChange={e => setNewPw(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleChangePassword()} />
            <p className="text-xs text-muted-foreground">At least {MIN_PASSWORD_LENGTH} characters.</p>
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleChangePassword}
              disabled={newPw.length < MIN_PASSWORD_LENGTH || (changingOwn && !currentPw)}
            >Update</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
