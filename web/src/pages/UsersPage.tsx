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
import { userApi, settingsApi, securityRetentionApi, type UserRecord, type SecurityRetention } from '../api/client'
import { useAuth } from '../layout/AuthContext'
import { useToast } from '../layout/AppToaster'

export function UsersPage() {
  const { user: me } = useAuth()
  const toast = useToast()
  const [users, setUsers] = useState<UserRecord[]>([])
  const [showForm, setShowForm] = useState(false)
  const [newUsername, setNewUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newRole, setNewRole] = useState<'admin' | 'viewer'>('viewer')
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null)

  // Change password dialog
  const [pwTarget, setPwTarget] = useState<string | null>(null)
  const [newPw, setNewPw] = useState('')

  // Session TTL
  const [, setSessionTTL] = useState<number>(3600)
  const [ttlInput, setTtlInput] = useState<string>('3600')

  // Security Events Retention
  const [retention, setRetention] = useState<SecurityRetention>({ maxWarnings: 500, maxCriticals: 300, ttlDays: 7 })
  const [retentionSaving, setRetentionSaving] = useState(false)

  const load = useCallback(async () => {
    try { setUsers(await userApi.list()) } catch { /* ignore */ }
  }, [])

  useEffect(() => {
    load()
    settingsApi.getSessionTTL().then(({ sessionTTL: ttl }) => {
      setSessionTTL(ttl)
      setTtlInput(String(ttl))
    }).catch(() => {})
    securityRetentionApi.get().then(setRetention).catch(() => {})
  }, [load])

  const handleSaveRetention = async () => {
    setRetentionSaving(true)
    try {
      const updated = await securityRetentionApi.set(retention)
      setRetention(updated)
      toast.success('Security Events retention updated.')
    } catch { toast.error('Failed to update retention') }
    finally { setRetentionSaving(false) }
  }

  const handleSaveTTL = async () => {
    const val = parseInt(ttlInput, 10)
    if (isNaN(val) || val <= 0) { toast.error('Please enter a valid number of seconds'); return }
    try {
      await settingsApi.setSessionTTL(val)
      setSessionTTL(val)
      toast.success('Session timeout updated. Takes effect on next login.')
    } catch { toast.error('Failed to update session timeout') }
  }

  const handleCreate = async () => {
    if (!newUsername.trim() || !newPassword.trim()) return
    try {
      await userApi.create(newUsername.trim(), newPassword.trim(), newRole)
      toast.success(`User "${newUsername.trim()}" created.`)
      setShowForm(false); setNewUsername(''); setNewPassword(''); setNewRole('viewer')
      load()
    } catch { toast.error('Failed to create user') }
  }

  const handleDelete = async () => {
    if (!deleteTarget) return
    try {
      await userApi.delete(deleteTarget)
      toast.success(`User "${deleteTarget}" deleted.`)
      setDeleteTarget(null); load()
    } catch { toast.error('Failed to delete user') }
  }

  const handleChangePassword = async () => {
    if (!pwTarget || !newPw.trim()) return
    try {
      await userApi.changePassword(pwTarget, newPw.trim())
      toast.success('Password updated.')
      setPwTarget(null); setNewPw('')
    } catch { toast.error('Failed to update password') }
  }

  return (
    <>
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h4 className="text-xl font-semibold">Users</h4>
          <p className="text-sm text-muted-foreground">Local dashboard user accounts.</p>
        </div>
        {me?.role === 'admin' && (
          <Button onClick={() => setShowForm(v => !v)}>{showForm ? 'Cancel' : '+ New User'}</Button>
        )}
      </div>

      {showForm && (
        <Card className="mb-6 border-primary/40">
          <CardHeader className="border-b pb-3">
            <CardTitle className="text-sm font-medium">New User</CardTitle>
          </CardHeader>
          <CardContent className="pt-4 flex flex-col gap-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="flex flex-col gap-1">
                <Label className="text-xs">Username <span className="text-destructive">*</span></Label>
                <Input className="h-8 text-sm" value={newUsername} onChange={e => setNewUsername(e.target.value)} />
              </div>
              <div className="flex flex-col gap-1">
                <Label className="text-xs">Password <span className="text-destructive">*</span></Label>
                <Input className="h-8 text-sm" type="password" value={newPassword} onChange={e => setNewPassword(e.target.value)} />
              </div>
            </div>
            <div className="flex flex-col gap-1">
              <Label className="text-xs">Role</Label>
              <div className="flex gap-2">
                {(['viewer', 'admin'] as const).map(r => (
                  <Button key={r} size="sm" variant={newRole === r ? 'default' : 'outline'}
                    onClick={() => setNewRole(r)} className="capitalize">{r}</Button>
                ))}
              </div>
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="outline" size="sm" onClick={() => setShowForm(false)}>Cancel</Button>
              <Button size="sm" onClick={handleCreate} disabled={!newUsername.trim() || !newPassword.trim()}>Create</Button>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="flex flex-col gap-2">
        {users.map(u => (
          <Card key={u.username}>
            <CardContent className="flex items-center justify-between py-3">
              <div className="flex items-center gap-3">
                <span className="font-medium text-sm">{u.username}</span>
                <Badge variant={u.role === 'admin' ? 'default' : 'secondary'} className="text-[10px] capitalize">{u.role}</Badge>
                {u.username === me?.username && (
                  <Badge variant="outline" className="text-[10px]">You</Badge>
                )}
              </div>
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <span>{new Date(u.createdAt).toLocaleDateString()}</span>
                <Button variant="ghost" size="sm" className="text-xs h-7"
                  onClick={() => { setPwTarget(u.username); setNewPw('') }}>
                  Change Password
                </Button>
                {me?.role === 'admin' && u.username !== me?.username && (
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
                  disabled={me?.role !== 'admin'}
                  onKeyDown={e => e.key === 'Enter' && handleSaveTTL()}
                />
              </div>
            </div>
            {me?.role === 'admin' && (
              <Button size="sm" className="mt-4" onClick={handleSaveTTL}>Save</Button>
            )}
          </div>
          <p className="mt-2 text-xs text-muted-foreground">Changes take effect on the next login. Active sessions are not affected.</p>
        </CardContent>
      </Card>

      {/* Security Events Retention */}
      <Card className="mt-6">
        <CardHeader className="border-b pb-3">
          <CardTitle className="text-sm font-medium">Security Events Retention</CardTitle>
        </CardHeader>
        <CardContent className="pt-4 flex flex-col gap-4">
          <div className="grid grid-cols-3 gap-4">
            <div className="flex flex-col gap-1">
              <Label className="text-xs text-muted-foreground">Max Warning Events</Label>
              <Input className="h-8 text-sm" type="number" min={1} max={5000}
                value={retention.maxWarnings}
                onChange={e => setRetention(r => ({ ...r, maxWarnings: Math.max(1, parseInt(e.target.value) || 1) }))}
                disabled={me?.role !== 'admin'} />
            </div>
            <div className="flex flex-col gap-1">
              <Label className="text-xs text-muted-foreground">Max Critical Events</Label>
              <Input className="h-8 text-sm" type="number" min={1} max={2000}
                value={retention.maxCriticals}
                onChange={e => setRetention(r => ({ ...r, maxCriticals: Math.max(1, parseInt(e.target.value) || 1) }))}
                disabled={me?.role !== 'admin'} />
            </div>
            <div className="flex flex-col gap-1">
              <Label className="text-xs text-muted-foreground">TTL (days)</Label>
              <Input className="h-8 text-sm" type="number" min={1} max={90}
                value={retention.ttlDays}
                onChange={e => setRetention(r => ({ ...r, ttlDays: Math.max(1, parseInt(e.target.value) || 1) }))}
                disabled={me?.role !== 'admin'} />
            </div>
          </div>
          <div className="flex items-center justify-between">
            <p className="text-xs text-muted-foreground">
              Total capacity: {retention.maxWarnings + retention.maxCriticals} events · Data older than {retention.ttlDays} day{retention.ttlDays !== 1 ? 's' : ''} is purged automatically.
            </p>
            {me?.role === 'admin' && (
              <Button size="sm" onClick={handleSaveRetention} disabled={retentionSaving}>
                {retentionSaving ? 'Saving...' : 'Save'}
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Delete confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete User</AlertDialogTitle>
            <AlertDialogDescription>Delete "{deleteTarget}"? This cannot be undone.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction variant="destructive" onClick={handleDelete}>Delete</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Change password dialog */}
      <AlertDialog open={!!pwTarget} onOpenChange={(open) => !open && setPwTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Change Password</AlertDialogTitle>
            <AlertDialogDescription>Set a new password for "{pwTarget}".</AlertDialogDescription>
          </AlertDialogHeader>
          <div className="flex flex-col gap-1.5 py-2">
            <Label>New Password</Label>
            <Input type="password" value={newPw} onChange={e => setNewPw(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleChangePassword()} />
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleChangePassword} disabled={!newPw.trim()}>Update</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
