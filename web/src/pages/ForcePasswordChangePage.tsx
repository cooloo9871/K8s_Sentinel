import { useState } from 'react'
import { Card, CardHeader, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { userApi } from '../api/client'
import logoUrl from '../assets/sentinel-lockup-light.svg'

const MIN_PASSWORD_LENGTH = 8

// Shown when the signed-in user still carries the "must change password" flag —
// the default admin account after its first login. The rest of the app is
// gated behind it until a new password is set, so this is a full-screen step
// rather than a dialog.
interface Props {
  username: string
  onDone: () => void
}

export function ForcePasswordChangePage({ username, onDone }: Props) {
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)

  const tooShort = newPassword.length > 0 && newPassword.length < MIN_PASSWORD_LENGTH
  const mismatch = confirm.length > 0 && confirm !== newPassword
  const canSubmit =
    !!currentPassword && newPassword.length >= MIN_PASSWORD_LENGTH &&
    confirm === newPassword && !saving

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!canSubmit) return
    setError('')
    setSaving(true)
    try {
      await userApi.changePassword(username, newPassword, currentPassword)
      onDone()
    } catch (err: unknown) {
      const status = (err as { response?: { status?: number } }).response?.status
      setError(status === 403
        ? 'Current password is incorrect.'
        : 'Could not update the password. Please try again.')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <Card className="w-full max-w-md">
        <CardHeader className="flex items-center px-8 pt-8 pb-2">
          <img src={logoUrl} alt="K8s Sentinel" className="w-full" />
        </CardHeader>
        <CardContent className="px-8 pb-8">
          <p className="mb-4 text-sm text-muted-foreground">
            Set a new password for <span className="font-medium text-foreground">{username}</span> before continuing.
            It must be at least {MIN_PASSWORD_LENGTH} characters.
          </p>
          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="current">Current password</Label>
              <Input
                id="current"
                type="password"
                autoFocus
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                disabled={saving}
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="new">New password</Label>
              <Input
                id="new"
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                disabled={saving}
              />
              {tooShort && (
                <p className="text-xs text-destructive">At least {MIN_PASSWORD_LENGTH} characters.</p>
              )}
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="confirm">Confirm new password</Label>
              <Input
                id="confirm"
                type="password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                disabled={saving}
              />
              {mismatch && (
                <p className="text-xs text-destructive">Passwords do not match.</p>
              )}
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
            <Button type="submit" disabled={!canSubmit}>
              {saving ? 'Saving...' : 'Set password and continue'}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
