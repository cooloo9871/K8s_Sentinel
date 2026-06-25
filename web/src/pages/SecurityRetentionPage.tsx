import { useEffect, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { securityRetentionApi, type SecurityRetention } from '../api/client'
import { useAuth } from '../layout/AuthContext'
import { useToast } from '../layout/AppToaster'

export function SecurityRetentionPage() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const toast = useToast()

  const [retention, setRetention] = useState<SecurityRetention>({
    maxWarnings: 500,
    maxCriticals: 300,
    ttlDays: 7,
  })
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    securityRetentionApi.get().then(setRetention).catch(() => {})
  }, [])

  const handleSave = async () => {
    setSaving(true)
    try {
      const updated = await securityRetentionApi.set(retention)
      setRetention(updated)
      toast.success('Retention settings updated.')
    } catch {
      toast.error('Failed to update retention settings.')
    } finally {
      setSaving(false)
    }
  }

  return (
    <>
      <div className="mb-6">
        <h4 className="text-xl font-semibold">Security Events Retention</h4>
        <p className="text-sm text-muted-foreground">
          Configure how many Security Events are kept and for how long.
        </p>
      </div>

      <Card className="max-w-xl">
        <CardHeader className="border-b pb-3">
          <CardTitle className="text-sm font-medium">Retention Limits</CardTitle>
        </CardHeader>
        <CardContent className="pt-5 flex flex-col gap-5">
          <div className="flex flex-col gap-1.5">
            <Label>Max Warning Events</Label>
            <div className="flex items-center gap-3">
              <Input
                type="number" min={1} max={5000}
                value={retention.maxWarnings}
                onChange={e => setRetention(r => ({ ...r, maxWarnings: Math.max(1, parseInt(e.target.value) || 1) }))}
                className="h-8 w-36 text-sm"
                disabled={!isAdmin}
              />
              <span className="text-xs text-muted-foreground">1 – 5000</span>
            </div>
          </div>

          <div className="flex flex-col gap-1.5">
            <Label>Max Critical Events</Label>
            <div className="flex items-center gap-3">
              <Input
                type="number" min={1} max={2000}
                value={retention.maxCriticals}
                onChange={e => setRetention(r => ({ ...r, maxCriticals: Math.max(1, parseInt(e.target.value) || 1) }))}
                className="h-8 w-36 text-sm"
                disabled={!isAdmin}
              />
              <span className="text-xs text-muted-foreground">1 – 2000</span>
            </div>
          </div>

          <div className="flex flex-col gap-1.5">
            <Label>TTL (days)</Label>
            <div className="flex items-center gap-3">
              <Input
                type="number" min={1} max={90}
                value={retention.ttlDays}
                onChange={e => setRetention(r => ({ ...r, ttlDays: Math.max(1, parseInt(e.target.value) || 1) }))}
                className="h-8 w-36 text-sm"
                disabled={!isAdmin}
              />
              <span className="text-xs text-muted-foreground">1 – 90 days</span>
            </div>
            <p className="text-xs text-muted-foreground">Events older than this are removed automatically.</p>
          </div>

          <div className="rounded-md bg-muted/40 px-4 py-3 text-sm">
            <span className="font-medium">Total capacity:</span>{' '}
            {retention.maxWarnings + retention.maxCriticals} events
            {' '}·{' '}
            <span className="font-medium">TTL:</span> {retention.ttlDays} day{retention.ttlDays !== 1 ? 's' : ''}
          </div>

          {isAdmin && (
            <div className="flex justify-end">
              <Button size="sm" onClick={handleSave} disabled={saving}>
                {saving ? 'Saving...' : 'Save'}
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </>
  )
}
