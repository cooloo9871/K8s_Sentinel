import { useEffect, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import {
  securityRetentionApi, type SecurityRetention,
  admissionRetentionApi, type AdmissionRetention,
} from '../api/client'
import { useAuth } from '../layout/AuthContext'
import { useToast } from '../layout/AppToaster'
import { useSecurityEvents } from '../layout/SecurityEventsProvider'
import { useAdmissionRetention } from '../layout/AdmissionRetentionContext'

export function SecurityRetentionPage() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const toast = useToast()
  const { applyRetention } = useSecurityEvents()
  const { applyRetention: applyAdmissionRetention } = useAdmissionRetention()

  const [security, setSecurity] = useState<SecurityRetention | null>(null)
  const [admission, setAdmission] = useState<AdmissionRetention | null>(null)
  const [secError, setSecError] = useState(false)
  const [admError, setAdmError] = useState(false)
  const [savingSec, setSavingSec] = useState(false)
  const [savingAdm, setSavingAdm] = useState(false)

  const fetchAll = () => {
    setSecError(false)
    setAdmError(false)
    securityRetentionApi.get().then(setSecurity).catch(() => setSecError(true))
    admissionRetentionApi.get().then(setAdmission).catch(() => setAdmError(true))
  }

  useEffect(() => { fetchAll() }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const handleSaveSecurity = async () => {
    if (!security) return
    setSavingSec(true)
    try {
      const updated = await securityRetentionApi.set(security)
      setSecurity(updated)
      applyRetention(updated.maxWarnings, updated.maxCriticals)
      toast.success('Security Events retention updated.')
    } catch {
      toast.error('Failed to update Security Events retention.')
    } finally {
      setSavingSec(false)
    }
  }

  const handleSaveAdmission = async () => {
    if (!admission) return
    setSavingAdm(true)
    try {
      const updated = await admissionRetentionApi.set(admission)
      setAdmission(updated)
      applyAdmissionRetention(updated.maxEvents)
      toast.success('Admission Events retention updated.')
    } catch {
      toast.error('Failed to update Admission Events retention.')
    } finally {
      setSavingAdm(false)
    }
  }

  return (
    <>
      <div className="mb-6">
        <h4 className="text-xl font-semibold">Event Retention</h4>
        <p className="text-sm text-muted-foreground">
          Configure how many events are kept for Security Events and Admission Events.
        </p>
      </div>

      <Tabs defaultValue="security" className="max-w-xl">
        <TabsList className="mb-4">
          <TabsTrigger value="security">Security Events</TabsTrigger>
          <TabsTrigger value="admission">Admission Events</TabsTrigger>
        </TabsList>

        <TabsContent value="security">
          <Card>
            <CardHeader className="border-b pb-3">
              <CardTitle className="text-sm font-medium">Security Events Retention</CardTitle>
            </CardHeader>
            <CardContent className="pt-5 flex flex-col gap-5">
              {secError ? (
                <div className="flex flex-col gap-3">
                  <p className="text-sm text-destructive">Failed to load retention settings.</p>
                  <Button size="sm" variant="outline" className="w-fit" onClick={fetchAll}>Retry</Button>
                </div>
              ) : !security ? (
                <div className="text-sm text-muted-foreground">Loading…</div>
              ) : (<>
                <div className="flex flex-col gap-1.5">
                  <Label>Max Warning Events</Label>
                  <div className="flex items-center gap-3">
                    <Input
                      type="number" min={1} max={5000}
                      value={security.maxWarnings}
                      onChange={e => setSecurity(r => r && ({ ...r, maxWarnings: Math.max(1, parseInt(e.target.value) || 1) }))}
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
                      value={security.maxCriticals}
                      onChange={e => setSecurity(r => r && ({ ...r, maxCriticals: Math.max(1, parseInt(e.target.value) || 1) }))}
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
                      value={security.ttlDays}
                      onChange={e => setSecurity(r => r && ({ ...r, ttlDays: Math.max(1, parseInt(e.target.value) || 1) }))}
                      className="h-8 w-36 text-sm"
                      disabled={!isAdmin}
                    />
                    <span className="text-xs text-muted-foreground">1 – 90 days</span>
                  </div>
                  <p className="text-xs text-muted-foreground">Events older than this are removed automatically.</p>
                </div>

                <div className="rounded-md bg-muted/40 px-4 py-3 text-sm">
                  <span className="font-medium">Total capacity:</span>{' '}
                  {security.maxWarnings + security.maxCriticals} events
                  {' '}·{' '}
                  <span className="font-medium">TTL:</span> {security.ttlDays} day{security.ttlDays !== 1 ? 's' : ''}
                </div>

                {isAdmin && (
                  <div className="flex justify-end">
                    <Button size="sm" onClick={handleSaveSecurity} disabled={savingSec}>
                      {savingSec ? 'Saving...' : 'Save'}
                    </Button>
                  </div>
                )}
              </>)}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="admission">
          <Card>
            <CardHeader className="border-b pb-3">
              <CardTitle className="text-sm font-medium">Admission Events Retention</CardTitle>
            </CardHeader>
            <CardContent className="pt-5 flex flex-col gap-5">
              {admError ? (
                <div className="flex flex-col gap-3">
                  <p className="text-sm text-destructive">Failed to load retention settings.</p>
                  <Button size="sm" variant="outline" className="w-fit" onClick={fetchAll}>Retry</Button>
                </div>
              ) : !admission ? (
                <div className="text-sm text-muted-foreground">Loading…</div>
              ) : (<>
                <div className="flex flex-col gap-1.5">
                  <Label>Max Events</Label>
                  <div className="flex items-center gap-3">
                    <Input
                      type="number" min={1} max={5000}
                      value={admission.maxEvents}
                      onChange={e => setAdmission({ maxEvents: Math.max(1, parseInt(e.target.value) || 1) })}
                      className="h-8 w-36 text-sm"
                      disabled={!isAdmin}
                    />
                    <span className="text-xs text-muted-foreground">1 – 5000</span>
                  </div>
                </div>

                <div className="rounded-md bg-muted/40 px-4 py-3 text-sm">
                  <span className="font-medium">Total capacity:</span>{' '}
                  {admission.maxEvents} events
                </div>

                {isAdmin && (
                  <div className="flex justify-end">
                    <Button size="sm" onClick={handleSaveAdmission} disabled={savingAdm}>
                      {savingAdm ? 'Saving...' : 'Save'}
                    </Button>
                  </div>
                )}
              </>)}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </>
  )
}
