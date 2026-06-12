import { useEffect, useState } from 'react'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Alert, AlertDescription } from '@/components/ui/alert'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { modeApi } from '../api/client'
import { useToast } from '../layout/AppToaster'
import { useAuth } from '../layout/AuthContext'
import type { Mode } from '../api/types'

const MODE_DESCRIPTIONS: Record<Mode, string> = {
  Monitoring: 'Monitors all behavior without blocking. Suitable for initial policy validation and behavioral analysis.',
  Protect: 'Actively blocks policy violations via Sigkill. Suitable for production enforcement.',
  Mixed: 'Some policies use Monitoring and others use Protect. Switching will apply the selected mode to all policies.',
}

export function ModePage() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const toast = useToast()
  const [mode, setMode] = useState<Mode>('Monitoring')
  const [loading, setLoading] = useState(true)
  const [switchModal, setSwitchModal] = useState(false)

  useEffect(() => {
    modeApi
      .get()
      .then(setMode)
      .catch(() => toast.error('Failed to load mode'))
      .finally(() => setLoading(false))
  }, [])

  const nextMode: 'Monitoring' | 'Protect' = mode === 'Protect' ? 'Monitoring' : 'Protect'
  const modeColor = mode === 'Protect' ? '#dc3545' : mode === 'Mixed' ? '#fd7e14' : '#28a745'

  const handleSwitch = async () => {
    try {
      await modeApi.set(nextMode)
      setMode(nextMode)
      toast.success(`Mode switched to ${nextMode}`)
    } catch {
      toast.error('Failed to switch mode')
    }
  }

  if (loading) {
    return (
      <div className="flex flex-col gap-4">
        <Skeleton className="h-8 w-36" />
        <Skeleton className="h-56 w-full max-w-sm rounded-xl" />
      </div>
    )
  }

  return (
    <>
      <h4 className="mb-6 text-lg font-semibold">Global Protect Mode</h4>

      <Card className="max-w-sm">
        <CardHeader className="border-b pb-3">
          <CardTitle className="text-sm font-medium">Global Protect Mode</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4 pt-4">
          <div
            className="rounded-lg p-5 text-center"
            style={{ border: `2px solid ${modeColor}` }}
          >
            <p className="mb-1 text-xs text-muted-foreground">Current status</p>
            <p className="text-3xl font-bold" style={{ color: modeColor }}>
              {mode === 'Protect' ? 'ON' : mode === 'Mixed' ? 'MIXED' : 'OFF'}
            </p>
          </div>

          <p className="text-sm text-muted-foreground">{MODE_DESCRIPTIONS[mode]}</p>

          {mode === 'Mixed' && (
            <Alert>
              <AlertDescription>
                Mixed mode: switching will apply the new mode to all policies.
              </AlertDescription>
            </Alert>
          )}

          {isAdmin && (
            <Button
              variant={nextMode === 'Protect' ? 'destructive' : 'outline'}
              className="w-full"
              onClick={() => setSwitchModal(true)}
            >
              {nextMode === 'Protect' ? 'Turn On' : 'Turn Off'}
            </Button>
          )}
        </CardContent>
      </Card>

      <AlertDialog open={switchModal} onOpenChange={setSwitchModal}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {nextMode === 'Protect' ? 'Turn On Global Protect Mode' : 'Turn Off Global Protect Mode'}
            </AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div>
                {nextMode === 'Protect'
                  ? 'Apply Protect mode to all TracingPolicies? Violations will be actively blocked (Sigkill).'
                  : 'Apply Monitoring mode to all TracingPolicies? Violations will be logged but not blocked.'}
                {nextMode === 'Protect' && (
                  <p className="mt-2 text-destructive">
                    ⚠ Warning: This will actively kill violating processes. Ensure all policies are correct before turning on.
                  </p>
                )}
              </div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              variant={nextMode === 'Protect' ? 'destructive' : 'default'}
              onClick={handleSwitch}
            >
              {nextMode === 'Protect' ? 'Turn On' : 'Turn Off'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
