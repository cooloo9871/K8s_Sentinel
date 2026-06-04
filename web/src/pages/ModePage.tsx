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
import type { Mode } from '../api/types'

const MODE_DESCRIPTIONS: Record<Mode, string> = {
  Monitoring: 'Monitors all behavior without blocking. Suitable for initial policy validation and behavioral analysis.',
  Protect: 'Actively blocks policy violations via Sigkill. Suitable for production enforcement.',
  Mixed: 'Some policies use Monitoring and others use Protect. Switching will apply the selected mode to all policies.',
}

export function ModePage() {
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
      <h4 className="mb-6 text-lg font-semibold">Mode Control</h4>

      <Card className="max-w-sm">
        <CardHeader className="border-b pb-3">
          <CardTitle className="text-sm font-medium">Enforcement Mode</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4 pt-4">
          <div
            className="rounded-lg p-5 text-center"
            style={{ border: `2px solid ${modeColor}` }}
          >
            <p className="mb-1 text-xs text-muted-foreground">Current mode</p>
            <p className="text-3xl font-bold" style={{ color: modeColor }}>
              {mode.toUpperCase()}
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

          <Button
            variant={nextMode === 'Protect' ? 'destructive' : 'outline'}
            className="w-full"
            onClick={() => setSwitchModal(true)}
          >
            Switch to {nextMode.toUpperCase()}
          </Button>
        </CardContent>
      </Card>

      <AlertDialog open={switchModal} onOpenChange={setSwitchModal}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Switch Enforcement Mode</AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div>
                Switch mode from <strong>{mode.toUpperCase()}</strong> to{' '}
                <strong>{nextMode.toUpperCase()}</strong>?
                {nextMode === 'Protect' && (
                  <p className="mt-2 text-destructive">
                    ⚠ Warning: Protect mode will actively kill (Sigkill) violating processes.
                    Ensure all policies are correct before switching.
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
              Switch to {nextMode}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
