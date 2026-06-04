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
  Monitoring: '觀測模式：記錄所有行為但不進行攔截，適合初期策略驗證與行為分析。',
  Protect: '保護模式：主動攔截違反策略的行為（Sigkill），適合生產環境強制執行。',
  Mixed: '混合模式：部分策略為 Monitoring，部分為 Protect，切換模式將統一套用。',
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
          {/* Mode indicator */}
          <div
            className="rounded-lg p-5 text-center"
            style={{ border: `2px solid ${modeColor}` }}
          >
            <p className="mb-1 text-xs text-muted-foreground">目前模式</p>
            <p className="text-3xl font-bold" style={{ color: modeColor }}>
              {mode.toUpperCase()}
            </p>
          </div>

          {/* Description */}
          <p className="text-sm text-muted-foreground">{MODE_DESCRIPTIONS[mode]}</p>

          {/* Mixed mode warning */}
          {mode === 'Mixed' && (
            <Alert>
              <AlertDescription>
                混合模式：切換後所有 Policy 將統一套用新模式。
              </AlertDescription>
            </Alert>
          )}

          {/* Switch button */}
          <Button
            variant={nextMode === 'Protect' ? 'destructive' : 'outline'}
            className="w-full"
            onClick={() => setSwitchModal(true)}
          >
            切換至 {nextMode.toUpperCase()}
          </Button>
        </CardContent>
      </Card>

      {/* Confirmation dialog */}
      <AlertDialog open={switchModal} onOpenChange={setSwitchModal}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>切換執行模式</AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div>
                確定要將模式從 <strong>{mode.toUpperCase()}</strong> 切換為{' '}
                <strong>{nextMode.toUpperCase()}</strong> 嗎？
                {nextMode === 'Protect' && (
                  <p className="mt-2 text-destructive">
                    ⚠ 警告：Protect 模式將主動攔截（Sigkill）違規行為，請確認策略正確後再切換。
                  </p>
                )}
              </div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>取消</AlertDialogCancel>
            <AlertDialogAction
              variant={nextMode === 'Protect' ? 'destructive' : 'default'}
              onClick={handleSwitch}
            >
              切換至 {nextMode}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
