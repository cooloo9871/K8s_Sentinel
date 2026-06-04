import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Card,
  CardHeader,
  CardTitle,
  CardAction,
  CardContent,
} from '@/components/ui/card'
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
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
import { policyApi, modeApi, namespaceApi } from '../api/client'
import { useToast } from '../layout/AppToaster'
import { StatCard } from '../components/StatCard'
import type { PolicyRecord, Mode } from '../api/types'

export function DashboardPage() {
  const navigate = useNavigate()
  const toast = useToast()
  const [policies, setPolicies] = useState<PolicyRecord[]>([])
  const [mode, setMode] = useState<Mode>('Monitoring')
  const [namespaceCount, setNamespaceCount] = useState(0)
  const [loading, setLoading] = useState(true)
  const [switchModal, setSwitchModal] = useState(false)

  useEffect(() => {
    Promise.all([policyApi.list(), modeApi.get(), namespaceApi.list()])
      .then(([p, m, ns]) => {
        setPolicies(p)
        setMode(m)
        setNamespaceCount(ns.length)
      })
      .catch(() => toast.error('Failed to load dashboard'))
      .finally(() => setLoading(false))
  }, [])

  const handleModeSwitch = async () => {
    const next: 'Monitoring' | 'Protect' = mode === 'Protect' ? 'Monitoring' : 'Protect'
    try {
      await modeApi.set(next)
      setMode(next)
      toast.success(`Mode switched to ${next}`)
    } catch {
      toast.error('Failed to switch mode')
    }
  }

  const clusterCount = policies.filter((p) => p.scope === 'cluster').length
  const recent = policies.slice(0, 5)
  const nextMode: 'Monitoring' | 'Protect' = mode === 'Protect' ? 'Monitoring' : 'Protect'
  const modeColor = mode === 'Protect' ? '#dc3545' : mode === 'Mixed' ? '#fd7e14' : '#28a745'

  if (loading) {
    return (
      <div className="flex flex-col gap-6">
        <h4 className="text-lg font-semibold">Dashboard</h4>
        <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-24 rounded-xl" />
          ))}
        </div>
        <div className="grid gap-4 xl:grid-cols-3">
          <Skeleton className="h-64 rounded-xl xl:col-span-2" />
          <Skeleton className="h-64 rounded-xl" />
        </div>
      </div>
    )
  }

  return (
    <>
      <h4 className="mb-6 text-lg font-semibold">Dashboard</h4>

      <div className="mb-6 grid grid-cols-2 gap-4 xl:grid-cols-4">
        <StatCard
          title="Total Policies"
          value={policies.length}
          subtitle="TracingPolicy"
          borderColor="#2d7dd2"
        />
        <StatCard
          title="Current Mode"
          value={mode.toUpperCase()}
          subtitle={mode === 'Protect' ? 'Actively blocking violations' : 'Monitoring only, no blocking'}
          borderColor={modeColor}
        />
        <StatCard
          title="Namespaces"
          value={namespaceCount}
          subtitle="Active namespaces"
          borderColor="#28a745"
        />
        <StatCard
          title="Cluster-scoped"
          value={clusterCount}
          subtitle="Cluster-scoped policies"
          borderColor="#dc3545"
        />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader>
            <CardTitle>Recent Policies</CardTitle>
            <CardAction>
              <Button variant="link" size="sm" onClick={() => navigate('/policies/tracing')}>
                View All →
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Scope</TableHead>
                  <TableHead>Namespace</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {recent.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={4} className="py-8 text-center text-muted-foreground">
                      No policies yet
                    </TableCell>
                  </TableRow>
                ) : (
                  recent.map((p) => (
                    <TableRow
                      key={`${p.scope}-${p.namespace ?? ''}-${p.name}`}
                      className="cursor-pointer"
                      onClick={() =>
                        navigate(`/policies/tracing/${p.name}/edit?namespace=${p.namespace ?? ''}`)
                      }
                    >
                      <TableCell className="font-medium text-primary">{p.name}</TableCell>
                      <TableCell>
                        <Badge variant={p.scope === 'cluster' ? 'destructive' : 'secondary'}>
                          {p.scope}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-muted-foreground">{p.namespace ?? '-'}</TableCell>
                      <TableCell className="text-muted-foreground">{p.createdAt}</TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Enforcement Mode</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-4 text-center">
            <div
              style={{ border: `2px solid ${modeColor}` }}
              className="rounded-lg p-4"
            >
              <p className="mb-1 text-xs text-muted-foreground">Current mode</p>
              <p className="text-lg font-bold" style={{ color: modeColor }}>
                {mode.toUpperCase()}
              </p>
            </div>
            <Button
              variant={nextMode === 'Protect' ? 'destructive' : 'outline'}
              className="w-full"
              onClick={() => setSwitchModal(true)}
            >
              Switch to {nextMode.toUpperCase()}
            </Button>
            {nextMode === 'Protect' && (
              <p className="text-xs text-destructive">
                ⚠ Will actively block violations when enabled
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      <AlertDialog open={switchModal} onOpenChange={setSwitchModal}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Switch Mode</AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div>
                Switch enforcement mode to <strong>{nextMode.toUpperCase()}</strong>?
                {nextMode === 'Protect' && (
                  <p className="mt-2 text-destructive">
                    Warning: Protect mode will actively kill violating processes.
                  </p>
                )}
              </div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              variant={nextMode === 'Protect' ? 'destructive' : 'default'}
              onClick={handleModeSwitch}
            >
              Switch to {nextMode}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
