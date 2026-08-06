import { useCallback, useEffect, useState } from 'react'
import { IconLock, IconRefresh } from '@tabler/icons-react'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import {
  Table, TableHeader, TableBody, TableRow, TableHead, TableCell,
} from '@/components/ui/table'
import { quarantineApi, type QuarantinedPod } from '../api/client'
import { useToast } from '../layout/AppToaster'
import { formatTWTime } from '../utils/time'
import { useAuth } from '../layout/AuthContext'

export function QuarantinePage() {
  const [pods, setPods] = useState<QuarantinedPod[]>([])
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState('')
  // Confirmed like quarantine is, and for the sharper version of the same
  // reason: an accidental release puts a possibly compromised workload back on
  // the network.
  const [releasing, setReleasing] = useState<QuarantinedPod | null>(null)
  const toast = useToast()
  const { user } = useAuth()
  const canEdit = user?.role === 'admin'

  const load = useCallback(async () => {
    try {
      setPods(await quarantineApi.list())
    } catch {
      toast.error('Could not read the quarantine list')
    } finally {
      setLoading(false)
    }
  }, [toast])

  useEffect(() => { load() }, [load])

  const release = async (p: QuarantinedPod) => {
    setReleasing(null)
    setBusy(p.namespace + '/' + p.pod)
    try {
      await quarantineApi.release(p.namespace, p.pod)
      toast.success(`${p.pod} released`)
      load()
    } catch {
      toast.error(`Could not release ${p.pod}`)
    } finally {
      setBusy('')
    }
  }

  return (
    <>
      <div className="mb-4 flex items-start justify-between">
        <h4 className="text-xl font-semibold">Quarantine</h4>
        <Button variant="outline" size="sm" className="h-8 gap-1.5" onClick={load}>
          <IconRefresh size={14} /> Refresh
        </Button>
      </div>

      {/* What quarantine does and does not do. Someone arriving at a list of
          contained pods needs to know the container is still running — that is
          the whole point of containing rather than killing — and that the state
          lives on the pod, so it survives a Sentinel restart and can be undone
          without this page. */}
      <Card className="mb-4">
        <CardContent className="p-4 text-sm">
          <p>
            A quarantined pod is cut off from the network but left running, so the
            process, its memory and its open files are still there to examine.
          </p>
          <ul className="mt-2 flex list-disc flex-col gap-1 pl-5 text-muted-foreground">
            <li>Nothing reaches it and it reaches nothing — except the kubelet's
              health probes, which keep it from being restarted and replaced by a
              fresh, uncontained pod.</li>
            <li>The state is the label <code className="font-mono">sentinel.io/quarantine=true</code> on
              the pod, so it survives a Sentinel restart, and{' '}
              <code className="font-mono">kubectl label pod … sentinel.io/quarantine-</code> releases
              it without this page.</li>
            <li>One cluster-wide policy, <code className="font-mono">sentinel-quarantine</code>,
              selects that label. It is created the first time it is needed.</li>
            <li>A pod that is deleted and recreated comes back uncontained — the
              new pod is not the one that was quarantined.</li>
          </ul>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="p-0">
          {loading ? (
            <p className="py-10 text-center text-sm text-muted-foreground">Loading…</p>
          ) : pods.length === 0 ? (
            <div className="flex flex-col items-center gap-3 py-16 text-muted-foreground">
              <IconLock size={40} strokeWidth={1.5} />
              <p className="text-base">Nothing is quarantined</p>
              <p className="text-sm">
                Quarantine a pod from the Security Events page, on the event that concerns it.
              </p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Namespace</TableHead>
                  <TableHead>Pod</TableHead>
                  <TableHead>Node</TableHead>
                  <TableHead>By</TableHead>
                  <TableHead>Quarantined</TableHead>
                  <TableHead className="w-24" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {pods.map(p => {
                  const key = p.namespace + '/' + p.pod
                  return (
                    <TableRow key={key}>
                      <TableCell className="text-sm">{p.namespace}</TableCell>
                      <TableCell className="font-mono text-sm">{p.pod}</TableCell>
                      <TableCell className="text-sm">{p.node || '—'}</TableCell>
                      <TableCell className="text-sm">{p.by || '—'}</TableCell>
                      <TableCell className="text-sm">{p.at ? formatTWTime(p.at) : '—'}</TableCell>
                      <TableCell>
                        {canEdit && (
                          <button
                            type="button"
                            className="text-sm text-primary hover:underline disabled:opacity-50"
                            disabled={busy === key}
                            onClick={() => setReleasing(p)}
                          >
                            Release
                          </button>
                        )}
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <AlertDialog open={!!releasing} onOpenChange={open => !open && setReleasing(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Release this pod?</AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div className="flex flex-col gap-2">
                <span>
                  <span className="font-mono font-medium">
                    {releasing?.namespace}/{releasing?.pod}
                  </span>{' '}
                  goes back on the network, able to reach and be reached as before.
                </span>
                <span>
                  It was contained because something it did was flagged. Releasing it does not
                  clear that — check what happened first if you have not already.
                </span>
              </div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              onClick={() => releasing && release(releasing)}
            >
              Release
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
