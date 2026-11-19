import { useState } from 'react'
import { IconLock } from '@tabler/icons-react'
import { Button } from '@/components/ui/button'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { quarantineApi } from '../api/client'
import { useToast } from '../layout/AppToaster'
import { useAuth } from '../layout/AuthContext'

// QuarantineAction cuts the pod off from the network without killing it. It is
// offered where a pod is being looked at, a security event or the topology,
// rather than as a standing rule: this contains the one pod a person chose, and
// changes nothing about future events.
export function QuarantineAction({ namespace, pod, quarantined, onChanged }: {
  namespace: string
  pod: string
  quarantined: boolean
  onChanged: () => void
}) {
  const [busy, setBusy] = useState(false)
  const [asking, setAsking] = useState(false)
  const toast = useToast()
  const { user } = useAuth()

  if (!pod || !namespace) return null

  // Containment is a fact about the pod, not about what is being read, so
  // everything shown about that pod says so, and nothing offers to do it again.
  if (quarantined) {
    return (
      <p className="mt-2 flex items-center gap-1 text-xs text-red-600">
        <IconLock size={12} /> This pod is quarantined. Release it from the Quarantine page.
      </p>
    )
  }
  if (user?.role !== 'admin') return null
  // An account limited to namespaces quarantines its own pods only.
  if (user.namespaces?.length && !user.namespaces.includes(namespace)) return null

  const run = async () => {
    setBusy(true)
    try {
      await quarantineApi.add(namespace, pod)
      toast.success(`${pod} quarantined. Network access stops shortly; the container keeps running.`)
      onChanged()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : `Could not quarantine ${pod}`)
    } finally {
      setBusy(false)
    }
  }

  // Confirmed first: this cuts a running workload off the network, and the
  // button sits inside a detail you opened to read rather than to act. The
  // dialog names the pod, because what was opened is not necessarily what is
  // still under the pointer.
  return (
    <AlertDialog open={asking} onOpenChange={setAsking}>
      <Button
        variant="outline"
        size="sm"
        className="mt-2 h-7 w-fit border-red-300 text-xs text-red-600 hover:bg-red-50 hover:text-red-700"
        disabled={busy}
        onClick={() => setAsking(true)}
      >
        {busy ? 'Quarantining…' : 'Quarantine this pod'}
      </Button>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Quarantine this pod?</AlertDialogTitle>
          <AlertDialogDescription>
            <span className="font-mono font-medium">{namespace}/{pod}</span> loses all network
            access. The container keeps running, so anything it serves stops. Release it from
            Policies → Quarantine.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction variant="destructive" onClick={run}>Quarantine</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
