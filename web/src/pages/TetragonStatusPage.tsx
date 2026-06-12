import { useEffect, useState, useCallback } from 'react'
import { IconRefresh, IconServer } from '@tabler/icons-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { formatTWTime } from '../utils/time'

interface TetragonAgent {
  podName: string
  nodeName: string
  phase: string
  ready: boolean
  restartCount: number
  startedAt?: string
  message?: string
}

function StatusBadge({ agent }: { agent: TetragonAgent }) {
  if (agent.ready && agent.phase === 'Running') {
    return <Badge className="bg-green-500/15 text-green-700 font-medium">Healthy</Badge>
  }
  if (agent.phase === 'Running') {
    return <Badge className="bg-amber-500/15 text-amber-700 font-medium">Not Ready</Badge>
  }
  return <Badge variant="destructive" className="font-medium">{agent.phase || 'Unknown'}</Badge>
}

export function TetragonStatusPage() {
  const [agents, setAgents] = useState<TetragonAgent[]>([])
  const [loading, setLoading] = useState(true)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    try {
      const res = await fetch('/api/tetragon/agents')
      if (!res.ok) throw new Error(await res.text())
      const data = await res.json()
      setAgents(data.agents ?? [])
      setLastUpdated(new Date())
      setError('')
    } catch (e: any) {
      setError(e.message ?? 'Failed to load agent status')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    const timer = setInterval(load, 30_000)
    return () => clearInterval(timer)
  }, [load])

  const healthy = agents.filter(a => a.ready && a.phase === 'Running').length
  const total = agents.length

  return (
    <>
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h4 className="text-xl font-semibold">Tetragon Agents</h4>
          <p className="text-sm text-muted-foreground">
            Health status of Tetragon DaemonSet pods across all nodes
          </p>
        </div>
        <div className="flex items-center gap-3">
          {lastUpdated && (
            <span className="text-xs text-muted-foreground">
              Updated {formatTWTime(lastUpdated.toISOString())}
            </span>
          )}
          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            <IconRefresh size={14} className={`mr-1.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        </div>
      </div>

      {/* Summary */}
      {!loading && agents.length > 0 && (
        <div className="mb-6 flex gap-4">
          <Card className="flex-1">
            <CardContent className="pt-5 pb-4">
              <p className="text-2xl font-bold text-green-600">{healthy}</p>
              <p className="text-xs text-muted-foreground mt-0.5">Healthy</p>
            </CardContent>
          </Card>
          <Card className="flex-1">
            <CardContent className="pt-5 pb-4">
              <p className={`text-2xl font-bold ${total - healthy > 0 ? 'text-destructive' : 'text-muted-foreground'}`}>
                {total - healthy}
              </p>
              <p className="text-xs text-muted-foreground mt-0.5">Unhealthy</p>
            </CardContent>
          </Card>
          <Card className="flex-1">
            <CardContent className="pt-5 pb-4">
              <p className="text-2xl font-bold">{total}</p>
              <p className="text-xs text-muted-foreground mt-0.5">Total Agents</p>
            </CardContent>
          </Card>
        </div>
      )}

      {error && (
        <div className="mb-4 rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3 text-sm text-destructive">
          {error}
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center py-24 text-muted-foreground">
          <IconRefresh size={20} className="mr-2 animate-spin" />
          Loading agent status...
        </div>
      ) : agents.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-3 py-24 text-muted-foreground">
          <IconServer size={48} strokeWidth={1.5} />
          <p className="text-base font-medium">No Tetragon agents found</p>
          <p className="text-sm">Make sure Tetragon is installed in the kube-system namespace</p>
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {agents
            .sort((a, b) => a.nodeName.localeCompare(b.nodeName))
            .map(agent => (
              <Card key={agent.podName} className={!agent.ready ? 'border-destructive/40 bg-destructive/5' : ''}>
                <CardHeader className="border-b pb-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm font-semibold truncate" title={agent.nodeName}>
                      {agent.nodeName}
                    </CardTitle>
                    <StatusBadge agent={agent} />
                  </div>
                </CardHeader>
                <CardContent className="pt-3 text-xs space-y-1.5">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Pod</span>
                    <span className="font-mono truncate ml-2 max-w-[180px]" title={agent.podName}>
                      {agent.podName}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Restarts</span>
                    <span className={agent.restartCount > 0 ? 'text-amber-600 font-medium' : ''}>
                      {agent.restartCount}
                    </span>
                  </div>
                  {agent.startedAt && (
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Started</span>
                      <span>{formatTWTime(agent.startedAt)}</span>
                    </div>
                  )}
                  {agent.message && (
                    <div className="mt-2 rounded bg-destructive/10 px-2 py-1 text-destructive">
                      {agent.message}
                    </div>
                  )}
                </CardContent>
              </Card>
            ))}
        </div>
      )}
    </>
  )
}
