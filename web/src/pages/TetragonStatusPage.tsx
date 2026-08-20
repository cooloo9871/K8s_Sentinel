import { useEffect, useState, useCallback } from 'react'
import { IconRefresh, IconServer } from '@tabler/icons-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { formatTWTime } from '../utils/time'
import { isNotDetected } from '../utils/ingestion'

interface TetragonAgent {
  podName: string
  nodeName: string
  phase: string
  ready: boolean
  restartCount: number
  startedAt?: string
  message?: string
  ingestObserved: boolean
  ingestConnected: boolean
  ingestFailures: number
  ingestLastEventAt?: string
  ingestLastError?: string
}

// The pod is Ready but Sentinel's gRPC stream to it is not connected — the
// silent-blindness case this page exists to expose.
function streamDown(a: TetragonAgent): boolean {
  return a.phase === 'Running' && a.ready && a.ingestObserved && !a.ingestConnected
}

function isHealthy(a: TetragonAgent): boolean {
  return a.ready && a.phase === 'Running' && !streamDown(a)
}

function StatusBadge({ agent }: { agent: TetragonAgent }) {
  if (agent.phase !== 'Running') {
    return <Badge variant="destructive" className="font-medium">{agent.phase || 'Unknown'}</Badge>
  }
  if (!agent.ready) {
    return <Badge className="bg-amber-500/15 text-amber-700 font-medium">Not Ready</Badge>
  }
  if (streamDown(agent)) {
    return <Badge variant="destructive" className="font-medium">Stream Down</Badge>
  }
  return <Badge className="bg-green-500/15 text-green-700 font-medium">Healthy</Badge>
}

// One ingestion source from /api/ingestion/health. Used here for the Hubble
// entry, which has no per-node pods the way Tetragon does.
interface IngestSource {
  kind: string
  name: string
  connected: boolean
  consecutiveFailures: number
  lastEventAt?: string
  lastError?: string
}

// hubbleState maps the raw source into a display state. A "Cilium not detected"
// error is a configuration fact, not a broken stream, so it reads as muted
// rather than an alarm.
function hubbleState(h: IngestSource | null): { label: string; down: boolean; muted: boolean } {
  if (!h) return { label: 'Not measured', down: false, muted: true }
  if (h.connected) return { label: 'Connected', down: false, muted: false }
  if (isNotDetected(h)) {
    return { label: 'Not detected', down: false, muted: true }
  }
  if (h.consecutiveFailures > 0 || h.lastError) return { label: 'Stream down', down: true, muted: false }
  return { label: 'Not measured', down: false, muted: true }
}

export function TetragonStatusPage() {
  const [agents, setAgents] = useState<TetragonAgent[]>([])
  const [hubble, setHubble] = useState<IngestSource | null>(null)
  const [loading, setLoading] = useState(true)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    try {
      const res = await fetch('/api/tetragon/agents')
      if (!res.ok) throw new Error(await res.text())
      const data = await res.json()
      setAgents(data.agents ?? [])
      // Best-effort: the Hubble entry is separate from Tetragon agents and its
      // absence must not blank the whole page.
      try {
        const ing = await fetch('/api/ingestion/health').then(r => r.json())
        setHubble((ing.sources ?? []).find((s: IngestSource) => s.kind === 'hubble') ?? null)
      } catch { /* leave hubble as-is */ }
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

  const healthy = agents.filter(isHealthy).length
  const total = agents.length
  const hb = hubbleState(hubble)

  return (
    <>
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h4 className="text-xl font-semibold">Event Sources</h4>
          <p className="text-sm text-muted-foreground">
            Whether Sentinel is actually ingesting from each source: Tetragon agents per node, and Hubble
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

      {error && (
        <div className="mb-4 rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3 text-sm text-destructive">
          {error}
        </div>
      )}

      {!loading && agents.length > 0 && (
        <h5 className="mb-3 text-sm font-semibold text-muted-foreground">Tetragon agents</h5>
      )}

      {/* Summary — Tetragon agent health counts */}
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
              <Card key={agent.podName} className={!agent.ready || streamDown(agent) ? 'border-destructive/40 bg-destructive/5' : ''}>
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
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Ingestion</span>
                    <span className={
                      !agent.ingestObserved ? 'text-muted-foreground'
                        : agent.ingestConnected ? 'text-green-700 font-medium'
                        : 'text-destructive font-medium'
                    }>
                      {!agent.ingestObserved ? 'Not measured'
                        : agent.ingestConnected ? 'Connected'
                        : 'Stream down'}
                    </span>
                  </div>
                  {agent.ingestObserved && (
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Last event</span>
                      <span>{agent.ingestLastEventAt ? formatTWTime(agent.ingestLastEventAt) : 'None yet'}</span>
                    </div>
                  )}
                  {agent.ingestFailures > 0 && (
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Consecutive failures</span>
                      <span className="text-destructive font-medium">{agent.ingestFailures}</span>
                    </div>
                  )}
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
                  {streamDown(agent) && agent.ingestLastError && (
                    <div className="mt-2 rounded bg-destructive/10 px-2 py-1 text-destructive break-words">
                      {agent.ingestLastError}
                    </div>
                  )}
                </CardContent>
              </Card>
            ))}
        </div>
      )}

      {/* Hubble — the aggregated relay stream, its own section below the
          per-node Tetragon agents rather than wedged between them. */}
      {!loading && (
        <>
          <h5 className="mb-3 mt-8 text-sm font-semibold text-muted-foreground">Hubble</h5>
          <Card className={hb.down ? 'border-destructive/40 bg-destructive/5' : ''}>
            <CardHeader className="border-b pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-semibold">Hubble Relay</CardTitle>
                {hb.down ? (
                  <Badge variant="destructive" className="font-medium">Stream Down</Badge>
                ) : hb.muted ? (
                  <Badge className="bg-muted text-muted-foreground font-medium">{hb.label}</Badge>
                ) : (
                  <Badge className="bg-green-500/15 text-green-700 font-medium">Connected</Badge>
                )}
              </div>
            </CardHeader>
            <CardContent className="pt-3 text-xs space-y-1.5">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Source</span>
                <span>Cluster-wide flow stream</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Last flow</span>
                <span>{hubble?.lastEventAt ? formatTWTime(hubble.lastEventAt) : 'None yet'}</span>
              </div>
              {(hubble?.consecutiveFailures ?? 0) > 0 && (
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Consecutive failures</span>
                  <span className="text-destructive font-medium">{hubble!.consecutiveFailures}</span>
                </div>
              )}
              {hb.down && hubble?.lastError && (
                <div className="mt-2 rounded bg-destructive/10 px-2 py-1 text-destructive break-words">
                  {hubble.lastError}
                </div>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </>
  )
}
