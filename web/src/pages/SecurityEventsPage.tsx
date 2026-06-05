import { useEffect, useRef, useState } from 'react'
import {
  IconActivity,
  IconPlayerPlay,
  IconPlayerPause,
  IconTrash,
  IconWifi,
  IconWifiOff,
} from '@tabler/icons-react'
import { Card, CardContent } from '@/components/ui/card'
import {
  Table, TableHeader, TableBody, TableRow, TableHead, TableCell,
} from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import type { TetragonEvent } from '../api/types'

const MAX_EVENTS = 500
const DEDUP_WINDOW_MS = 5000 // merge identical events within 5s

type FilterType = 'all' | 'kill'

// DisplayEvent extends TetragonEvent with a client-side dedup count
interface DisplayEvent extends TetragonEvent {
  count: number
}

function isSameEvent(a: DisplayEvent, b: TetragonEvent): boolean {
  return (
    a.binary === b.binary &&
    a.pod === b.pod &&
    a.function === b.function &&
    a.policyName === b.policyName &&
    a.action === b.action &&
    Math.abs(new Date(b.time).getTime() - new Date(a.time).getTime()) < DEDUP_WINDOW_MS
  )
}

function EventTypeBadge({ type, action }: { type: string; action: string }) {
  if (type === 'exec') return <Badge variant="secondary">exec</Badge>
  if (type === 'exit') return <Badge variant="outline">exit</Badge>
  if (type === 'kprobe' && action === 'kill')
    return <Badge variant="destructive">kill</Badge>
  if (type === 'kprobe')
    return <Badge className="bg-amber-500/20 text-amber-700 hover:bg-amber-500/20">kprobe</Badge>
  return <Badge variant="outline">{type}</Badge>
}

function RelativeTime({ iso }: { iso: string }) {
  if (!iso) return <span className="text-muted-foreground">—</span>
  const d = new Date(iso)
  if (isNaN(d.getTime())) return <span className="font-mono text-xs">{iso}</span>
  const diff = Math.floor((Date.now() - d.getTime()) / 1000)
  const label = diff < 5 ? 'just now'
    : diff < 60 ? `${diff}s ago`
    : diff < 3600 ? `${Math.floor(diff / 60)}m ago`
    : `${Math.floor(diff / 3600)}h ago`
  return <span className="font-mono text-xs" title={d.toLocaleString()}>{label}</span>
}

export function SecurityEventsPage() {
  const [events, setEvents] = useState<DisplayEvent[]>([])
  const [connected, setConnected] = useState(false)
  const [paused, setPaused] = useState(false)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState<FilterType>('all')
  const pausedRef = useRef(false)
  const esRef = useRef<EventSource | null>(null)

  const connect = () => {
    setError('')
    const es = new EventSource('/api/events/stream')
    esRef.current = es

    es.onopen = () => setConnected(true)

    es.onmessage = (e) => {
      if (pausedRef.current) return
      try {
        const evt: TetragonEvent = JSON.parse(e.data)
        setEvents((prev) => {
          // Merge into the most recent identical event instead of adding a new row
          if (prev.length > 0 && isSameEvent(prev[0], evt)) {
            return [{ ...prev[0], count: prev[0].count + 1, time: evt.time }, ...prev.slice(1)]
          }
          return [{ ...evt, count: 1 }, ...prev].slice(0, MAX_EVENTS)
        })
      } catch {}
    }

    es.addEventListener('stream-error', (e: MessageEvent) => {
      setError(e.data)
      setConnected(false)
      es.close()
    })

    es.onerror = () => {
      setConnected(false)
      // EventSource auto-reconnects — show brief disconnected state
    }
  }

  useEffect(() => {
    connect()
    return () => esRef.current?.close()
  }, [])

  const togglePause = () => {
    pausedRef.current = !paused
    setPaused(!paused)
  }

  const clearEvents = () => setEvents([])

  const filtered = events.filter((e) => {
    if (filter === 'all') return true
    if (filter === 'kill') return e.type === 'kprobe' && e.action === 'kill'
    return e.type === filter
  })

  return (
    <>
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h4 className="text-xl font-semibold">Security Events</h4>
          <p className="text-sm text-muted-foreground">
            Policy-triggered kprobe events from your TracingPolicies
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Connection status */}
          <div className="flex items-center gap-1.5 text-sm">
            {connected ? (
              <>
                <IconWifi size={16} className="text-green-500" />
                <span className="text-green-600">Live</span>
              </>
            ) : (
              <>
                <IconWifiOff size={16} className="text-muted-foreground" />
                <span className="text-muted-foreground">Disconnected</span>
              </>
            )}
          </div>

          {/* Filter */}
          <Select value={filter} onValueChange={(v) => setFilter(v as FilterType)}>
            <SelectTrigger className="h-9 w-36">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="all">All Policy Events</SelectItem>
                <SelectItem value="kill">Kills Only</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>

          <Button variant="outline" size="sm" onClick={togglePause}>
            {paused ? (
              <><IconPlayerPlay size={14} className="mr-1.5" />Resume</>
            ) : (
              <><IconPlayerPause size={14} className="mr-1.5" />Pause</>
            )}
          </Button>

          <Button variant="outline" size="sm" onClick={clearEvents}>
            <IconTrash size={14} className="mr-1.5" />
            Clear
          </Button>
        </div>
      </div>

      {/* Error banner */}
      {error && (
        <div className="mb-4 flex items-center gap-3 rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3">
          <span className="text-sm text-destructive">{error}</span>
          <Button size="sm" variant="outline" className="ml-auto" onClick={() => { setError(''); connect() }}>
            Reconnect
          </Button>
        </div>
      )}

      <Card>
        {/* Stats bar */}
        <div className="flex items-center gap-6 border-b px-5 py-3 text-sm text-muted-foreground">
          <span>{filtered.length} events{filter !== 'all' ? ` (filtered)` : ''}</span>
          <span>{events.filter(e => e.action === 'monitor').length} monitor</span>
          <span className="text-destructive">
            {events.filter(e => e.action === 'kill').length} kills
          </span>
          {paused && (
            <span className="ml-auto rounded bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-700">
              PAUSED
            </span>
          )}
        </div>

        <CardContent className="p-0">
          {filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center gap-3 py-16 text-muted-foreground">
              <IconActivity size={40} strokeWidth={1.5} />
              <p className="text-base">
                {connected ? 'Waiting for events...' : 'Not connected'}
              </p>
              <p className="text-sm">
                Events will appear here as Tetragon detects runtime activity
              </p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-24">Type</TableHead>
                  <TableHead>Binary</TableHead>
                  <TableHead>Pod / Namespace</TableHead>
                  <TableHead>Policy</TableHead>
                  <TableHead>Function</TableHead>
                  <TableHead>Node</TableHead>
                  <TableHead className="w-14 text-center">×</TableHead>
                  <TableHead className="w-24">Time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((e, i) => (
                  <TableRow
                    key={i}
                    className={e.action === 'kill' ? 'bg-destructive/5 hover:bg-destructive/10' : ''}
                  >
                    <TableCell>
                      <EventTypeBadge type={e.type} action={e.action} />
                    </TableCell>
                    <TableCell>
                      <p className="font-mono text-sm font-medium">{e.binary || '—'}</p>
                      {e.arguments && (
                        <p className="truncate font-mono text-xs text-muted-foreground max-w-[200px]" title={e.arguments}>
                          {e.arguments}
                        </p>
                      )}
                      {e.parentBin && (
                        <p className="font-mono text-xs text-muted-foreground">
                          ↑ {e.parentBin}
                        </p>
                      )}
                    </TableCell>
                    <TableCell>
                      {e.pod ? (
                        <>
                          <p className="text-sm font-medium">{e.pod}</p>
                          <p className="text-xs text-muted-foreground">{e.namespace}{e.container ? ` / ${e.container}` : ''}</p>
                        </>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      {e.policyName ? (
                        <Badge variant="outline" className="font-mono text-xs">
                          {e.policyName}
                        </Badge>
                      ) : '—'}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {e.function || '—'}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {e.nodeName || '—'}
                    </TableCell>
                    <TableCell className="text-center">
                      {e.count > 1 ? (
                        <Badge variant="secondary" className="text-xs">×{e.count}</Badge>
                      ) : null}
                    </TableCell>
                    <TableCell>
                      <RelativeTime iso={e.time} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </>
  )
}
