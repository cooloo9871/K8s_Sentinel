import { useEffect, useRef, useState } from 'react'
import {
  IconActivity,
  IconWifi,
  IconWifiOff,
} from '@tabler/icons-react'
import { Card, CardContent } from '@/components/ui/card'
import {
  Table, TableHeader, TableBody, TableRow, TableHead, TableCell,
} from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import type { TetragonEvent } from '../api/types'

const MAX_EVENTS = 500
const DEDUP_WINDOW_MS = 5000

type FilterType = 'all' | 'kill'

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

function EventTypeBadge({ action }: { action: string }) {
  if (action === 'kill') return <Badge variant="destructive">kill</Badge>
  return <Badge className="bg-amber-500/20 text-amber-700 hover:bg-amber-500/20">kprobe</Badge>
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
  const [error, setError] = useState('')
  const [filter, setFilter] = useState<FilterType>('all')
  const [podSearch, setPodSearch] = useState('')
  const esRef = useRef<EventSource | null>(null)

  const connect = () => {
    setError('')
    const es = new EventSource('/api/events/stream')
    esRef.current = es

    es.onopen = () => setConnected(true)

    es.onmessage = (e) => {
      try {
        const evt: TetragonEvent = JSON.parse(e.data)
        setEvents((prev) => {
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

    es.onerror = () => setConnected(false)
  }

  useEffect(() => {
    connect()
    return () => esRef.current?.close()
  }, [])

  const filtered = events.filter((e) => {
    if (filter === 'kill' && e.action !== 'kill') return false
    if (podSearch.trim() && !e.pod.toLowerCase().includes(podSearch.trim().toLowerCase())) return false
    return true
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
          <div className="flex items-center gap-1.5 text-sm">
            {connected ? (
              <><IconWifi size={16} className="text-green-500" /><span className="text-green-600">Live</span></>
            ) : (
              <><IconWifiOff size={16} className="text-muted-foreground" /><span className="text-muted-foreground">Disconnected</span></>
            )}
          </div>

          <Input
            placeholder="Search pod name..."
            value={podSearch}
            onChange={(e) => setPodSearch(e.target.value)}
            className="h-9 w-48"
          />

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
        </div>
      </div>

      {error && (
        <div className="mb-4 flex items-center gap-3 rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3">
          <span className="text-sm text-destructive">{error}</span>
          <Button size="sm" variant="outline" className="ml-auto" onClick={() => { setError(''); connect() }}>
            Reconnect
          </Button>
        </div>
      )}

      <Card>
        <div className="flex items-center gap-6 border-b px-5 py-3 text-sm text-muted-foreground">
          <span>{filtered.length} events{(filter !== 'all' || podSearch) ? ' (filtered)' : ''}</span>
          <span>{events.filter(e => e.action === 'monitor').length} monitor</span>
          <span className="text-destructive">{events.filter(e => e.action === 'kill').length} kills</span>
        </div>

        <CardContent className="p-0">
          {filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center gap-3 py-16 text-muted-foreground">
              <IconActivity size={40} strokeWidth={1.5} />
              <p className="text-base">
                {connected
                  ? podSearch ? `No events for pod "${podSearch}"` : 'Waiting for events...'
                  : 'Not connected'}
              </p>
              <p className="text-sm">Events will appear here as Tetragon detects runtime activity</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-20">Type</TableHead>
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
                      <EventTypeBadge action={e.action} />
                    </TableCell>
                    <TableCell>
                      <p className="font-mono text-sm font-medium">{e.binary || '—'}</p>
                      {e.arguments && (
                        <p className="truncate font-mono text-xs text-muted-foreground max-w-[200px]" title={e.arguments}>
                          {e.arguments}
                        </p>
                      )}
                    </TableCell>
                    <TableCell>
                      {e.pod ? (
                        <>
                          <p className="text-sm font-medium">{e.pod}</p>
                          <p className="text-xs text-muted-foreground">
                            {e.namespace}{e.container ? ` / ${e.container}` : ''}
                          </p>
                        </>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      {e.policyName ? (
                        <Badge variant="outline" className="font-mono text-xs">{e.policyName}</Badge>
                      ) : '—'}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {e.function || '—'}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {e.nodeName || '—'}
                    </TableCell>
                    <TableCell className="text-center">
                      {e.count > 1 && (
                        <Badge variant="secondary" className="text-xs">×{e.count}</Badge>
                      )}
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
