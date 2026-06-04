import { useCallback, useEffect, useState } from 'react'
import { Card, CardContent } from '@/components/ui/card'
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
import { eventsApi } from '../api/client'
import { useToast } from '../layout/AppToaster'
import type { SecurityEvent } from '../api/types'

function formatTime(iso: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (isNaN(d.getTime())) return iso
  return d.toLocaleString()
}

function RelativeTime({ iso }: { iso: string }) {
  if (!iso) return <span className="text-muted-foreground">—</span>
  const d = new Date(iso)
  if (isNaN(d.getTime())) return <span>{iso}</span>
  const diffMs = Date.now() - d.getTime()
  const diffMin = Math.floor(diffMs / 60000)
  const diffHr = Math.floor(diffMin / 60)
  const diffDay = Math.floor(diffHr / 24)
  let label = ''
  if (diffMin < 1) label = 'Just now'
  else if (diffMin < 60) label = `${diffMin}m ago`
  else if (diffHr < 24) label = `${diffHr}h ago`
  else label = `${diffDay}d ago`
  return <span title={formatTime(iso)}>{label}</span>
}

export function SecurityEventsPage() {
  const toast = useToast()
  const [events, setEvents] = useState<SecurityEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)

  const load = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true)
    else setLoading(true)
    try {
      setEvents(await eventsApi.list())
    } catch {
      toast.error('Failed to load security events')
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  return (
    <>
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h4 className="text-lg font-semibold">Security Events</h4>
          <p className="text-sm text-muted-foreground">
            Cluster-wide Warning and Tetragon violation events
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => load(true)}
          disabled={refreshing}
        >
          {refreshing ? 'Refreshing…' : 'Refresh'}
        </Button>
      </div>

      <Card>
        <CardContent className="p-0">
          {loading ? (
            <div className="flex flex-col gap-2 p-4">
              {Array.from({ length: 6 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full rounded-lg" />
              ))}
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-28">Type</TableHead>
                  <TableHead>Object</TableHead>
                  <TableHead>Reason</TableHead>
                  <TableHead className="max-w-xs">Message</TableHead>
                  <TableHead className="text-center w-16">Count</TableHead>
                  <TableHead className="w-32">Last Seen</TableHead>
                  <TableHead>Source</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {events.length === 0 ? (
                  <TableRow>
                    <TableCell
                      colSpan={7}
                      className="py-12 text-center text-muted-foreground"
                    >
                      No security events found
                    </TableCell>
                  </TableRow>
                ) : (
                  events.map((e, i) => (
                    <TableRow key={i}>
                      <TableCell>
                        <Badge variant={e.type === 'Warning' ? 'destructive' : 'secondary'}>
                          {e.type || '—'}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="font-medium">{e.involvedName}</div>
                        <div className="text-xs text-muted-foreground">
                          {e.involvedKind}
                          {e.involvedNamespace ? ` / ${e.involvedNamespace}` : ''}
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-xs">{e.reason || '—'}</TableCell>
                      <TableCell className="max-w-xs">
                        <p
                          className="truncate text-sm"
                          title={e.message}
                        >
                          {e.message || '—'}
                        </p>
                      </TableCell>
                      <TableCell className="text-center text-sm">
                        {e.count || 1}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        <RelativeTime iso={e.lastTime} />
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {e.source || '—'}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </>
  )
}
