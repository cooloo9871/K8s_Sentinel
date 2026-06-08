import { useState } from 'react'
import { IconActivity, IconWifi, IconWifiOff } from '@tabler/icons-react'
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
import { useSecurityEvents, type Severity } from '../layout/SecurityEventsProvider'

type FilterType = 'all' | 'warning' | 'critical'

function SeverityBadge({ severity }: { severity: Severity }) {
  if (severity === 'critical') {
    return (
      <Badge variant="destructive" className="font-medium">
        Critical
      </Badge>
    )
  }
  return (
    <Badge className="bg-amber-500/15 text-amber-700 hover:bg-amber-500/15 font-medium">
      Warning
    </Badge>
  )
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
  const { events, connected, error, reconnect } = useSecurityEvents()
  const [filter, setFilter] = useState<FilterType>('all')
  const [podSearch, setPodSearch] = useState('')

  const filtered = events.filter((e) => {
    if (filter === 'warning' && e.severity !== 'warning') return false
    if (filter === 'critical' && e.severity !== 'critical') return false
    if (podSearch.trim() && !e.pod.toLowerCase().includes(podSearch.trim().toLowerCase())) return false
    return true
  })

  const warningCount = events.filter(e => e.severity === 'warning').length
  const criticalCount = events.filter(e => e.severity === 'critical').length

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
            <SelectTrigger className="h-9 w-40">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="all">All Events</SelectItem>
                <SelectItem value="warning">Warning Only</SelectItem>
                <SelectItem value="critical">Critical Only</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>
        </div>
      </div>

      {error && (
        <div className="mb-4 flex items-center gap-3 rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3">
          <span className="text-sm text-destructive">{error}</span>
          <Button size="sm" variant="outline" className="ml-auto" onClick={reconnect}>
            Reconnect
          </Button>
        </div>
      )}

      <Card>
        {/* Stats bar */}
        <div className="flex items-center gap-6 border-b px-5 py-3 text-sm">
          <span className="text-muted-foreground">
            {filtered.length} events{(filter !== 'all' || podSearch) ? ' (filtered)' : ''}
          </span>
          <div className="flex items-center gap-1.5">
            <span className="size-2 rounded-full bg-amber-400" />
            <span className="text-amber-700">{warningCount} warning</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="size-2 rounded-full bg-destructive" />
            <span className="text-destructive">{criticalCount} critical</span>
          </div>
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
                  <TableHead className="w-24">Severity</TableHead>
                  <TableHead>Binary</TableHead>
                  <TableHead>Namespace / Pod</TableHead>
                  <TableHead>Policy</TableHead>
                  <TableHead>Function</TableHead>
                  <TableHead>Node</TableHead>
                  <TableHead className="w-24">Time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((e, i) => (
                  <TableRow
                    key={i}
                    className={e.severity === 'critical' ? 'bg-destructive/5 hover:bg-destructive/10' : ''}
                  >
                    <TableCell>
                      <SeverityBadge severity={e.severity} />
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
                      {e.namespace || e.pod ? (
                        <>
                          <p className="text-sm font-medium">{e.namespace || '—'}</p>
                          <p className="text-xs text-muted-foreground">
                            {e.pod}{e.container ? ` / ${e.container}` : ''}
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
