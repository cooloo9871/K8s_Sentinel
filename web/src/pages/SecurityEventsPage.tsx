import React, { useState } from 'react'
import { IconActivity, IconChevronDown, IconChevronRight, IconWifi, IconWifiOff } from '@tabler/icons-react'
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
import type { DisplayEvent } from '../layout/SecurityEventsProvider'
import { formatTWTime } from '../utils/time'

type FilterType = 'all' | 'warning' | 'critical'

function ruleType(fn: string): 'File' | 'Network' | 'Process' | null {
  if (!fn) return null
  if (fn.includes('file_permission') || fn.includes('sys_read') || fn.includes('sys_write') || fn.includes('sys_open')) return 'File'
  if (fn.includes('tcp_connect') || fn.includes('tcp_sendmsg') || fn.includes('udp')) return 'Network'
  if (fn.includes('execve') || fn.includes('bprm')) return 'Process'
  return null
}

function RuleTypeBadge({ fn }: { fn: string }) {
  const type = ruleType(fn)
  if (!type) return null
  const styles: Record<string, string> = {
    File: 'bg-orange-500/15 text-orange-700',
    Network: 'bg-blue-500/15 text-blue-700',
    Process: 'bg-purple-500/15 text-purple-700',
  }
  return (
    <Badge className={`${styles[type]} text-[10px] font-medium`}>{type} Rule</Badge>
  )
}

function SeverityBadge({ severity }: { severity: Severity }) {
  if (severity === 'critical') {
    return <Badge variant="destructive" className="font-medium">Critical</Badge>
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
  const diff = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000))
  const label = diff < 5 ? 'just now'
    : diff < 60 ? `${diff}s ago`
    : diff < 3600 ? `${Math.floor(diff / 60)}m ago`
    : diff < 86400 ? `${Math.floor(diff / 3600)}h ago`
    : `${Math.floor(diff / 86400)}d ago`
  return <span className="font-mono text-xs" title={formatTWTime(iso)}>{label}</span>
}

function DetailRow({ e }: { e: DisplayEvent }) {
  const items: { label: string; value: string }[] = []

  if (e.filePath)  items.push({ label: 'File',    value: e.filePath })
  if (e.netDest)   items.push({ label: 'Network', value: e.netDest })
  if (e.binary)    items.push({ label: 'Binary',  value: e.binary })
  // When the parent is runc, the "arguments" belong to runc (not to the
  // binary being exec'd), so merge them into the Parent line to avoid confusion.
  if (e.parentBin) {
    const isRuncParent = e.parentBin.includes('runc')
    const parentValue = isRuncParent && e.arguments
      ? `${e.parentBin} ${e.arguments}`
      : e.parentBin
    items.push({ label: 'Parent', value: parentValue })
    if (!isRuncParent && e.arguments) {
      items.push({ label: 'Arguments', value: e.arguments })
    }
  } else if (e.arguments) {
    items.push({ label: 'Arguments', value: e.arguments })
  }
  if (e.processUid !== undefined) {
    const user = e.processUid === 0 ? 'root (uid=0)' : `uid=${e.processUid}`
    items.push({ label: 'User', value: user })
  }
  if (e.namespace)  items.push({ label: 'Namespace', value: e.namespace })
  if (e.pod) {
    const podValue = e.container ? `${e.pod} / ${e.container}` : e.pod
    items.push({ label: 'Pod / Container', value: podValue })
  }
  if (e.policyName) items.push({ label: 'Policy',    value: e.policyName })
  if (e.function)   items.push({ label: 'Function',  value: e.function })
  if (e.nodeName)   items.push({ label: 'Node',      value: e.nodeName })
  items.push({ label: 'Time', value: formatTWTime(e.time) })

  return (
    <TableRow className="bg-muted/30 hover:bg-muted/30">
      <TableCell colSpan={7} className="py-3 pl-10 pr-6">
        <div className="flex flex-col gap-1 text-xs">
          {items.map(({ label, value }) => (
            <div key={label} className="flex min-w-0 gap-1.5">
              <span className="shrink-0 whitespace-nowrap text-muted-foreground">{label}:</span>
              <span className="font-mono min-w-0 flex-1" style={{ wordBreak: 'break-all', overflowWrap: 'break-word', whiteSpace: 'pre-wrap' }}>{value}</span>
            </div>
          ))}
        </div>
      </TableCell>
    </TableRow>
  )
}

export function SecurityEventsPage() {
  const { events, connected, error, reconnect, paused, pendingCount, togglePause } = useSecurityEvents()
  const [filter, setFilter] = useState<FilterType>('all')
  const [nsFilter, setNsFilter] = useState('all')
  const [podSearch, setPodSearch] = useState('')
  const [expanded, setExpanded] = useState<Set<string>>(new Set())

  const namespaces = [...new Set(events.map(e => e.namespace).filter(Boolean))].sort()

  // Stable key derived from event content so expansions survive new events prepending.
  // Use the stable unique ID assigned on event creation.
  // This ensures each event row is independently expandable even when multiple
  // events share the same pod/binary/policy/function combination.
  const eventKey = (e: DisplayEvent) => e.id

  const filtered = events.filter((e) => {
    if (filter === 'warning' && e.severity !== 'warning') return false
    if (filter === 'critical' && e.severity !== 'critical') return false
    if (nsFilter !== 'all' && e.namespace !== nsFilter) return false
    if (podSearch.trim() && !e.pod.toLowerCase().includes(podSearch.trim().toLowerCase())) return false
    return true
  })

  const warningCount = events.filter(e => e.severity === 'warning').length
  const criticalCount = events.filter(e => e.severity === 'critical').length

  const toggle = (key: string) =>
    setExpanded(prev => {
      const next = new Set(prev)
      next.has(key) ? next.delete(key) : next.add(key)
      return next
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

          <Button
            variant={paused ? 'default' : 'outline'}
            size="sm"
            className="h-9 gap-1.5"
            onClick={togglePause}
          >
            {paused ? '▶ Resume' : '⏸ Pause'}
            {paused && pendingCount > 0 && (
              <span className="rounded-full bg-primary-foreground/20 px-1.5 py-0.5 text-[10px] font-bold">
                +{pendingCount}
              </span>
            )}
          </Button>

          <Select value={nsFilter} onValueChange={setNsFilter}>
            <SelectTrigger className="h-9 w-40">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="all">All Namespaces</SelectItem>
                {namespaces.map(ns => (
                  <SelectItem key={ns} value={ns}>{ns}</SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>

          <Input
            placeholder="Search pod name..."
            value={podSearch}
            onChange={(e) => setPodSearch(e.target.value)}
            className="h-9 w-44"
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

      <Card className="overflow-x-hidden">
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
            <Table className="table-fixed">
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8" />
                  <TableHead className="w-24">Severity</TableHead>
                  <TableHead className="w-40">Rule / Detail</TableHead>
                  <TableHead className="w-28">Namespace</TableHead>
                  <TableHead className="w-52">Pod / Container</TableHead>
                  <TableHead className="w-36">Policy</TableHead>
                  <TableHead className="w-24">Time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((e) => {
                  const key = eventKey(e)
                  return (
                  <React.Fragment key={key}>
                    <TableRow
                      className={`cursor-pointer ${e.severity === 'critical' ? 'bg-destructive/5 hover:bg-destructive/10' : 'hover:bg-muted/50'}`}
                      onClick={() => toggle(key)}
                    >
                      <TableCell className="py-2 pl-3 pr-0">
                        {expanded.has(key)
                          ? <IconChevronDown size={14} className="text-muted-foreground" />
                          : <IconChevronRight size={14} className="text-muted-foreground" />}
                      </TableCell>
                      <TableCell>
                        <SeverityBadge severity={e.severity} />
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1.5">
                          <RuleTypeBadge fn={e.function} />
                          <span className="font-mono text-sm font-medium">
                            {e.binary ? e.binary.split('/').pop() : '—'}
                          </span>
                        </div>
                        {e.filePath && (
                          <p className="truncate font-mono text-xs text-muted-foreground max-w-[260px]" title={e.filePath}>
                            {e.filePath}
                          </p>
                        )}
                        {e.netDest && (
                          <p className="font-mono text-xs text-muted-foreground">{e.netDest}</p>
                        )}
                      </TableCell>
                      <TableCell className="text-sm truncate" title={e.namespace}>{e.namespace || '—'}</TableCell>
                      <TableCell className="text-sm">
                        <div className="truncate" title={e.pod + (e.container ? ' / ' + e.container : '')}>
                          {e.pod || '—'}
                          {e.container && (
                            <span className="text-xs text-muted-foreground"> / {e.container}</span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="max-w-[180px]">
                        {e.policyName
                          ? <Badge variant="outline" className="font-mono text-xs max-w-full truncate block" title={e.policyName}>{e.policyName}</Badge>
                          : '—'}
                      </TableCell>
                      <TableCell>
                        <RelativeTime iso={e.time} />
                      </TableCell>
                    </TableRow>
                    {expanded.has(key) && <DetailRow key={`detail-${key}`} e={e} />}
                  </React.Fragment>
                  )
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </>
  )
}
