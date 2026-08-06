import React, { useEffect, useRef, useState } from 'react'
import { IconActivity, IconChevronDown, IconChevronRight, IconWifi, IconWifiOff } from '@tabler/icons-react'
import { Card, CardContent } from '@/components/ui/card'
import {
  Table, TableHeader, TableBody, TableRow, TableHead, TableCell,
} from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { ScopeFilter, matchesScopeFilter } from '../components/ScopeFilter'
import { FilterPopover, matchesFilter } from '../components/FilterPopover'
import { useSecurityEvents, type DisplayEvent, type Severity } from '../layout/SecurityEventsProvider'
import { quarantineApi } from '../api/client'
import { useToast } from '../layout/AppToaster'
import { useAuth } from '../layout/AuthContext'
import { formatTWTime } from '../utils/time'
import { exportCSV } from '../utils/exportEvents'
import { RelativeTime } from '../components/RelativeTime'

function ruleType(fn: string): 'File' | 'Network' | 'Process' | null {
  if (!fn) return null
  if (fn.includes('file_permission') || fn.includes('sys_read') || fn.includes('sys_write') || fn.includes('sys_open')) return 'File'
  if (fn.includes('tcp_connect') || fn.includes('tcp_sendmsg') || fn.includes('udp') || fn.includes('inet_csk_accept') || fn.includes('deny')) return 'Network'
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


// QuarantineAction cuts the pod off from the network without killing it. It is
// offered per event rather than as a standing rule: this contains the one pod
// the event names, chosen by a person, and changes nothing about future events.
function QuarantineAction({ e }: { e: DisplayEvent }) {
  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState(false)
  const toast = useToast()
  const { user } = useAuth()

  if (user?.role !== 'admin' || !e.pod || !e.namespace) return null

  const run = async () => {
    setBusy(true)
    try {
      await quarantineApi.add(e.namespace, e.pod)
      setDone(true)
      toast.success(`${e.pod} quarantined — network cut off, container left running`)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : `Could not quarantine ${e.pod}`)
    } finally {
      setBusy(false)
    }
  }

  if (done) {
    return (
      <p className="mt-2 text-xs text-muted-foreground">
        Quarantined. Release it from the Quarantine page.
      </p>
    )
  }
  return (
    <Button
      variant="outline"
      size="sm"
      className="mt-2 h-7 w-fit border-red-300 text-xs text-red-600 hover:bg-red-50 hover:text-red-700"
      disabled={busy}
      onClick={run}
    >
      {busy ? 'Quarantining…' : 'Quarantine this pod'}
    </Button>
  )
}

function DetailRow({ e }: { e: DisplayEvent }) {
  const items: { label: string; value: string }[] = []

  if (e.filePath) {
    const opLabel = e.fileOp ? `File (${e.fileOp})` : 'File'
    items.push({ label: opLabel, value: e.filePath })
  }
  const isInbound = e.function === 'inet_csk_accept'
  if (e.netDest)   items.push({ label: isInbound ? 'Inbound From' : 'Destination', value: e.netDest })
  if (e.netSrc)    items.push({ label: isInbound ? 'Service Port' : 'Source',      value: e.netSrc })
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
    // A network denial lists every container of the pod, because they share one
    // network namespace and one IP — the flow cannot say which opened the
    // connection. Say so, otherwise the list reads as "all of them did it".
    if ((e.container ?? '').includes(', ') && (e.function ?? '').includes('deny')) {
      items.push({
        label: 'Container',
        value: 'cannot be narrowed — all containers in a pod share one network namespace',
      })
    }
  }
  if (e.policyName) items.push({ label: 'Policy',    value: e.policyName })
  if (e.function)   items.push({ label: 'Function',  value: e.function })
  if (e.dropReason) items.push({ label: 'Drop Reason', value: e.dropReason })
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
        <QuarantineAction e={e} />
      </TableCell>
    </TableRow>
  )
}

export function SecurityEventsPage() {
  // Use the shared SSE provider — single connection for all consumers
  const { events: allEvents, connected, reconnect } = useSecurityEvents()

  // Pause/Resume: buffer incoming events locally while paused
  const [paused, setPaused] = useState(false)
  const [pendingCount, setPendingCount] = useState(0)
  const pendingRef = useRef<DisplayEvent[]>([])
  const prevLengthRef = useRef(allEvents.length)
  const [displayEvents, setDisplayEvents] = useState<DisplayEvent[]>([])
  const error = ''

  useEffect(() => {
    if (paused) {
      // Accumulate new events as pending
      if (allEvents.length !== prevLengthRef.current) {
        const newOnes = allEvents.filter(e => !displayEvents.some(d => d.id === e.id))
        pendingRef.current = [...newOnes, ...pendingRef.current]
        setPendingCount(pendingRef.current.length)
        prevLengthRef.current = allEvents.length
      }
    } else {
      setDisplayEvents(allEvents)
      prevLengthRef.current = allEvents.length
    }
  }, [allEvents, paused])

  const events = paused ? displayEvents : allEvents

  const togglePause = () => {
    const nowPaused = !paused
    setPaused(nowPaused)
    if (!nowPaused) {
      pendingRef.current = []
      setPendingCount(0)
      setDisplayEvents(allEvents)
    }
  }
  // Empty means no filter, for both — see matchesFilter.
  const [severities, setSeverities] = useState<string[]>([])
  const [ruleTypes, setRuleTypes] = useState<string[]>([])
  const [namespaceFilter, setNamespaceFilter] = useState<string[]>([])
  const [podSearch, setPodSearch] = useState('')
  const [expanded, setExpanded] = useState<Set<string>>(new Set())

  const namespaces = [...new Set(events.map(e => e.namespace).filter(Boolean))].sort()

  // Stable key derived from event content so expansions survive new events prepending.
  // Use the stable unique ID assigned on event creation.
  // This ensures each event row is independently expandable even when multiple
  // events share the same pod/binary/policy/function combination.
  const eventKey = (e: DisplayEvent) => e.id

  const filtered = events.filter((e) => {
    if (!matchesFilter(severities, e.severity)) return false
    if (!matchesFilter(ruleTypes, ruleType(e.function ?? ''))) return false
    if (!matchesScopeFilter('namespaced', e.namespace, namespaceFilter)) return false
    if (podSearch.trim() && !e.pod.toLowerCase().includes(podSearch.trim().toLowerCase())) return false
    return true
  })

  const warningCount = filtered.filter(e => e.severity === 'warning').length
  const criticalCount = filtered.filter(e => e.severity === 'critical').length
  const isFiltered = severities.length > 0 || ruleTypes.length > 0 ||
    namespaceFilter.length > 0 || podSearch.trim() !== ''

  const toggle = (key: string) =>
    setExpanded(prev => {
      const next = new Set(prev)
      next.has(key) ? next.delete(key) : next.add(key)
      return next
    })

  return (
    <>
      {/* Row 1: title + actions */}
      <div className="mb-4 flex items-start justify-between">
        <div>
          <h4 className="text-xl font-semibold">Security Events</h4>
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
            className="h-8 gap-1.5"
            onClick={togglePause}
          >
            {paused ? '▶ Resume' : '⏸ Pause'}
            {paused && pendingCount > 0 && (
              <span className="rounded-full bg-primary-foreground/20 px-1.5 py-0.5 text-[10px] font-bold">
                +{pendingCount}
              </span>
            )}
          </Button>

          <Button variant="outline" size="sm" className="h-8"
            onClick={() => exportCSV(filtered)}>
            Export CSV
          </Button>
        </div>
      </div>

      {/* Row 2: filters — pod search leftmost */}
      <div className="mb-4 flex items-center gap-2">
        <Input
          placeholder="Search pod name..."
          value={podSearch}
          onChange={(e) => setPodSearch(e.target.value)}
          className="h-8 w-56 text-sm"
        />
        <ScopeFilter
          value={namespaceFilter}
          onChange={setNamespaceFilter}
          namespaces={namespaces}
          includeCluster={false}
        />
        <FilterPopover sections={[
          {
            label: 'Severity',
            value: severities,
            onChange: setSeverities,
            options: [
              { key: 'warning', label: 'Warning' },
              { key: 'critical', label: 'Critical' },
            ],
          },
          {
            label: 'Rule',
            value: ruleTypes,
            onChange: setRuleTypes,
            options: [
              { key: 'Process', label: 'Process' },
              { key: 'File', label: 'File' },
              { key: 'Network', label: 'Network' },
            ],
          },
        ]} />
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
            {filtered.length} events{isFiltered ? ' (filtered)' : ''}
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
                      <TableCell className="overflow-hidden">
                        <div className="flex items-center gap-1.5 min-w-0">
                          <RuleTypeBadge fn={e.function ?? ''} />
                          <span className="font-mono text-sm font-medium truncate" title={e.binary ?? ''}>
                            {e.binary ? e.binary.split('/').pop() : '—'}
                          </span>
                        </div>
                        {e.filePath && (
                          <p className="truncate font-mono text-xs text-muted-foreground" title={e.filePath}>
                            {e.filePath}
                          </p>
                        )}
                        {e.netDest && (
                          <p className="truncate font-mono text-xs text-muted-foreground"
                            title={e.function === 'inet_csk_accept' ? `← ${e.netDest}` : `→ ${e.netDest}`}>
                            {e.function === 'inet_csk_accept' ? '←' : '→'} {e.netDest}
                          </p>
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
