import { Fragment, useEffect, useRef, useState } from 'react' // useRef kept for esRef
import { useAdmissionRetention } from '../layout/AdmissionRetentionContext'
import { Card, CardContent } from '@/components/ui/card'
import {
  Table, TableHeader, TableBody, TableRow, TableHead, TableCell,
} from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { type AdmissionEvent } from '../api/client'
import {
  Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import { formatTWTime } from '../utils/time'
import { IconChevronDown, IconChevronRight } from '@tabler/icons-react'

function RelativeTime({ iso }: { iso: string }) {
  if (!iso) return <span className="text-muted-foreground">—</span>
  const d = new Date(iso)
  if (isNaN(d.getTime())) return <span className="font-mono text-xs">{iso}</span>
  const diff = Math.floor((Date.now() - d.getTime()) / 60000)
  const label = diff < 1 ? 'just now'
    : diff < 60 ? `${diff}m ago`
    : diff < 1440 ? `${Math.floor(diff / 60)}h ago`
    : `${Math.floor(diff / 1440)}d ago`
  return <span className="font-mono text-xs" title={formatTWTime(iso)}>{label}</span>
}

type SeverityFilter = 'all' | 'warning' | 'critical'
type SourceFilter = 'all' | 'audit' | 'k8s-event'

export function AdmissionEventsPage() {
  const [events, setEvents] = useState<AdmissionEvent[]>([])
  const [search, setSearch] = useState('')
  const [nsFilter, setNsFilter] = useState('all')
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all')
  const [sourceFilter, setSourceFilter] = useState<SourceFilter>('audit')
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const esRef = useRef<EventSource | null>(null)
  const { maxEvents, maxEventsRef, loaded } = useAdmissionRetention()
  // Trim existing events whenever the cap decreases.
  useEffect(() => {
    setEvents(prev => prev.length > maxEvents ? prev.slice(0, maxEvents) : prev)
  }, [maxEvents])

  const sourceVisible = sourceFilter === 'all' ? events : events.filter(e => e.source === sourceFilter)
  const namespaces = [...new Set(sourceVisible.map(e => e.namespace).filter(Boolean))].sort()



  // Wait for retention fetch before opening SSE so the cap is correct from the first message.
  useEffect(() => {
    if (!loaded) return
    const es = new EventSource('/api/admission-events/stream')
    esRef.current = es
    es.onmessage = (e) => {
      try {
        const evt: AdmissionEvent = JSON.parse(e.data)
        setEvents(prev => {
          if (prev.some(x => x.id === evt.id)) return prev
          return [evt, ...prev].slice(0, maxEventsRef.current)
        })
      } catch { /* ignore */ }
    }
    return () => es.close()
  }, [loaded]) // eslint-disable-line react-hooks/exhaustive-deps

  const toggle = (id: string) =>
    setExpanded(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })

  const filtered = events.filter(e => {
    if (nsFilter !== 'all' && e.namespace !== nsFilter) return false
    if (severityFilter !== 'all' && e.severity !== severityFilter) return false
    if (sourceFilter !== 'all' && e.source !== sourceFilter) return false
    if (search) {
      const q = search.toLowerCase()
      if (!e.involvedName.toLowerCase().includes(q) &&
          !e.name.toLowerCase().includes(q) &&
          !e.policyName.toLowerCase().includes(q)) return false
    }
    return true
  })

  const warningCount = filtered.filter(e => e.severity === 'warning').length
  const criticalCount = filtered.filter(e => e.severity === 'critical').length
  const isFiltered = severityFilter !== 'all' || sourceFilter !== 'audit' || nsFilter !== 'all' || search.trim() !== ''

  return (
    <>
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h4 className="text-xl font-semibold">Admission Events</h4>
          <p className="text-sm text-muted-foreground">
            ValidatingAdmissionPolicy violations captured from Kubernetes Warning events.
          </p>
        </div>
      </div>

      <div className="mb-4 flex items-center gap-2">
        <Input placeholder="Search name or policy..."
          value={search} onChange={e => setSearch(e.target.value)}
          className="h-8 w-56 text-sm" />
        <Select value={nsFilter} onValueChange={setNsFilter}>
          <SelectTrigger className="h-8 w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              <SelectItem value="all">All Namespaces</SelectItem>
              {namespaces.map(ns => <SelectItem key={ns} value={ns}>{ns}</SelectItem>)}
            </SelectGroup>
          </SelectContent>
        </Select>
        <Select value={severityFilter} onValueChange={v => setSeverityFilter(v as SeverityFilter)}>
          <SelectTrigger className="h-8 w-36">
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
        <Select value={sourceFilter} onValueChange={v => { setSourceFilter(v as SourceFilter); setNsFilter('all') }}>
          <SelectTrigger className="h-8 w-36">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              <SelectItem value="all">All Sources</SelectItem>
              <SelectItem value="audit">Audit Log</SelectItem>
              <SelectItem value="k8s-event">K8s Event</SelectItem>
            </SelectGroup>
          </SelectContent>
        </Select>
      </div>

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
            <div className="py-10 text-center text-sm text-muted-foreground flex flex-col items-center gap-2">
              {events.length === 0 ? (
                <>
                  <p>No admission violation events yet.</p>
                  <p className="text-xs max-w-lg">
                    To see violations here, configure the Kubernetes audit webhook to send events to K8s Sentinel:
                  </p>
                  <code className="text-xs bg-muted px-2 py-1 rounded font-mono">
                    POST /api/admission-events/webhook
                  </code>
                </>
              ) : (
                <p>No events match the current filters.</p>
              )}
            </div>
          ) : (
            <Table className="table-fixed">
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8" />
                  <TableHead className="w-24">Severity</TableHead>
                  <TableHead className="w-24">Source</TableHead>
                  <TableHead className="w-28">Namespace</TableHead>
                  <TableHead className="w-44">Resource / Name</TableHead>
                  <TableHead className="w-44">Policy</TableHead>
                  <TableHead className="w-24">Time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map(e => (
                  <Fragment key={e.id}>
                    <TableRow
                      className={`cursor-pointer ${e.severity === 'critical' ? 'bg-destructive/5 hover:bg-destructive/10' : 'hover:bg-muted/50'}`}
                      onClick={() => toggle(e.id)}
                    >
                      <TableCell className="py-2 pl-3 pr-0">
                        {expanded.has(e.id)
                          ? <IconChevronDown size={14} className="text-muted-foreground" />
                          : <IconChevronRight size={14} className="text-muted-foreground" />}
                      </TableCell>
                      <TableCell>
                        {e.severity === 'critical'
                          ? <Badge variant="destructive" className="font-medium">Critical</Badge>
                          : <Badge className="font-medium bg-amber-500/15 text-amber-700 hover:bg-amber-500/15">Warning</Badge>
                        }
                      </TableCell>
                      <TableCell>
                        <Badge variant={e.source === 'audit' ? 'default' : 'secondary'}>
                          {e.source === 'audit' ? 'audit log' : 'k8s event'}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm truncate" title={e.namespace}>{e.namespace || '—'}</TableCell>
                      <TableCell className="text-sm">
                        {e.source === 'audit' ? (
                          <div className="truncate" title={`${e.resource} / ${e.name || '—'}`}>
                            {e.resource && (
                              <span className="text-muted-foreground">{e.resource} / </span>
                            )}
                            {e.name || '—'}
                          </div>
                        ) : (
                          <div className="truncate" title={`${e.involvedKind?.toLowerCase() || ''}s / ${e.involvedName || '—'}`}>
                            {e.involvedKind && (
                              <span className="text-muted-foreground">{e.involvedKind.toLowerCase()}s / </span>
                            )}
                            {e.involvedName || '—'}
                          </div>
                        )}
                      </TableCell>
                      <TableCell className="max-w-[180px]">
                        {e.policyName
                          ? <Badge variant="outline" className="font-mono text-xs max-w-full truncate block" title={e.policyName}>{e.policyName}</Badge>
                          : '—'}
                      </TableCell>
                      <TableCell><RelativeTime iso={e.time} /></TableCell>
                    </TableRow>
                    {expanded.has(e.id) && (
                      <TableRow key={`detail-${e.id}`} className="bg-muted/30 hover:bg-muted/30">
                        <TableCell colSpan={7} className="py-3 pl-10 pr-6">
                          <div className="flex flex-col gap-1 text-xs">
                            {(e.resource || e.involvedKind) && (
                              <div className="flex gap-1.5">
                                <span className="shrink-0 text-muted-foreground">Object:</span>
                                <span className="font-mono">
                                  {e.source === 'audit'
                                    ? `${e.resource}/${e.name || '—'}`
                                    : `${e.involvedKind?.toLowerCase()}s/${e.involvedName}`}
                                </span>
                              </div>
                            )}
                            {e.operation && (
                              <div className="flex gap-1.5">
                                <span className="shrink-0 text-muted-foreground">Action:</span>
                                <span className="font-mono">{e.operation}</span>
                              </div>
                            )}
                            <div className="flex gap-1.5">
                              <span className="shrink-0 text-muted-foreground">Violation:</span>
                              <span className="font-mono" style={{ wordBreak: 'break-all' }}>{e.message}</span>
                            </div>
                            <div className="flex gap-1.5">
                              <span className="shrink-0 text-muted-foreground">Policy:</span>
                              <span className="font-mono">{e.policyName}</span>
                            </div>
                            <div className="flex gap-1.5">
                              <span className="shrink-0 text-muted-foreground">Binding:</span>
                              <span className="font-mono">{e.bindingName}</span>
                            </div>
                            {e.username && (
                              <div className="flex gap-1.5">
                                <span className="shrink-0 text-muted-foreground">Requestor:</span>
                                <span className="font-mono">{e.username}</span>
                              </div>
                            )}
                            <div className="flex gap-1.5">
                              <span className="shrink-0 text-muted-foreground">Time:</span>
                              <span>{formatTWTime(e.time)}</span>
                            </div>
                          </div>
                        </TableCell>
                      </TableRow>
                    )}
                  </Fragment>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </>
  )
}
