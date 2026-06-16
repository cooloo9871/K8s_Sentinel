import { useEffect, useRef, useState } from 'react'
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

export function AdmissionEventsPage() {
  const [events, setEvents] = useState<AdmissionEvent[]>([])
  const [search, setSearch] = useState('')
  const [nsFilter, setNsFilter] = useState('all')
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all')
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const esRef = useRef<EventSource | null>(null)

  const namespaces = [...new Set(events.map(e => e.namespace).filter(Boolean))].sort()

  useEffect(() => {
    const es = new EventSource('/api/admission-events/stream')
    esRef.current = es
    es.onmessage = (e) => {
      try {
        const evt: AdmissionEvent = JSON.parse(e.data)
        setEvents(prev => {
          if (prev.some(x => x.id === evt.id)) return prev
          return [evt, ...prev].slice(0, 500)
        })
      } catch { /* ignore */ }
    }
    return () => es.close()
  }, [])

  const toggle = (id: string) =>
    setExpanded(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })

  const filtered = events.filter(e => {
    if (nsFilter !== 'all' && e.namespace !== nsFilter) return false
    if (severityFilter !== 'all' && e.severity !== severityFilter) return false
    if (search) {
      const q = search.toLowerCase()
      if (!e.involvedName.toLowerCase().includes(q) &&
          !e.name.toLowerCase().includes(q) &&
          !e.policyName.toLowerCase().includes(q)) return false
    }
    return true
  })

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
        <span className="ml-auto text-xs text-muted-foreground">
          {filtered.length} event{filtered.length !== 1 ? 's' : ''}
        </span>
      </div>

      <Card>
        <CardContent className="p-0">
          {filtered.length === 0 ? (
            <div className="py-10 text-center text-sm text-muted-foreground flex flex-col items-center gap-2">
              <p>No admission violation events.</p>
              <p className="text-xs max-w-lg">
                Only controller-managed resource denials (e.g. Pods) appear without audit log.
                For complete coverage including direct <code className="font-mono">kubectl apply</code> denials,
                configure the kube-apiserver audit webhook to POST to{' '}
                <code className="font-mono">/api/admission-events/webhook</code>.
              </p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8" />
                  <TableHead>Severity</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Namespace</TableHead>
                  <TableHead>Resource / Name</TableHead>
                  <TableHead>Policy</TableHead>
                  <TableHead>Time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map(e => (
                  <>
                    <TableRow
                      key={e.id}
                      className={`cursor-pointer ${e.severity === 'critical' ? 'bg-destructive/5 hover:bg-destructive/10' : 'hover:bg-muted/50'}`}
                      onClick={() => toggle(e.id)}
                    >
                      <TableCell className="py-2 pl-3 pr-0 text-muted-foreground text-xs">
                        {expanded.has(e.id) ? '▾' : '▸'}
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
                      <TableCell className="text-sm text-muted-foreground">{e.namespace || '—'}</TableCell>
                      <TableCell className="text-sm">
                        {e.source === 'audit' ? (
                          <>
                            <span className="text-muted-foreground text-xs capitalize">{e.operation} </span>
                            <span className="text-muted-foreground text-xs">{e.resource}</span>
                            <span className="text-muted-foreground text-xs"> / </span>
                            <span className="font-medium">{e.name || '—'}</span>
                          </>
                        ) : (
                          <>
                            <span className="text-muted-foreground text-xs capitalize">{e.operation || 'create'} </span>
                            <span className="text-muted-foreground text-xs">{e.involvedKind?.toLowerCase() || ''}s</span>
                            <span className="text-muted-foreground text-xs"> / </span>
                            <span className="font-medium">{e.involvedName || '—'}</span>
                          </>
                        )}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="font-mono text-xs max-w-[180px] truncate block" title={e.policyName}>
                          {e.policyName || '—'}
                        </Badge>
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
                                    ? `${e.resource}/${e.name}`
                                    : `${e.involvedKind?.toLowerCase()}s/${e.involvedName}`}
                                </span>
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
                  </>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </>
  )
}
