import { useEffect, useRef, useState } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import {
  Table, TableHeader, TableBody, TableRow, TableHead, TableCell,
} from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { type AdmissionEvent } from '../api/client'
import { formatTWTime } from '../utils/time'

export function AdmissionEventsPage() {
  const [events, setEvents] = useState<AdmissionEvent[]>([])
  const [search, setSearch] = useState('')
  const [nsFilter, setNsFilter] = useState('all')
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
    if (search && !e.involvedName.toLowerCase().includes(search.toLowerCase()) &&
        !e.policyName.toLowerCase().includes(search.toLowerCase())) return false
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
        <Button variant="ghost" size="sm" className="text-xs text-muted-foreground"
          onClick={() => setEvents([])}>Clear</Button>
      </div>

      <div className="mb-4 flex items-center gap-2">
        <Input placeholder="Search name or policy..."
          value={search} onChange={e => setSearch(e.target.value)}
          className="h-8 w-56 text-sm" />
        <select
          value={nsFilter}
          onChange={e => setNsFilter(e.target.value)}
          className="h-8 rounded-md border bg-background px-2 text-sm"
        >
          <option value="all">All Namespaces</option>
          {namespaces.map(ns => <option key={ns} value={ns}>{ns}</option>)}
        </select>
        <span className="ml-auto text-xs text-muted-foreground">
          {filtered.length} event{filtered.length !== 1 ? 's' : ''}
        </span>
      </div>

      <Card>
        <CardContent className="p-0">
          {filtered.length === 0 ? (
            <div className="py-16 text-center text-sm text-muted-foreground">
              <p>No admission violation events.</p>
              <p className="mt-1 text-xs">Events appear when controller-managed resources (e.g. Pods) are denied by VAP.</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8" />
                  <TableHead>Time</TableHead>
                  <TableHead>Namespace</TableHead>
                  <TableHead>Resource</TableHead>
                  <TableHead>Policy</TableHead>
                  <TableHead>Binding</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map(e => (
                  <>
                    <TableRow
                      key={e.id}
                      className="cursor-pointer bg-destructive/5 hover:bg-destructive/10"
                      onClick={() => toggle(e.id)}
                    >
                      <TableCell className="py-2 pl-3 pr-0 text-muted-foreground text-xs">
                        {expanded.has(e.id) ? '▾' : '▸'}
                      </TableCell>
                      <TableCell className="text-sm">{formatTWTime(e.time)}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">{e.namespace || '—'}</TableCell>
                      <TableCell className="text-sm">
                        <span className="text-muted-foreground text-xs">{e.involvedKind} </span>
                        <span className="font-medium">{e.involvedName || '—'}</span>
                      </TableCell>
                      <TableCell>
                        <Badge variant="destructive" className="font-mono text-[10px] max-w-[180px] truncate block" title={e.policyName}>
                          {e.policyName || '—'}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground truncate max-w-[160px]" title={e.bindingName}>
                        {e.bindingName || '—'}
                      </TableCell>
                    </TableRow>
                    {expanded.has(e.id) && (
                      <TableRow key={`detail-${e.id}`} className="bg-muted/30 hover:bg-muted/30">
                        <TableCell colSpan={6} className="py-3 pl-10 pr-6">
                          <div className="flex flex-col gap-1 text-xs">
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
