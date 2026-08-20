import { useCallback, useEffect, useState } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { IconDownload, IconRefresh } from '@tabler/icons-react'
import { auditApi, type AuditEntry } from '../api/client'
import { formatTWTime } from '../utils/time'
import { downloadCSV } from '../utils/csv'

// A failed action is worth spotting: an attempt that was rejected still says
// what someone tried to do. Shown as words rather than the HTTP code, with the
// code kept on hover for anyone who wants it.
function statusText(status: number): string {
  if (status >= 200 && status < 300) return 'Success'
  switch (status) {
    case 400: return 'Rejected'
    case 401: return 'Unauthorized'
    case 403: return 'Denied'
    case 404: return 'Not found'
    case 409: return 'Conflict'
  }
  if (status >= 500) return 'Error'
  return 'Failed'
}

function StatusBadge({ status }: { status: number }) {
  const ok = status >= 200 && status < 300
  return (
    <Badge variant={ok ? 'secondary' : 'destructive'} className="text-[10px]" title={String(status)}>
      {statusText(status)}
    </Badge>
  )
}

export function AuditLogPage() {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try { setEntries(await auditApi.list()) } catch { /* ignore */ }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  const q = search.trim().toLowerCase()
  const filtered = q
    ? entries.filter(e =>
        e.user.toLowerCase().includes(q) ||
        e.action.toLowerCase().includes(q) ||
        (e.target ?? '').toLowerCase().includes(q))
    : entries

  // Exports what is on screen — the filter narrows the file too, which is the
  // usual intent when someone filters then exports.
  const exportCsv = () => {
    downloadCSV(
      'audit-log.csv',
      ['Time', 'User', 'Action', 'Target', 'Status', 'Method', 'Path'],
      filtered.map(e => [
        formatTWTime(e.time), e.user, e.action, e.target ?? '',
        statusText(e.status), e.method, e.path,
      ]),
    )
  }

  return (
    <>
      <div className="mb-4 flex items-start justify-between">
        <div>
          <h4 className="text-xl font-semibold">Audit Log</h4>
          <p className="text-sm text-muted-foreground">
            A record of every operation performed in Sentinel.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={exportCsv} disabled={filtered.length === 0}>
            <IconDownload size={14} className="mr-1" /> Export CSV
          </Button>
          <Button variant="outline" size="sm" onClick={load}>
            <IconRefresh size={14} className="mr-1" /> Refresh
          </Button>
        </div>
      </div>

      <div className="mb-3">
        <Input
          className="h-8 w-72 text-sm"
          placeholder="Filter by user, action or target..."
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
      </div>

      {!loading && filtered.length === 0 && (
        <p className="py-10 text-center text-sm text-muted-foreground">
          {entries.length === 0 ? 'No actions recorded yet.' : 'No entries match the filter.'}
        </p>
      )}

      {filtered.length > 0 && (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-44">Time</TableHead>
                  <TableHead className="w-32">User</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead className="w-20">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map(e => (
                  <TableRow key={e.id}>
                    <TableCell className="text-xs text-muted-foreground">{formatTWTime(e.time)}</TableCell>
                    <TableCell className="text-sm font-medium">{e.user || '—'}</TableCell>
                    <TableCell className="text-sm">{e.action}</TableCell>
                    <TableCell className="font-mono text-xs">{e.target || '—'}</TableCell>
                    <TableCell><StatusBadge status={e.status} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </>
  )
}
