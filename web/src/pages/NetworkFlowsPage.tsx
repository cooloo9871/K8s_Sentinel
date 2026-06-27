import { useState } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { IconWifi, IconWifiOff, IconAlertTriangle } from '@tabler/icons-react'
import { useCilium } from '../layout/CiliumProvider'
import { RelativeTime } from '../components/RelativeTime'
import type { CiliumFlow } from '../api/client'

function VerdictBadge({ verdict }: { verdict: string }) {
  if (verdict === 'allowed') return <Badge variant="secondary" className="text-[10px] bg-green-500/10 text-green-700">Allowed</Badge>
  if (verdict === 'dropped') return <Badge variant="destructive" className="text-[10px]">Dropped</Badge>
  return <Badge variant="outline" className="text-[10px]">{verdict}</Badge>
}

function endpoint(ip: string, pod: string, ns: string) {
  if (pod) return <span><span className="text-muted-foreground text-[10px]">{ns}/</span>{pod}</span>
  return <span className="font-mono text-xs">{ip}</span>
}

function FlowRow({ f }: { f: CiliumFlow }) {
  const port = f.dstPort ? `:${f.dstPort}` : ''
  const l7 = f.l7Type && (
    <span className="ml-1 text-[10px] text-blue-600 font-medium">{f.l7Type}
      {f.httpMethod && ` ${f.httpMethod}`}
      {f.httpStatus ? ` ${f.httpStatus}` : ''}
      {f.dnsQuery ? ` ${f.dnsQuery}` : ''}
    </span>
  )

  return (
    <TableRow className={f.verdict === 'dropped' ? 'bg-destructive/5' : ''}>
      <TableCell><VerdictBadge verdict={f.verdict} /></TableCell>
      <TableCell className="text-sm">{endpoint(f.srcIP, f.srcPod, f.srcNs)}</TableCell>
      <TableCell className="text-muted-foreground text-xs">→</TableCell>
      <TableCell className="text-sm">
        {endpoint(f.dstIP, f.dstPod, f.dstNs)}
        <span className="text-muted-foreground">{port}</span>
        {l7}
      </TableCell>
      <TableCell className="text-xs text-muted-foreground">{f.protocol}</TableCell>
      <TableCell className="text-muted-foreground text-xs">{f.nodeName}</TableCell>
      <TableCell><RelativeTime iso={f.time} /></TableCell>
    </TableRow>
  )
}

export function NetworkFlowsPage() {
  const { flows, status, connected } = useCilium()
  const [search, setSearch] = useState('')
  const [verdict, setVerdict] = useState('all')
  const [proto, setProto] = useState('all')

  // Not available
  if (!status) return (
    <div className="flex items-center justify-center py-24 text-muted-foreground text-sm">
      Checking Cilium status…
    </div>
  )
  if (!status.available) return (
    <div className="flex flex-col items-center justify-center gap-3 py-24 text-muted-foreground">
      <IconAlertTriangle size={36} strokeWidth={1.5} />
      <p className="text-base font-medium">Cilium CNI not detected</p>
      <p className="text-sm">Network Flows requires Cilium as the cluster CNI.</p>
    </div>
  )
  if (!status.ready) return (
    <div className="flex flex-col items-center justify-center gap-3 py-24 text-muted-foreground">
      <IconAlertTriangle size={36} strokeWidth={1.5} />
      <p className="text-base font-medium">Hubble agent not ready</p>
      <p className="text-sm max-w-sm text-center">
        Enable Hubble in Cilium config: <code className="font-mono text-xs bg-muted px-1 py-0.5 rounded">enable-hubble: "true"</code>
        {status.message && <span className="block mt-1 text-xs">{status.message}</span>}
      </p>
    </div>
  )

  const filtered = flows.filter(f => {
    if (verdict !== 'all' && f.verdict !== verdict) return false
    if (proto !== 'all' && f.protocol !== proto) return false
    if (search) {
      const q = search.toLowerCase()
      if (!f.srcPod.toLowerCase().includes(q) &&
          !f.dstPod.toLowerCase().includes(q) &&
          !f.srcIP.includes(q) &&
          !f.dstIP.includes(q) &&
          !f.srcNs.toLowerCase().includes(q) &&
          !f.dstNs.toLowerCase().includes(q) &&
          !(f.httpURL ?? '').toLowerCase().includes(q) &&
          !(f.dnsQuery ?? '').toLowerCase().includes(q)) return false
    }
    return true
  })

  return (
    <>
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h4 className="text-xl font-semibold">Network Flows</h4>
          <p className="text-sm text-muted-foreground">Real-time L3/L4/L7 flows via Cilium Hubble agent.</p>
        </div>
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          {connected
            ? <><IconWifi size={14} className="text-green-500" />Connected</>
            : <><IconWifiOff size={14} />Disconnected</>}
        </div>
      </div>

      <Card>
        <div className="flex items-center gap-3 border-b px-4 py-3">
          <div className="relative flex-1 max-w-xs">
            <Input
              placeholder="Search pod / IP / path…"
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="h-8 text-sm pl-8"
            />
          </div>
          <Select value={verdict} onValueChange={setVerdict}>
            <SelectTrigger className="h-8 w-32 text-xs">
              <SelectValue placeholder="Verdict" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="all">All verdicts</SelectItem>
                <SelectItem value="allowed">Allowed</SelectItem>
                <SelectItem value="dropped">Dropped</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>
          <Select value={proto} onValueChange={setProto}>
            <SelectTrigger className="h-8 w-28 text-xs">
              <SelectValue placeholder="Protocol" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="all">All proto</SelectItem>
                <SelectItem value="TCP">TCP</SelectItem>
                <SelectItem value="UDP">UDP</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>
          <span className="text-xs text-muted-foreground ml-auto">{filtered.length} flows</span>
        </div>

        <CardContent className="p-0">
          {filtered.length === 0 ? (
            <div className="py-16 text-center text-sm text-muted-foreground">
              {flows.length === 0 ? 'Waiting for flows…' : 'No flows match the filter.'}
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-24">Verdict</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead className="w-6"></TableHead>
                  <TableHead>Destination</TableHead>
                  <TableHead className="w-16">Proto</TableHead>
                  <TableHead className="w-24">Node</TableHead>
                  <TableHead className="w-24">Time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((f, i) => <FlowRow key={i} f={f} />)}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </>
  )
}
