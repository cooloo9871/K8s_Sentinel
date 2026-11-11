import { Fragment, useCallback, useEffect, useRef, useState } from 'react'
import { vulnApi } from '../api/client'
import type { ImageVuln, VulnDetail, VulnOverview, WorkloadVuln } from '../api/client'
import { Card, CardContent } from '@/components/ui/card'
import {
  Table, TableHeader, TableBody, TableRow, TableHead, TableCell,
} from '@/components/ui/table'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { ScopeFilter } from '../components/ScopeFilter'
import { FilterPopover } from '../components/FilterPopover'
import { RelativeTime } from '../components/RelativeTime'
import { downloadCSV } from '../utils/csv'
import {
  filterWorkloads, workloadCsvRows, workloadKey, WORKLOAD_CSV_HEADERS,
} from '../utils/vulnerabilities'
import {
  IconChevronDown, IconChevronRight, IconDownload, IconRefresh,
} from '@tabler/icons-react'

// How many findings an expanded workload shows before asking. A base image can
// carry hundreds, and the ones worth reading are sorted to the top.
const DETAIL_PAGE = 50

const SEVERITY_CLASS: Record<string, string> = {
  CRITICAL: 'bg-destructive/15 text-destructive hover:bg-destructive/15',
  HIGH: 'bg-orange-500/15 text-orange-700 hover:bg-orange-500/15',
  MEDIUM: 'bg-amber-500/15 text-amber-700 hover:bg-amber-500/15',
}
const SEVERITY_MUTED = 'bg-muted text-muted-foreground hover:bg-muted'

function SeverityBadge({ severity }: { severity: string }) {
  const label = severity.charAt(0) + severity.slice(1).toLowerCase()
  return <Badge className={`font-medium ${SEVERITY_CLASS[severity] ?? SEVERITY_MUTED}`}>{label}</Badge>
}

// A count in the list. Zero recedes so the eye lands on what is there, and a
// workload with no report shows a dash, since zero would claim it is clean.
function Count({ value, scanned, className }: { value: number; scanned: boolean; className: string }) {
  if (!scanned) return <span className="text-muted-foreground">—</span>
  if (value === 0) return <span className="text-muted-foreground">0</span>
  return <span className={`font-semibold ${className}`}>{value}</span>
}

// The list has room for the name and tag, which are what tell images apart;
// the registry and path are in the tooltip and the expanded row.
const shortImage = (image: string) => image.slice(image.lastIndexOf('/') + 1)

type Detail = VulnDetail | 'loading' | 'error'

export function VulnerabilitiesPage() {
  const [overview, setOverview] = useState<VulnOverview | null>(null)
  const [loadError, setLoadError] = useState('')
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [namespaceFilter, setNamespaceFilter] = useState<string[]>([])
  const [severities, setSeverities] = useState<string[]>([])
  const [flags, setFlags] = useState<string[]>([])
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [details, setDetails] = useState<Record<string, Detail>>({})
  const [showAll, setShowAll] = useState<Set<string>>(new Set())

  // Bumped on every load, so findings requested before a refresh are dropped
  // when they arrive after it instead of being shown against the new list.
  const generation = useRef(0)

  const load = useCallback(async (refresh = false) => {
    setLoading(true)
    try {
      const next = await vulnApi.overview(refresh)
      generation.current++
      setOverview(next)
      setLoadError('')
      // Findings already fetched may describe an older scan.
      setDetails({})
      setExpanded(new Set())
      setShowAll(new Set())
    } catch (e) {
      setLoadError(e instanceof Error && e.message ? e.message : 'Failed to load vulnerabilities')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const toggle = (w: WorkloadVuln) => {
    const key = workloadKey(w)
    const opening = !expanded.has(key)
    setExpanded(prev => {
      const next = new Set(prev)
      opening ? next.add(key) : next.delete(key)
      return next
    })
    if (opening && w.scan !== 'none' && typeof details[key] !== 'object') {
      const asked = generation.current
      const settle = (d: Detail) => {
        if (generation.current === asked) setDetails(prev => ({ ...prev, [key]: d }))
      }
      settle('loading')
      vulnApi.detail(w.namespace, w.kind, w.name).then(settle).catch(() => settle('error'))
    }
  }

  const header = (actions?: React.ReactNode) => (
    <div className="mb-4 flex items-start justify-between">
      <div>
        <h4 className="text-xl font-semibold">Vulnerabilities</h4>
        <p className="text-sm text-muted-foreground">
          Known vulnerabilities in the images of running workloads, as reported by Trivy Operator.
        </p>
      </div>
      <div className="flex gap-2">
        {actions}
        <Button variant="outline" size="sm" onClick={() => load(true)} disabled={loading}>
          <IconRefresh size={14} className="mr-1" /> Refresh
        </Button>
      </div>
    </div>
  )

  const notice = (title: string, body: React.ReactNode) => (
    <>
      {header()}
      <Card>
        <CardContent className="flex flex-col items-center gap-2 py-10 text-center text-sm">
          <p className="font-medium">{title}</p>
          <div className="max-w-xl text-muted-foreground">{body}</div>
        </CardContent>
      </Card>
    </>
  )

  if (!overview) {
    return loadError
      ? notice('Vulnerabilities could not be loaded.', <p>{loadError}</p>)
      : notice('Loading...', null)
  }

  if (overview.status === 'not-installed') {
    return notice('Trivy Operator was not found in this cluster.', (
      <>
        <p>
          Sentinel does not scan images itself. It shows the reports Trivy Operator produces,
          so nothing has been scanned and this page has nothing to show.
        </p>
        <p className="mt-2">
          The install steps are in <span className="font-mono text-xs">docs/install.md</span>,
          under Vulnerability scanning.
        </p>
      </>
    ))
  }
  if (overview.status === 'forbidden') {
    return notice('Sentinel is not permitted to read vulnerability reports.', (
      <>
        <p>
          The ClusterRole installed with an earlier version does not include the rule for them.
          Re-apply <span className="font-mono text-xs">deploy/sentinel.yaml</span> to add it.
        </p>
        <p className="mt-2 font-mono text-xs">{overview.message}</p>
      </>
    ))
  }
  if (overview.status === 'error') {
    return notice('Vulnerability reports could not be read.', (
      <p className="font-mono text-xs">{overview.message}</p>
    ))
  }

  const workloads = overview.workloads
  const namespaces = [...new Set(workloads.map(w => w.namespace))].sort()
  const filtered = filterWorkloads(workloads, { search, namespaces: namespaceFilter, severities, flags })
  const isFiltered = search.trim() !== '' || namespaceFilter.length > 0 ||
    severities.length > 0 || flags.length > 0

  const critical = filtered.reduce((n, w) => n + w.counts.critical, 0)
  const high = filtered.reduce((n, w) => n + w.counts.high, 0)
  const exposedCritical = filtered.filter(w => w.exposed && w.counts.critical > 0).length
  const unscanned = filtered.filter(w => w.scan !== 'full').length

  const exportCsv = () =>
    downloadCSV('vulnerabilities.csv', WORKLOAD_CSV_HEADERS, workloadCsvRows(filtered))

  return (
    <>
      {header(
        <Button variant="outline" size="sm" onClick={exportCsv} disabled={filtered.length === 0}>
          <IconDownload size={14} className="mr-1" /> Export CSV
        </Button>,
      )}

      {loadError && (
        <Alert variant="destructive" className="mb-4">
          <AlertDescription>
            The list could not be refreshed, so what is shown may be out of date. {loadError}
          </AlertDescription>
        </Alert>
      )}

      <div className="mb-4 flex items-center gap-2">
        <Input placeholder="Search workload or image..."
          value={search} onChange={e => setSearch(e.target.value)}
          className="h-8 w-56 text-sm" />
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
              { key: 'critical', label: 'Critical' },
              { key: 'high', label: 'High' },
              { key: 'medium', label: 'Medium' },
              { key: 'low', label: 'Low' },
              { key: 'unknown', label: 'Unknown' },
            ],
          },
          {
            label: 'Show only',
            value: flags,
            onChange: setFlags,
            options: [
              { key: 'exposed', label: 'Exposed' },
              { key: 'fixable', label: 'Fix available' },
              { key: 'unscanned', label: 'Not fully scanned' },
            ],
          },
        ]} />
      </div>

      <Card className="overflow-x-hidden">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-1 border-b px-5 py-3 text-sm">
          <span className="text-muted-foreground">
            {filtered.length} workloads{isFiltered ? ' (filtered)' : ''}
          </span>
          <div className="flex items-center gap-1.5">
            <span className="size-2 rounded-full bg-destructive" />
            <span className="text-destructive">{critical} critical</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="size-2 rounded-full bg-orange-500" />
            <span className="text-orange-700">{high} high</span>
          </div>
          {exposedCritical > 0 && (
            <span className="text-destructive">{exposedCritical} critical and exposed</span>
          )}
          {unscanned > 0 && (
            <span className="text-muted-foreground">{unscanned} not fully scanned</span>
          )}
        </div>
        <CardContent className="p-0">
          {filtered.length === 0 ? (
            <div className="py-10 text-center text-sm text-muted-foreground">
              {workloads.length === 0
                ? 'No running workloads were found.'
                : 'No workloads match the current filters.'}
            </div>
          ) : (
            <Table className="table-fixed">
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8" />
                  <TableHead className="w-60">Workload</TableHead>
                  <TableHead className="w-28">Namespace</TableHead>
                  <TableHead>Image</TableHead>
                  <TableHead className="w-16 text-right">Critical</TableHead>
                  <TableHead className="w-14 text-right">High</TableHead>
                  <TableHead className="w-18 text-right">Medium</TableHead>
                  <TableHead className="w-14 text-right">Low</TableHead>
                  <TableHead className="w-20 text-right">Unknown</TableHead>
                  <TableHead className="w-18 text-right">Fixable</TableHead>
                  <TableHead className="w-28">Scanned</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map(w => {
                  const key = workloadKey(w)
                  const open = expanded.has(key)
                  const scanned = w.scan !== 'none'
                  const urgent = w.exposed && w.counts.critical > 0
                  return (
                    <Fragment key={key}>
                      <TableRow
                        className={`cursor-pointer ${urgent ? 'bg-destructive/5 hover:bg-destructive/10' : 'hover:bg-muted/50'}`}
                        onClick={() => toggle(w)}
                      >
                        <TableCell className="py-2 pl-3 pr-0">
                          {open
                            ? <IconChevronDown size={14} className="text-muted-foreground" />
                            : <IconChevronRight size={14} className="text-muted-foreground" />}
                        </TableCell>
                        <TableCell className="text-sm">
                          <div className="flex items-center gap-2">
                            <span className="truncate" title={`${w.kind} / ${w.name}`}>
                              <span className="text-muted-foreground">{w.kind} / </span>{w.name}
                            </span>
                            {w.exposed && (
                              <Badge className="shrink-0 bg-amber-500/15 font-medium text-amber-700 hover:bg-amber-500/15"
                                title="Reachable from outside the cluster">
                                Exposed
                              </Badge>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="truncate text-sm" title={w.namespace}>{w.namespace}</TableCell>
                        <TableCell className="text-sm">
                          <div className="flex items-center gap-2">
                            <span className="truncate font-mono text-xs" title={w.images.map(i => i.image).join('\n')}>
                              {shortImage(w.images[0]?.image ?? '')}
                            </span>
                            {w.images.length > 1 && (
                              <span className="shrink-0 text-xs text-muted-foreground">
                                +{w.images.length - 1} more
                              </span>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="text-right text-sm">
                          <Count value={w.counts.critical} scanned={scanned} className="text-destructive" />
                        </TableCell>
                        <TableCell className="text-right text-sm">
                          <Count value={w.counts.high} scanned={scanned} className="text-orange-700" />
                        </TableCell>
                        <TableCell className="text-right text-sm">
                          <Count value={w.counts.medium} scanned={scanned} className="text-amber-700" />
                        </TableCell>
                        <TableCell className="text-right text-sm">
                          <Count value={w.counts.low} scanned={scanned} className="text-foreground" />
                        </TableCell>
                        <TableCell className="text-right text-sm">
                          <Count value={w.counts.unknown} scanned={scanned} className="text-foreground" />
                        </TableCell>
                        <TableCell className="text-right text-sm">
                          <Count value={w.fixable} scanned={scanned} className="text-foreground" />
                        </TableCell>
                        <TableCell className="text-sm">
                          {w.scan === 'none' ? (
                            <Badge variant="outline" className="font-medium">Not scanned</Badge>
                          ) : (
                            <div className="flex items-center gap-1.5">
                              <RelativeTime iso={w.scannedAt ?? ''} />
                              {w.stale && <span className="text-xs text-amber-700">stale</span>}
                              {w.scan === 'partial' && <span className="text-xs text-muted-foreground">partial</span>}
                            </div>
                          )}
                        </TableCell>
                      </TableRow>
                      {open && (
                        <TableRow className="bg-muted/30 hover:bg-muted/30">
                          <TableCell colSpan={11} className="py-3 pl-10 pr-6">
                            <WorkloadDetail
                              workload={w}
                              detail={details[key]}
                              showAll={showAll.has(key)}
                              onShowAll={() => setShowAll(prev => new Set(prev).add(key))}
                            />
                          </TableCell>
                        </TableRow>
                      )}
                    </Fragment>
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

function imageStatus(i: ImageVuln) {
  if (!i.scanned) return <span className="text-muted-foreground">not scanned</span>
  return (
    <span className="text-muted-foreground">
      {i.counts.critical} critical, {i.counts.high} high, {i.counts.medium} medium, {i.counts.low} low
      {i.counts.unknown > 0 && `, ${i.counts.unknown} unknown`}
      {i.stale && <span className="text-amber-700">, scan is more than 7 days old</span>}
    </span>
  )
}

function WorkloadDetail({ workload, detail, showAll, onShowAll }: {
  workload: WorkloadVuln
  detail: Detail | undefined
  showAll: boolean
  onShowAll: () => void
}) {
  const loaded = typeof detail === 'object' ? detail : null
  const findings = loaded?.findings ?? []
  const unavailable = loaded?.unavailable ?? []
  const shown = showAll ? findings : findings.slice(0, DETAIL_PAGE)
  const severalImages = workload.images.length > 1

  return (
    <div className="flex flex-col gap-3 text-xs">
      <div className="flex flex-col gap-1">
        {workload.images.map(i => (
          <div key={`${i.container}|${i.image}`} className="flex gap-1.5">
            <span className="shrink-0 text-muted-foreground">{i.container}:</span>
            <span className="font-mono" style={{ wordBreak: 'break-all' }}>{i.image}</span>
            <span className="shrink-0">{imageStatus(i)}</span>
          </div>
        ))}
      </div>

      {workload.scan === 'none' && (
        <p className="text-muted-foreground">
          Trivy Operator has no report for this workload yet, so nothing is known about its images.
        </p>
      )}
      {detail === 'loading' && <p className="text-muted-foreground">Loading findings...</p>}
      {detail === 'error' && <p className="text-destructive">The findings could not be loaded.</p>}
      {unavailable.length > 0 && (
        <p className="text-amber-700">
          The report for {unavailable.join(', ')} could not be read just now, so its findings are
          missing below. Trivy Operator rewrites a report each time it rescans. Refresh to try again.
        </p>
      )}
      {loaded && findings.length === 0 && unavailable.length === 0 && (
        <p className="text-muted-foreground">No known vulnerabilities in the scanned images.</p>
      )}

      {shown.length > 0 && (
        <Table className="table-fixed text-xs">
          <TableHeader>
            <TableRow>
              <TableHead className="h-8 w-24">Severity</TableHead>
              <TableHead className="h-8 w-40">ID</TableHead>
              <TableHead className="h-8 w-40">Package</TableHead>
              <TableHead className="h-8 w-32">Installed</TableHead>
              <TableHead className="h-8 w-32">Fixed in</TableHead>
              {severalImages && <TableHead className="h-8 w-32">Container</TableHead>}
              <TableHead className="h-8">Summary</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {shown.map((v, i) => (
              <TableRow key={`${v.container}|${v.id}|${v.package}|${i}`} className="hover:bg-transparent">
                <TableCell className="py-1.5"><SeverityBadge severity={v.severity} /></TableCell>
                <TableCell className="py-1.5 font-mono">
                  {v.link
                    ? <a href={v.link} target="_blank" rel="noreferrer" className="underline underline-offset-2 hover:text-primary">{v.id}</a>
                    : v.id}
                </TableCell>
                <TableCell className="truncate py-1.5 font-mono" title={v.package}>{v.package}</TableCell>
                <TableCell className="truncate py-1.5 font-mono" title={v.installedVersion}>{v.installedVersion}</TableCell>
                <TableCell className="truncate py-1.5 font-mono" title={v.fixedVersion}>
                  {v.fixedVersion || <span className="font-sans text-muted-foreground">no fix yet</span>}
                </TableCell>
                {severalImages && <TableCell className="truncate py-1.5" title={v.container}>{v.container}</TableCell>}
                <TableCell className="truncate py-1.5" title={v.title}>{v.title}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      {findings.length > shown.length && (
        <div>
          <Button variant="outline" size="sm" onClick={onShowAll}>
            Show all {findings.length} findings
          </Button>
        </div>
      )}
    </div>
  )
}
