import {
  Table, TableHeader, TableBody, TableRow, TableHead, TableCell,
} from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'

// Shared by the workload and registry vulnerability lists, so a finding reads
// the same wherever it is shown.

// How many findings are shown before asking. A base image can carry hundreds,
// and the ones worth reading are sorted to the top.
export const FINDINGS_PAGE = 50

const SEVERITY_CLASS: Record<string, string> = {
  CRITICAL: 'bg-destructive/15 text-destructive hover:bg-destructive/15',
  HIGH: 'bg-orange-500/15 text-orange-700 hover:bg-orange-500/15',
  MEDIUM: 'bg-amber-500/15 text-amber-700 hover:bg-amber-500/15',
}
const SEVERITY_MUTED = 'bg-muted text-muted-foreground hover:bg-muted'

export function SeverityBadge({ severity }: { severity: string }) {
  const label = severity.charAt(0) + severity.slice(1).toLowerCase()
  return <Badge className={`font-medium ${SEVERITY_CLASS[severity] ?? SEVERITY_MUTED}`}>{label}</Badge>
}

// A count in a list. Zero recedes so the eye lands on what is there, and
// something with no scan shows a dash, since zero would claim it is clean.
export function Count({ value, scanned, className }: { value: number; scanned: boolean; className: string }) {
  if (!scanned) return <span className="text-muted-foreground">—</span>
  if (value === 0) return <span className="text-muted-foreground">0</span>
  return <span className={`font-semibold ${className}`}>{value}</span>
}

export interface FindingRow {
  id: string
  severity: string
  package: string
  installedVersion: string
  fixedVersion: string
  title: string
  link: string
  container?: string
}

export function FindingsTable({ findings, showContainer = false, showAll, onShowAll }: {
  findings: FindingRow[]
  showContainer?: boolean
  showAll: boolean
  onShowAll: () => void
}) {
  const shown = showAll ? findings : findings.slice(0, FINDINGS_PAGE)
  if (shown.length === 0) return null
  return (
    <>
      <Table className="table-fixed text-xs">
        <TableHeader>
          <TableRow>
            <TableHead className="h-8 w-24">Severity</TableHead>
            <TableHead className="h-8 w-40">ID</TableHead>
            <TableHead className="h-8 w-40">Package</TableHead>
            <TableHead className="h-8 w-32">Installed</TableHead>
            <TableHead className="h-8 w-32">Fixed in</TableHead>
            {showContainer && <TableHead className="h-8 w-32">Container</TableHead>}
            <TableHead className="h-8">Summary</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {shown.map((v, i) => (
            <TableRow key={`${v.container ?? ''}|${v.id}|${v.package}|${i}`} className="hover:bg-transparent">
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
              {showContainer && <TableCell className="truncate py-1.5" title={v.container}>{v.container}</TableCell>}
              <TableCell className="truncate py-1.5" title={v.title}>{v.title}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {findings.length > shown.length && (
        <div>
          <Button variant="outline" size="sm" onClick={onShowAll}>
            Show all {findings.length} findings
          </Button>
        </div>
      )}
    </>
  )
}
