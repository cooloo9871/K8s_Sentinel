import type { VulnOverview, WorkloadVuln } from '../api/client'
import { matchesScopeFilter } from '../components/ScopeFilter'
import { formatTWTime } from './time'

export type VulnSeverity = 'critical' | 'high' | 'medium' | 'low' | 'unknown'
export type VulnFlag = 'fixable' | 'exposed' | 'unscanned'

export interface VulnFilter {
  search: string
  namespaces: string[]
  /** A workload passes with a finding of any selected severity. */
  severities: string[]
  /** Every selected flag must hold. */
  flags: string[]
}

export const workloadKey = (w: WorkloadVuln) => `${w.namespace}/${w.kind}/${w.name}`

const FLAG_TEST: Record<VulnFlag, (w: WorkloadVuln) => boolean> = {
  fixable: w => w.fixable > 0,
  exposed: w => w.exposed,
  unscanned: w => w.scan !== 'full',
}

export function filterWorkloads(workloads: WorkloadVuln[], f: VulnFilter): WorkloadVuln[] {
  const q = f.search.trim().toLowerCase()
  return workloads.filter(w => {
    if (!matchesScopeFilter('namespaced', w.namespace, f.namespaces)) return false
    if (f.severities.length > 0 &&
        !f.severities.some(s => w.counts[s as VulnSeverity] > 0)) return false
    if (!f.flags.every(flag => FLAG_TEST[flag as VulnFlag](w))) return false
    if (q && !w.name.toLowerCase().includes(q) &&
        !w.images.some(i => i.image.toLowerCase().includes(q))) return false
    return true
  })
}

export const WORKLOAD_CSV_HEADERS = [
  'Namespace', 'Kind', 'Workload', 'Exposed', 'Container', 'Image',
  'Critical', 'High', 'Medium', 'Low', 'Unknown', 'Fixable', 'Scanned',
]

export function workloadCsvRows(workloads: WorkloadVuln[]): string[][] {
  return workloads.flatMap(w => w.images.map(i => [
    w.namespace, w.kind, w.name, w.exposed ? 'Yes' : 'No', i.container, i.image,
    ...(i.scanned
      ? [i.counts.critical, i.counts.high, i.counts.medium, i.counts.low, i.counts.unknown, i.fixable].map(String)
      : ['', '', '', '', '', '']),
    i.scanned ? formatTWTime(i.scannedAt) : 'Not scanned',
  ]))
}

/** The headline numbers, shared so the page and the dashboard cannot disagree. */
export function summarizeWorkloads(workloads: WorkloadVuln[]) {
  return {
    critical: workloads.reduce((n, w) => n + w.counts.critical, 0),
    high: workloads.reduce((n, w) => n + w.counts.high, 0),
    exposedCritical: workloads.filter(w => w.exposed && w.counts.critical > 0).length,
    unscanned: workloads.filter(w => w.scan !== 'full').length,
  }
}

// The same age at which a single scan result is marked stale.
const SCANNER_STALE_MS = 7 * 24 * 60 * 60 * 1000

export interface ScannerState {
  label: string
  tone: 'ok' | 'muted' | 'warn' | 'down'
}

/**
 * Whether the scanner is delivering. Not installed is a fact about the cluster
 * and reads muted; installed but unreadable, or silent for a week, does not.
 */
export function scannerState(o: VulnOverview | null, now = Date.now()): ScannerState {
  if (!o) return { label: 'Not measured', tone: 'muted' }
  if (o.status === 'not-installed') return { label: 'Not detected', tone: 'muted' }
  if (o.status === 'forbidden') return { label: 'Not permitted', tone: 'down' }
  if (o.status === 'error') return { label: 'Error', tone: 'down' }
  if (o.reports === 0 || !o.lastScanAt) return { label: 'No reports yet', tone: 'muted' }
  if (now - new Date(o.lastScanAt).getTime() > SCANNER_STALE_MS) return { label: 'Stale', tone: 'warn' }
  return { label: 'Reporting', tone: 'ok' }
}
