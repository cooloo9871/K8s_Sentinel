import type { WorkloadVuln } from '../api/client'
import { matchesScopeFilter } from '../components/ScopeFilter'
import { formatTWTime } from './time'

export type VulnSeverity = 'critical' | 'high' | 'medium' | 'low'
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
