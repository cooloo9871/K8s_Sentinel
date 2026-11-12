import { describe, it, expect } from 'vitest'
import type { VulnOverview, WorkloadVuln } from '../api/client'
import { filterWorkloads, workloadCsvRows, workloadKey, summarizeWorkloads, scannerState } from './vulnerabilities'

const zero = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }

function workload(over: Partial<WorkloadVuln>): WorkloadVuln {
  return {
    namespace: 'demo', kind: 'Deployment', name: 'web',
    images: [{ container: 'app', image: 'nginx:1.25', scanned: true, stale: false, counts: zero, fixable: 0 }],
    counts: zero, fixable: 0, scan: 'full', stale: false, exposed: false,
    ...over,
  }
}

const none = { search: '', namespaces: [], severities: [], flags: [] }
const names = (ws: WorkloadVuln[]) => ws.map(w => w.name)

describe('filterWorkloads', () => {
  const critical = workload({ name: 'crit', counts: { ...zero, critical: 2 } })
  const low = workload({ name: 'low', counts: { ...zero, low: 5 } })
  const clean = workload({ name: 'clean' })

  it('keeps everything when nothing is selected', () => {
    expect(names(filterWorkloads([critical, low, clean], none))).toEqual(['crit', 'low', 'clean'])
  })

  it('keeps a workload with a finding of any selected severity', () => {
    expect(names(filterWorkloads([critical, low, clean], { ...none, severities: ['critical'] }))).toEqual(['crit'])
    expect(names(filterWorkloads([critical, low, clean], { ...none, severities: ['critical', 'low'] }))).toEqual(['crit', 'low'])
  })

  it('fixable keeps only workloads an upgrade would improve', () => {
    const fixable = workload({ name: 'fix', fixable: 3 })
    expect(names(filterWorkloads([fixable, clean], { ...none, flags: ['fixable'] }))).toEqual(['fix'])
  })

  it('exposed keeps only workloads reachable from outside', () => {
    const edge = workload({ name: 'edge', exposed: true })
    expect(names(filterWorkloads([edge, clean], { ...none, flags: ['exposed'] }))).toEqual(['edge'])
  })

  // Partly scanned counts: one unscanned container is still a blind spot.
  it('unscanned keeps workloads that are not fully scanned', () => {
    const partial = workload({ name: 'partial', scan: 'partial' })
    const unscanned = workload({ name: 'unscanned', scan: 'none' })
    expect(names(filterWorkloads([partial, unscanned, clean], { ...none, flags: ['unscanned'] })))
      .toEqual(['partial', 'unscanned'])
  })

  it('flags combine, so "exposed and fixable" is a to-do list', () => {
    const both = workload({ name: 'both', exposed: true, fixable: 1 })
    const edge = workload({ name: 'edge', exposed: true })
    expect(names(filterWorkloads([both, edge], { ...none, flags: ['exposed', 'fixable'] }))).toEqual(['both'])
  })

  it('search matches the workload name and its images', () => {
    const redis = workload({
      name: 'cache',
      images: [{ container: 'c', image: 'redis:7', scanned: true, stale: false, counts: zero, fixable: 0 }],
    })
    expect(names(filterWorkloads([redis, clean], { ...none, search: 'REDIS' }))).toEqual(['cache'])
    expect(names(filterWorkloads([redis, clean], { ...none, search: 'clea' }))).toEqual(['clean'])
  })

  it('filters by namespace', () => {
    const other = workload({ name: 'other', namespace: 'prod' })
    expect(names(filterWorkloads([other, clean], { ...none, namespaces: ['prod'] }))).toEqual(['other'])
  })
})

describe('workloadCsvRows', () => {
  it('writes one row per image, so every image can be sorted and filtered', () => {
    const w = workload({
      exposed: true,
      images: [
        { container: 'app', image: 'app:1', scanned: true, scannedAt: '2026-11-10T00:00:00Z', stale: false, counts: { ...zero, critical: 1 }, fixable: 1 },
        { container: 'sidecar', image: 'proxy:2', scanned: false, stale: false, counts: zero, fixable: 0 },
      ],
    })
    const rows = workloadCsvRows([w])
    expect(rows).toHaveLength(2)
    expect(rows[0].slice(0, 6)).toEqual(['demo', 'Deployment', 'web', 'Yes', 'app', 'app:1'])
    expect(rows[0][6]).toBe('1')
    // Not scanned must not export as zeros.
    expect(rows[1].slice(6, 11)).toEqual(['', '', '', '', ''])
    expect(rows[1][12]).toBe('Not scanned')
  })
})

describe('workloadKey', () => {
  it('tells apart same-named workloads of different kinds and namespaces', () => {
    expect(workloadKey(workload({}))).not.toBe(workloadKey(workload({ kind: 'StatefulSet' })))
    expect(workloadKey(workload({}))).not.toBe(workloadKey(workload({ namespace: 'prod' })))
  })
})

describe('summarizeWorkloads', () => {
  it('counts findings, and exposure only where there is a critical finding', () => {
    const s = summarizeWorkloads([
      workload({ counts: { ...zero, critical: 2, high: 1 }, exposed: true }),
      workload({ counts: { ...zero, high: 4 }, exposed: true }),
      workload({ counts: { ...zero, critical: 1 }, scan: 'partial' }),
      workload({ scan: 'none' }),
    ])
    expect(s).toEqual({ critical: 3, high: 5, exposedCritical: 1, unscanned: 2 })
  })
})

describe('scannerState', () => {
  const now = new Date('2026-11-12T00:00:00Z').getTime()
  const ok = (over: Partial<VulnOverview>): VulnOverview =>
    ({ status: 'ok', workloads: [], reports: 4, lastScanAt: '2026-11-11T20:00:00Z', ...over })

  it('is reporting when a recent report exists', () => {
    expect(scannerState(ok({}), now)).toEqual({ label: 'Reporting', tone: 'ok' })
  })
  it('is muted, not an alarm, when the scanner is absent or has not reported yet', () => {
    expect(scannerState(null, now).tone).toBe('muted')
    expect(scannerState(ok({ status: 'not-installed', reports: 0, lastScanAt: undefined }), now))
      .toEqual({ label: 'Not detected', tone: 'muted' })
    expect(scannerState(ok({ reports: 0, lastScanAt: undefined }), now))
      .toEqual({ label: 'No reports yet', tone: 'muted' })
  })
  it('is a problem when reports exist but cannot be read', () => {
    expect(scannerState(ok({ status: 'forbidden' }), now).tone).toBe('down')
    expect(scannerState(ok({ status: 'error' }), now).tone).toBe('down')
  })
  it('warns when the newest report is over a week old', () => {
    expect(scannerState(ok({ lastScanAt: '2026-11-04T23:00:00Z' }), now)).toEqual({ label: 'Stale', tone: 'warn' })
    expect(scannerState(ok({ lastScanAt: '2026-11-05T01:00:00Z' }), now).tone).toBe('ok')
  })
})
