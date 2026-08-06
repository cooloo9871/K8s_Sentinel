import type { DisplayEvent } from '../layout/SecurityEventsProvider'

function ruleType(fn: string): string {
  // Keep in step with the badge on the Security Events page: a Cilium policy
  // denial (cilium-egress-deny, cilium-ingress-deny) is a network event, and was
  // being exported as "Process".
  if (fn.includes('tcp_connect') || fn.includes('deny')) return 'Network'
  if (fn.includes('security_file') || fn.includes('security_path')) return 'File'
  return 'Process'
}

function userLabel(uid: number | undefined): string {
  if (uid === undefined) return ''
  return uid === 0 ? 'root (uid=0)' : `uid=${uid}`
}

const COLUMNS = [
  'Time', 'Severity', 'Rule', 'Namespace', 'Pod', 'Binary',
  'Policy', 'Node', 'User', 'File Op', 'File Path', 'Destination', 'Source',
]

function toRow(e: DisplayEvent): string[] {
  return [
    e.time,
    e.severity.toUpperCase(),
    ruleType(e.function ?? ''),
    e.namespace,
    e.pod + (e.container ? ` / ${e.container}` : ''),
    e.binary ?? '',
    e.policyName ?? '',
    e.nodeName ?? '',
    userLabel(e.processUid),
    e.fileOp ?? '',
    e.filePath ?? '',
    e.netDest ?? '',
    e.netSrc ?? '',
  ]
}

export function exportCSV(events: DisplayEvent[], filename = 'security-events.csv') {
  const escape = (v: string) => `"${v.replace(/"/g, '""')}"`
  const header = COLUMNS.map(escape).join(',')
  const rows = events.map(e => toRow(e).map(escape).join(','))
  const csv = [header, ...rows].join('\r\n')
  const blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}
