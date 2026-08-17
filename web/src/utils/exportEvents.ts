import type { DisplayEvent } from '../layout/SecurityEventsProvider'
import { ruleType } from './ruleType'

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
    ruleType(e.function ?? '') ?? '',
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
