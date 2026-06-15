import jsPDF from 'jspdf'
import autoTable from 'jspdf-autotable'
import type { DisplayEvent } from '../layout/SecurityEventsProvider'

function ruleType(fn: string): string {
  if (fn.includes('tcp_connect')) return 'Network'
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
    ruleType(e.function),
    e.namespace,
    e.pod + (e.container ? ` / ${e.container}` : ''),
    e.binary,
    e.policyName,
    e.nodeName,
    userLabel(e.processUid),
    e.fileOp,
    e.filePath,
    e.netDest,
    e.netSrc,
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

export function exportPDF(events: DisplayEvent[], filename = 'security-events.pdf') {
  const doc = new jsPDF({ orientation: 'landscape', unit: 'mm', format: 'a4' })

  doc.setFontSize(14)
  doc.text('Sentinel — Security Events', 14, 14)
  doc.setFontSize(9)
  doc.setTextColor(120)
  doc.text(`Exported: ${new Date().toLocaleString()}  |  Total: ${events.length} events`, 14, 20)
  doc.setTextColor(0)

  autoTable(doc, {
    startY: 25,
    head: [COLUMNS],
    body: events.map(toRow),
    styles: { fontSize: 7, cellPadding: 1.5, overflow: 'ellipsize' },
    headStyles: { fillColor: [30, 30, 30], textColor: 255, fontStyle: 'bold' },
    alternateRowStyles: { fillColor: [245, 245, 245] },
    didParseCell(data) {
      if (data.section === 'body' && data.column.index === 1) {
        const val = data.cell.raw as string
        if (val === 'CRITICAL') data.cell.styles.textColor = [185, 28, 28]
        else if (val === 'WARNING') data.cell.styles.textColor = [161, 98, 7]
      }
    },
    columnStyles: {
      0:  { cellWidth: 32 }, // Time
      1:  { cellWidth: 16 }, // Severity
      2:  { cellWidth: 16 }, // Rule
      3:  { cellWidth: 22 }, // Namespace
      4:  { cellWidth: 30 }, // Pod
      5:  { cellWidth: 28 }, // Binary
      6:  { cellWidth: 38 }, // Policy
      7:  { cellWidth: 16 }, // Node
      8:  { cellWidth: 20 }, // User
      9:  { cellWidth: 12 }, // File Op
      10: { cellWidth: 30 }, // File Path
      11: { cellWidth: 22 }, // Destination
      12: { cellWidth: 22 }, // Source
    },
  })

  doc.save(filename)
}
