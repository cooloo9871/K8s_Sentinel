// Generic CSV download: a BOM so Excel reads UTF-8, CRLF rows, and every field
// quoted so commas, quotes and newlines in the data cannot break the columns.
export function downloadCSV(filename: string, headers: string[], rows: string[][]) {
  // A field that starts like a formula is given a leading apostrophe, so a
  // spreadsheet shows it instead of running it. Some of these values, the name
  // on a failed sign-in for one, are typed by whoever is knocking.
  const escape = (v: string) => `"${(/^[=+\-@\t\r]/.test(v) ? "'" + v : v).replace(/"/g, '""')}"`
  const csv = [headers, ...rows].map(r => r.map(escape).join(',')).join('\r\n')
  const blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}
