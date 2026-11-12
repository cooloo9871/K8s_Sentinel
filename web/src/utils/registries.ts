import type { Registry, RegistryImage } from '../api/client'
import type { VulnSeverity } from './vulnerabilities'
import { formatTWTime } from './time'

export interface ImageFilter {
  search: string
  /** An image passes with a finding of any selected severity. */
  severities: string[]
  /** Every selected flag must hold: 'fixable' | 'failed'. */
  flags: string[]
}

const FLAG_TEST: Record<string, (i: RegistryImage) => boolean> = {
  fixable: i => i.fixable > 0,
  failed: i => !i.scanned,
}

export function filterImages(images: RegistryImage[], f: ImageFilter): RegistryImage[] {
  const q = f.search.trim().toLowerCase()
  return images.filter(i => {
    if (f.severities.length > 0 && !f.severities.some(s => i.counts[s as VulnSeverity] > 0)) return false
    if (!f.flags.every(flag => FLAG_TEST[flag]?.(i))) return false
    return !q || i.image.toLowerCase().includes(q)
  })
}

/** The headline numbers. A failed scan counts as failed, never as zero findings. */
export function summarizeImages(images: RegistryImage[]) {
  const scanned = images.filter(i => i.scanned)
  return {
    critical: scanned.reduce((n, i) => n + i.counts.critical, 0),
    high: scanned.reduce((n, i) => n + i.counts.high, 0),
    failed: images.length - scanned.length,
  }
}

export const IMAGE_CSV_HEADERS = [
  'Image', 'Critical', 'High', 'Medium', 'Low', 'Unknown', 'Fixable', 'Scanned', 'Error',
]

export function imageCsvRows(images: RegistryImage[]): string[][] {
  return images.map(i => [
    i.image,
    ...(i.scanned
      ? [i.counts.critical, i.counts.high, i.counts.medium, i.counts.low, i.counts.unknown, i.fixable].map(String)
      : ['', '', '', '', '', '']),
    i.scanned ? formatTWTime(i.scannedAt) : 'Scan failed',
    i.error ?? '',
  ])
}

/** The image without its registry host, which every row of one registry shares. */
export const imagePath = (image: string) => image.slice(image.indexOf('/') + 1)

export const scheduleLabel = (days: number) => (days === 1 ? 'Every day' : `Every ${days} days`)

/** How many matched images a capped run left out. */
export const leftOut = (r: Registry) => Math.max(0, r.run.matched - r.run.total)

/** One filter per line, as the form's text box holds them. */
export const parseFilters = (text: string) => text.split('\n').map(s => s.trim()).filter(Boolean)
