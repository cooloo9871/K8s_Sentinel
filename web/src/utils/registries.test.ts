import { describe, it, expect } from 'vitest'
import type { Registry, RegistryImage } from '../api/client'
import {
  filterImages, summarizeImages, imageCsvRows, imagePath, scheduleLabel, leftOut, parseFilters,
} from './registries'

const zero = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }
const image = (over: Partial<RegistryImage>): RegistryImage =>
  ({ image: 'harbor.internal/library/nginx:1.27', scanned: true, counts: zero, fixable: 0, scannedAt: '2026-11-12T01:00:00Z', ...over })

const crit = image({ image: 'h/a/crit:1', counts: { ...zero, critical: 2, high: 1 }, fixable: 3 })
const low = image({ image: 'h/a/low:1', counts: { ...zero, low: 4 } })
const failed = image({ image: 'h/a/broken:1', scanned: false, error: 'unable to find the specified image' })
const none = { search: '', severities: [], flags: [] }
const names = (is: RegistryImage[]) => is.map(i => i.image)

describe('filterImages', () => {
  it('keeps everything when nothing is selected', () => {
    expect(filterImages([crit, low, failed], none)).toHaveLength(3)
  })
  it('filters by severity, search and flags together', () => {
    expect(names(filterImages([crit, low, failed], { ...none, severities: ['critical'] }))).toEqual(['h/a/crit:1'])
    expect(names(filterImages([crit, low, failed], { ...none, search: 'LOW' }))).toEqual(['h/a/low:1'])
    expect(names(filterImages([crit, low, failed], { ...none, flags: ['fixable'] }))).toEqual(['h/a/crit:1'])
    expect(names(filterImages([crit, low, failed], { ...none, flags: ['failed'] }))).toEqual(['h/a/broken:1'])
    expect(filterImages([crit, low, failed], { ...none, severities: ['low'], flags: ['fixable'] })).toEqual([])
  })
})

describe('summarizeImages', () => {
  it('counts a failed scan as failed, not as an image with nothing found', () => {
    expect(summarizeImages([crit, low, failed])).toEqual({ critical: 2, high: 1, failed: 1 })
  })
})

describe('imageCsvRows', () => {
  it('leaves the counts of a failed scan blank and gives the reason', () => {
    const [ok, bad] = imageCsvRows([crit, failed])
    expect(ok.slice(0, 7)).toEqual(['h/a/crit:1', '2', '1', '0', '0', '0', '3'])
    expect(bad.slice(1, 7)).toEqual(['', '', '', '', '', ''])
    expect(bad.slice(7)).toEqual(['Scan failed', 'unable to find the specified image'])
  })
})

describe('small helpers', () => {
  it('drops the registry host from an image', () => {
    expect(imagePath('harbor.internal:8443/library/team/app:v1')).toBe('library/team/app:v1')
  })
  it('words the schedule', () => {
    expect(scheduleLabel(1)).toBe('Every day')
    expect(scheduleLabel(30)).toBe('Every 30 days')
  })
  it('says how many images the cap left out', () => {
    const r = (matched: number, total: number) => ({ run: { matched, total } }) as Registry
    expect(leftOut(r(740, 500))).toBe(240)
    expect(leftOut(r(12, 12))).toBe(0)
  })
  it('reads one filter per line', () => {
    expect(parseFilters(' library/* \n\n team/app:v1.* \n')).toEqual(['library/*', 'team/app:v1.*'])
  })
  it('reads filters separated by commas', () => {
    expect(parseFilters('library/*, team/app:v1.*,\nops/*:*')).toEqual(['library/*', 'team/app:v1.*', 'ops/*:*'])
  })
})
