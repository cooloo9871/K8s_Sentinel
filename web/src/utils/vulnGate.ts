import type { VulnGateSettings } from '../api/client'

// Why the limits cannot be saved as they are, or '' when they can.
export function gateLimitError(s: VulnGateSettings): string {
  if (s.enabled && s.criticalLimit < 0 && s.highLimit < 0) return 'Count at least one severity.'
  return ''
}

// The rule in force, in one line, with how many images it catches.
export function gateRule(s: VulnGateSettings, images: number): string {
  const parts: string[] = []
  if (s.criticalLimit >= 0) parts.push(`more than ${s.criticalLimit} critical`)
  if (s.highLimit >= 0) parts.push(`more than ${s.highLimit} high`)
  const verb = s.mode === 'deny' ? 'refused' : 'warned about'
  return `${images} image${images !== 1 ? 's' : ''} ${verb}: ${parts.join(' or ')}`
}
