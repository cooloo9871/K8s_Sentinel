import { formatTWTime } from '../utils/time'

export function RelativeTime({ iso }: { iso: string }) {
  if (!iso) return <span className="text-muted-foreground">—</span>
  const d = new Date(iso)
  if (isNaN(d.getTime())) return <span className="font-mono text-xs">{iso}</span>
  const diffSec = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000))
  const label =
    diffSec < 60 ? 'just now'
    : diffSec < 3600 ? `${Math.floor(diffSec / 60)}m ago`
    : diffSec < 86400 ? `${Math.floor(diffSec / 3600)}h ago`
    : `${Math.floor(diffSec / 86400)}d ago`
  return <span className="font-mono text-xs" title={formatTWTime(iso)}>{label}</span>
}
