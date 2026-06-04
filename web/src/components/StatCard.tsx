import { Card, CardContent } from '@/components/ui/card'

interface Props {
  title: string
  value: string | number
  subtitle?: string
  borderColor: string
}

export function StatCard({ title, value, subtitle, borderColor }: Props) {
  return (
    <Card style={{ borderLeft: `4px solid ${borderColor}` }}>
      <CardContent>
        <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
          {title}
        </p>
        <p className="mt-1 text-3xl font-bold">{value}</p>
        {subtitle && (
          <p className="mt-1 text-xs text-muted-foreground">{subtitle}</p>
        )}
      </CardContent>
    </Card>
  )
}
