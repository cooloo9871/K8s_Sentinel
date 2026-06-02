import { CCard, CCardBody } from '@coreui/react'

interface Props {
  title: string
  value: string | number
  subtitle?: string
  borderColor: string
}

export function StatCard({ title, value, subtitle, borderColor }: Props) {
  return (
    <CCard style={{ borderLeft: `4px solid ${borderColor}` }}>
      <CCardBody>
        <div
          style={{
            fontSize: '0.65rem',
            color: '#6c757d',
            textTransform: 'uppercase',
            letterSpacing: '0.5px',
            marginBottom: '0.4rem',
          }}
        >
          {title}
        </div>
        <div style={{ fontSize: '1.6rem', fontWeight: 700, color: '#1b2a3b' }}>{value}</div>
        {subtitle && (
          <div style={{ fontSize: '0.7rem', color: '#6c757d', marginTop: '0.2rem' }}>
            {subtitle}
          </div>
        )}
      </CCardBody>
    </CCard>
  )
}
