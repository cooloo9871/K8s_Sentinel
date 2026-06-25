import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import { securityRetentionApi } from '../api/client'

export type Severity = 'warning' | 'critical'

export interface DisplayEvent {
  id: string
  time: string
  count: number
  severity: Severity
  namespace: string
  pod: string
  container?: string
  nodeName?: string
  binary?: string
  arguments?: string
  parentBin?: string
  function?: string
  policyName?: string
  action?: string
  processUid?: number
  filePath?: string
  fileOp?: string
  netDest?: string
  netSrc?: string
}

interface SecurityEventsContextValue {
  events: DisplayEvent[]
  connected: boolean
  reconnect: () => void
}

const SecurityEventsContext = createContext<SecurityEventsContextValue>({
  events: [],
  connected: false,
  reconnect: () => {},
})

export function useSecurityEvents() {
  return useContext(SecurityEventsContext)
}

export function SecurityEventsProvider({ children }: { children: React.ReactNode }) {
  const [events, setEvents] = useState<DisplayEvent[]>([])
  const [connected, setConnected] = useState(false)
  const esRef = useRef<EventSource | null>(null)
  const capRef = useRef({ maxWarnings: 500, maxCriticals: 300 })

  function applyEvent(evt: DisplayEvent, prev: DisplayEvent[]): DisplayEvent[] {
    if (prev.some(x => x.id === evt.id)) {
      return prev.map(x => x.id === evt.id ? { ...x, count: evt.count, time: evt.time } : x)
    }
    const { maxWarnings, maxCriticals } = capRef.current
    let warn = 0, crit = 0
    return [evt, ...prev].filter(e => {
      if (e.severity === 'critical' && crit < maxCriticals) { crit++; return true }
      if (e.severity === 'warning'  && warn < maxWarnings)  { warn++; return true }
      return false
    })
  }

  const connect = useCallback(() => {
    esRef.current?.close()
    setConnected(false)

    securityRetentionApi.get()
      .then(r => { capRef.current = { maxWarnings: r.maxWarnings, maxCriticals: r.maxCriticals } })
      .catch(() => {})

    const es = new EventSource('/api/security-events/stream')
    esRef.current = es

    es.onopen = () => setConnected(true)

    es.onmessage = (e) => {
      try {
        const evt: DisplayEvent = JSON.parse(e.data)
        setEvents(prev => applyEvent(evt, prev))
      } catch { /* ignore */ }
    }

    es.onerror = () => setConnected(false)
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    connect()
    return () => esRef.current?.close()
  }, [connect])

  return (
    <SecurityEventsContext.Provider value={{ events, connected, reconnect: connect }}>
      {children}
    </SecurityEventsContext.Provider>
  )
}
