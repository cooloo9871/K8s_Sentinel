import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'

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

function applyEvent(evt: DisplayEvent, prev: DisplayEvent[]): DisplayEvent[] {
  if (prev.some(x => x.id === evt.id)) {
    return prev.map(x => x.id === evt.id ? { ...x, count: evt.count, time: evt.time } : x)
  }
  return [evt, ...prev]
}

export function SecurityEventsProvider({ children }: { children: React.ReactNode }) {
  const [events, setEvents] = useState<DisplayEvent[]>([])
  const [connected, setConnected] = useState(false)
  const esRef = useRef<EventSource | null>(null)

  const connect = useCallback(() => {
    esRef.current?.close()
    setConnected(false)

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
  }, [])

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
