import { createContext, useCallback, useContext, useEffect, useState } from 'react'

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
}

const SecurityEventsContext = createContext<SecurityEventsContextValue>({ events: [] })

export function useSecurityEvents() {
  return useContext(SecurityEventsContext)
}

export function SecurityEventsProvider({ children }: { children: React.ReactNode }) {
  const [events, setEvents] = useState<DisplayEvent[]>([])

  const fetchEvents = useCallback(() => {
    fetch('/api/security-events', { credentials: 'include' })
      .then(r => r.json())
      .then((data: DisplayEvent[]) => setEvents(data ?? []))
      .catch(() => {})
  }, [])

  useEffect(() => {
    fetchEvents()
    // Refresh every 30s to pick up new events without SSE overhead in global context
    const timer = setInterval(fetchEvents, 30_000)
    return () => clearInterval(timer)
  }, [fetchEvents])

  return (
    <SecurityEventsContext.Provider value={{ events }}>
      {children}
    </SecurityEventsContext.Provider>
  )
}
