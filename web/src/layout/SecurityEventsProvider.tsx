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
  hook?: string
  policyName?: string
  action?: string
  processUid?: number
  filePath?: string
  fileOp?: string
  netDest?: string
  netSrc?: string
  dropReason?: string
}

interface SecurityEventsContextValue {
  events: DisplayEvent[]
  connected: boolean
  reconnect: () => void
  applyRetention: (maxWarnings: number, maxCriticals: number) => void
}

const SecurityEventsContext = createContext<SecurityEventsContextValue>({
  events: [],
  connected: false,
  reconnect: () => {},
  applyRetention: () => {},
})

export function useSecurityEvents() {
  return useContext(SecurityEventsContext)
}

export function SecurityEventsProvider({ children }: { children: React.ReactNode }) {
  const [events, setEvents] = useState<DisplayEvent[]>([])
  const [connected, setConnected] = useState(false)
  const esRef = useRef<EventSource | null>(null)
  // capRef is always up-to-date before SSE starts — no async race
  const capRef = useRef({ maxWarnings: 500, maxCriticals: 300 })

  // startSSE: clears events, then opens a fresh SSE connection.
  // capRef must already be updated before calling.
  const startSSE = useCallback(() => {
    esRef.current?.close()
    setEvents([])
    setConnected(false)

    const es = new EventSource('/api/security-events/stream')
    esRef.current = es

    es.onopen = () => setConnected(true)
    es.onmessage = (raw) => {
      try {
        const evt: DisplayEvent = JSON.parse(raw.data)
        setEvents(prev => {
          // Update existing event (dedup / count increment)
          if (prev.some(x => x.id === evt.id)) {
            return prev.map(x => x.id === evt.id ? { ...x, count: evt.count, time: evt.time } : x)
          }
          // New event: prepend then cap — capRef is always current here
          const { maxWarnings, maxCriticals } = capRef.current
          let warn = 0, crit = 0
          return [evt, ...prev].filter(e => {
            if (e.severity === 'critical' && crit < maxCriticals) { crit++; return true }
            if (e.severity === 'warning'  && warn < maxWarnings)  { warn++; return true }
            return false
          })
        })
      } catch { /* ignore malformed */ }
    }
    es.onerror = () => setConnected(false)
  }, [])

  // reconnect: re-fetch retention then start SSE (used by error recovery / manual trigger)
  const reconnect = useCallback(() => {
    securityRetentionApi.get()
      .then(r => { capRef.current = { maxWarnings: r.maxWarnings, maxCriticals: r.maxCriticals } })
      .catch(() => {})
      .finally(() => startSSE())
  }, [startSSE])

  // applyRetention: called by SecurityRetentionPage after a successful save.
  // Trims in-place — no SSE reconnect needed, avoids visible flash.
  const applyRetention = useCallback((maxWarnings: number, maxCriticals: number) => {
    capRef.current = { maxWarnings, maxCriticals }
    setEvents(prev => {
      let warn = 0, crit = 0
      return prev.filter(e => {
        if (e.severity === 'critical' && crit < maxCriticals) { crit++; return true }
        if (e.severity === 'warning'  && warn < maxWarnings)  { warn++; return true }
        return false
      })
    })
  }, [])

  // Initial mount: fetch retention first, then start SSE
  useEffect(() => {
    securityRetentionApi.get()
      .then(r => { capRef.current = { maxWarnings: r.maxWarnings, maxCriticals: r.maxCriticals } })
      .catch(() => {})
      .finally(() => startSSE())
    return () => esRef.current?.close()
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <SecurityEventsContext.Provider value={{ events, connected, reconnect, applyRetention }}>
      {children}
    </SecurityEventsContext.Provider>
  )
}
