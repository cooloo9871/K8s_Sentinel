import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import { admissionRetentionApi } from '../api/client'
import type { AdmissionEvent } from '../api/client'

interface AdmissionEventsContextValue {
  events: AdmissionEvent[]
  connected: boolean
  maxEvents: number
  reconnect: () => void
  applyRetention: (maxEvents: number, ttlDays: number) => void
}

const AdmissionEventsContext = createContext<AdmissionEventsContextValue>({
  events: [],
  connected: false,
  maxEvents: 500,
  reconnect: () => {},
  applyRetention: () => {},
})

export function useAdmissionEvents() {
  return useContext(AdmissionEventsContext)
}

export function AdmissionEventsProvider({ children }: { children: React.ReactNode }) {
  const [events, setEvents] = useState<AdmissionEvent[]>([])
  const [connected, setConnected] = useState(false)
  const [maxEvents, setMaxEvents] = useState(500)
  const esRef = useRef<EventSource | null>(null)
  const capRef = useRef(500)

  const startSSE = useCallback(() => {
    esRef.current?.close()
    setEvents([])
    setConnected(false)

    const es = new EventSource('/api/admission-events/stream')
    esRef.current = es
    es.onopen = () => setConnected(true)
    es.onmessage = (raw) => {
      try {
        const evt: AdmissionEvent = JSON.parse(raw.data)
        setEvents(prev => {
          if (prev.some(x => x.id === evt.id)) return prev
          return [evt, ...prev].slice(0, capRef.current)
        })
      } catch { /* ignore */ }
    }
    es.onerror = () => setConnected(false)
  }, [])

  const reconnect = useCallback(() => {
    admissionRetentionApi.get()
      .then(r => { capRef.current = r.maxEvents; setMaxEvents(r.maxEvents) })
      .catch(() => {})
      .finally(() => startSSE())
  }, [startSSE])

  const applyRetention = useCallback((newMax: number, _ttlDays: number) => {
    capRef.current = newMax
    setMaxEvents(newMax)
    setEvents(prev => prev.length > newMax ? prev.slice(0, newMax) : prev)
  }, [])

  useEffect(() => {
    admissionRetentionApi.get()
      .then(r => { capRef.current = r.maxEvents; setMaxEvents(r.maxEvents) })
      .catch(() => {})
      .finally(() => startSSE())
    return () => esRef.current?.close()
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <AdmissionEventsContext.Provider value={{ events, connected, maxEvents, reconnect, applyRetention }}>
      {children}
    </AdmissionEventsContext.Provider>
  )
}
