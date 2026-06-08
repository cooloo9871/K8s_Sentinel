import { createContext, useContext, useEffect, useRef, useState } from 'react'
import type { TetragonEvent } from '../api/types'

const MAX_EVENTS = 500
const DEDUP_WINDOW_MS = 5000
const STORAGE_KEY = 'sentinel_security_events'

export type Severity = 'warning' | 'critical'

export interface DisplayEvent extends TetragonEvent {
  count: number
  severity: Severity // warning = monitor (not blocked), critical = kill (blocked)
}

function loadFromStorage(): DisplayEvent[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (raw) {
      const data = JSON.parse(raw) as any[]
      // Backfill fields added after initial storage schema (count, severity)
      return data.map((e) => ({
        ...e,
        count: e.count ?? 1,
        severity: e.severity ?? (e.action === 'kill' ? 'critical' : 'warning'),
      })) as DisplayEvent[]
    }
  } catch {}
  return []
}

function saveToStorage(events: DisplayEvent[]) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(events))
  } catch {}
}

function isSameEvent(a: DisplayEvent, b: TetragonEvent): boolean {
  return (
    a.binary === b.binary &&
    a.pod === b.pod &&
    a.function === b.function &&
    a.policyName === b.policyName &&
    a.action === b.action &&
    Math.abs(new Date(b.time).getTime() - new Date(a.time).getTime()) < DEDUP_WINDOW_MS
  )
}

interface SecurityEventsContextValue {
  events: DisplayEvent[]
  connected: boolean
  error: string
  reconnect: () => void
}

const SecurityEventsContext = createContext<SecurityEventsContextValue>({
  events: [],
  connected: false,
  error: '',
  reconnect: () => {},
})

export function useSecurityEvents() {
  return useContext(SecurityEventsContext)
}

export function SecurityEventsProvider({ children }: { children: React.ReactNode }) {
  const [events, setEvents] = useState<DisplayEvent[]>(() => loadFromStorage())
  const [connected, setConnected] = useState(false)
  const [error, setError] = useState('')
  const esRef = useRef<EventSource | null>(null)

  const connect = () => {
    esRef.current?.close()
    setError('')

    const es = new EventSource('/api/events/stream')
    esRef.current = es

    es.onopen = () => setConnected(true)

    es.onmessage = (e) => {
      try {
        const evt: TetragonEvent = JSON.parse(e.data)
        const severity: Severity = evt.action === 'kill' ? 'critical' : 'warning'
        setEvents((prev) => {
          if (prev.length > 0 && isSameEvent(prev[0], evt)) {
            return [{ ...prev[0], count: prev[0].count + 1, time: evt.time }, ...prev.slice(1)]
          }
          return [{ ...evt, count: 1, severity }, ...prev].slice(0, MAX_EVENTS)
        })
      } catch {}
    }

    es.addEventListener('stream-error', (e: MessageEvent) => {
      setError(e.data)
      setConnected(false)
      es.close()
    })

    es.onerror = () => setConnected(false)
  }

  // Persist events to localStorage whenever they change
  useEffect(() => {
    saveToStorage(events)
  }, [events])

  useEffect(() => {
    connect()
    return () => esRef.current?.close()
  }, [])

  return (
    <SecurityEventsContext.Provider value={{ events, connected, error, reconnect: connect }}>
      {children}
    </SecurityEventsContext.Provider>
  )
}
