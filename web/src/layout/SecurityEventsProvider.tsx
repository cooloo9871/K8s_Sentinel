import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import type { TetragonEvent } from '../api/types'

const MAX_EVENTS = 500
const DEDUP_WINDOW_MS = 5000
const STORAGE_KEY = 'sentinel_security_events'

export type Severity = 'warning' | 'critical'

export interface DisplayEvent extends TetragonEvent {
  id: string   // stable unique ID set on creation, never changed on dedup
  count: number
  severity: Severity
}

function loadFromStorage(): DisplayEvent[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (raw) {
      const data = JSON.parse(raw) as any[]
      return data
        .filter((e) => e.type === 'kprobe' && e.policyName)
        .map((e) => ({
          ...e,
          id: e.id ?? `${e.time}-${e.pod}-${e.binary}-${Math.random()}`,
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
  const saveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const eventsRef = useRef<DisplayEvent[]>(events)

  const connect = useCallback(() => {
    esRef.current?.close()
    setError('')

    const es = new EventSource('/api/events/stream')
    esRef.current = es

    es.onopen = () => setConnected(true)

    es.onmessage = (e) => {
      try {
        const evt: TetragonEvent = JSON.parse(e.data)
        // Only store kprobe events that belong to a named user-defined TracingPolicy.
        if (evt.type !== 'kprobe' || !evt.policyName) return
        const severity: Severity = evt.action === 'kill' ? 'critical' : 'warning'
        setEvents((prev) => {
          if (prev.length > 0 && isSameEvent(prev[0], evt)) {
            // Dedup: preserve the original id so the expanded row stays open.
            return [{ ...prev[0], count: prev[0].count + 1, time: evt.time }, ...prev.slice(1)]
          }
          const id = `${evt.time}-${evt.pod}-${evt.binary}-${evt.policyName}-${Math.random().toString(36).slice(2)}`
          return [{ ...evt, id, count: 1, severity }, ...prev].slice(0, MAX_EVENTS)
        })
      } catch {}
    }

    es.addEventListener('stream-error', (e: MessageEvent) => {
      setError(e.data)
      setConnected(false)
      es.close()
    })

    es.onerror = () => setConnected(false)
  }, [])

  useEffect(() => { eventsRef.current = events }, [events])

  useEffect(() => {
    if (saveTimerRef.current) clearTimeout(saveTimerRef.current)
    saveTimerRef.current = setTimeout(() => saveToStorage(events), 2000)
    return () => { if (saveTimerRef.current) clearTimeout(saveTimerRef.current) }
  }, [events])

  useEffect(() => { return () => { saveToStorage(eventsRef.current) } }, [])

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
