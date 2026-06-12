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

const TTL_DAYS = 7
const TTL_MS = TTL_DAYS * 24 * 60 * 60 * 1000

function loadFromStorage(): DisplayEvent[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (raw) {
      const cutoff = Date.now() - TTL_MS
      const data = JSON.parse(raw) as any[]
      return data
        .filter((e) => e.type === 'kprobe' && e.policyName)
        .filter((e) => !e.time || new Date(e.time).getTime() >= cutoff)
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
  paused: boolean
  pendingCount: number
  togglePause: () => void
}

const SecurityEventsContext = createContext<SecurityEventsContextValue>({
  events: [],
  connected: false,
  error: '',
  reconnect: () => {},
  paused: false,
  pendingCount: 0,
  togglePause: () => {},
})

export function useSecurityEvents() {
  return useContext(SecurityEventsContext)
}

export function SecurityEventsProvider({ children }: { children: React.ReactNode }) {
  const [events, setEvents] = useState<DisplayEvent[]>(() => loadFromStorage())
  const [connected, setConnected] = useState(false)
  const [error, setError] = useState('')
  const [paused, setPaused] = useState(false)
  const pausedRef = useRef(false)
  const pendingRef = useRef<DisplayEvent[]>([])
  const [pendingCount, setPendingCount] = useState(0)
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
        const id = `${evt.time}-${evt.pod}-${evt.binary}-${evt.policyName}-${Math.random().toString(36).slice(2)}`
        const newEvt: DisplayEvent = { ...evt, id, count: 1, severity }

        if (pausedRef.current) {
          // While paused, buffer new events without updating the display.
          pendingRef.current = [newEvt, ...pendingRef.current].slice(0, MAX_EVENTS)
          setPendingCount(pendingRef.current.length)
          return
        }

        setEvents((prev) => {
          if (prev.length > 0 && isSameEvent(prev[0], evt)) {
            // Dedup: preserve the original id so the expanded row stays open.
            return [{ ...prev[0], count: prev[0].count + 1, time: evt.time }, ...prev.slice(1)]
          }
          return [newEvt, ...prev].slice(0, MAX_EVENTS)
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

  const togglePause = useCallback(() => {
    setPaused(prev => {
      const nowPaused = !prev
      pausedRef.current = nowPaused
      if (!nowPaused && pendingRef.current.length > 0) {
        // Resume: flush buffered events into the main list.
        const pending = pendingRef.current
        pendingRef.current = []
        setPendingCount(0)
        setEvents(prev => [...pending, ...prev].slice(0, MAX_EVENTS))
      }
      return nowPaused
    })
  }, [])

  useEffect(() => {
    connect()
    return () => esRef.current?.close()
  }, [])

  return (
    <SecurityEventsContext.Provider value={{ events, connected, error, reconnect: connect, paused, pendingCount, togglePause }}>
      {children}
    </SecurityEventsContext.Provider>
  )
}
