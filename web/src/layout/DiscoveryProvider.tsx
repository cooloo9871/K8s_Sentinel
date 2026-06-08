import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'

const STORAGE_KEY = 'sentinel_discovery_profiles'
const SAVE_DEBOUNCE_MS = 3000

export interface PodProfile {
  namespace: string
  pod: string
  binaries: string[]   // unique process binaries observed
  filePaths: string[]  // unique file paths accessed
  netDests: string[]   // unique network destinations (addr:port)
  firstSeen: string
  lastSeen: string
}

type ProfileMap = Record<string, PodProfile> // key = "namespace/pod"

interface DiscoveryContextValue {
  profiles: PodProfile[]
  clearProfiles: () => void
}

const DiscoveryContext = createContext<DiscoveryContextValue>({
  profiles: [],
  clearProfiles: () => {},
})

export function useDiscovery() {
  return useContext(DiscoveryContext)
}

function loadFromStorage(): ProfileMap {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (raw) return JSON.parse(raw) as ProfileMap
  } catch {}
  return {}
}

function saveToStorage(map: ProfileMap) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(map))
  } catch {}
}

export function DiscoveryProvider({ children }: { children: React.ReactNode }) {
  const [profileMap, setProfileMap] = useState<ProfileMap>(() => loadFromStorage())
  const esRef = useRef<EventSource | null>(null)
  const saveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const profileMapRef = useRef<ProfileMap>(profileMap)

  // Keep ref in sync for flush-on-unmount
  useEffect(() => {
    profileMapRef.current = profileMap
  }, [profileMap])

  // Debounced localStorage save
  useEffect(() => {
    if (saveTimerRef.current) clearTimeout(saveTimerRef.current)
    saveTimerRef.current = setTimeout(() => saveToStorage(profileMap), SAVE_DEBOUNCE_MS)
    return () => { if (saveTimerRef.current) clearTimeout(saveTimerRef.current) }
  }, [profileMap])

  // Flush on unmount
  useEffect(() => {
    return () => { saveToStorage(profileMapRef.current) }
  }, [])

  const handleEvent = useCallback((raw: string) => {
    try {
      const evt = JSON.parse(raw) as {
        type: string
        namespace: string
        pod: string
        binary?: string
        filePath?: string
        netDest?: string
        time: string
      }

      if (!evt.namespace || !evt.pod) return

      const key = `${evt.namespace}/${evt.pod}`
      const now = evt.time || new Date().toISOString()

      setProfileMap(prev => {
        const existing = prev[key] ?? {
          namespace: evt.namespace,
          pod: evt.pod,
          binaries: [],
          filePaths: [],
          netDests: [],
          firstSeen: now,
          lastSeen: now,
        }

        let changed = false
        const binaries = [...existing.binaries]
        const filePaths = [...existing.filePaths]
        const netDests = [...existing.netDests]

        if (evt.binary && !binaries.includes(evt.binary)) {
          binaries.push(evt.binary)
          changed = true
        }
        if (evt.filePath && !filePaths.includes(evt.filePath)) {
          filePaths.push(evt.filePath)
          changed = true
        }
        if (evt.netDest && !netDests.includes(evt.netDest)) {
          netDests.push(evt.netDest)
          changed = true
        }
        if (now > existing.lastSeen) changed = true

        if (!changed && now <= existing.lastSeen) return prev // no-op

        return {
          ...prev,
          [key]: { ...existing, binaries, filePaths, netDests, lastSeen: now },
        }
      })
    } catch {}
  }, [])

  // SSE connection — separate from SecurityEventsProvider so Discovery
  // accumulates profiles independently of the 500-event security alert window.
  useEffect(() => {
    const connect = () => {
      const es = new EventSource('/api/events/stream')
      esRef.current = es
      es.onmessage = (e) => handleEvent(e.data)
      es.onerror = () => {}
    }
    connect()
    return () => esRef.current?.close()
  }, [handleEvent])

  const clearProfiles = useCallback(() => {
    setProfileMap({})
    localStorage.removeItem(STORAGE_KEY)
  }, [])

  const profiles = Object.values(profileMap).sort(
    (a, b) => `${a.namespace}/${a.pod}`.localeCompare(`${b.namespace}/${b.pod}`)
  )

  return (
    <DiscoveryContext.Provider value={{ profiles, clearProfiles }}>
      {children}
    </DiscoveryContext.Provider>
  )
}
