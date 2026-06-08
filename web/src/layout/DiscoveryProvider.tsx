import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import { useSecurityEvents } from './SecurityEventsProvider'

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
  const { subscribeRaw } = useSecurityEvents()
  const [profileMap, setProfileMap] = useState<ProfileMap>(() => loadFromStorage())
  const saveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const profileMapRef = useRef<ProfileMap>(profileMap)

  useEffect(() => { profileMapRef.current = profileMap }, [profileMap])

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

  // Subscribe to the shared SSE stream via SecurityEventsProvider — no second connection needed
  const handleRaw = useCallback((raw: string) => {
    try {
      const evt = JSON.parse(raw) as {
        type?: string
        namespace?: string
        pod?: string
        binary?: string
        filePath?: string
        netDest?: string
        time?: string
      }

      const ns = evt.namespace ?? ''
      const pod = evt.pod ?? ''
      if (!ns || !pod) return

      const key = `${ns}/${pod}`
      const now = evt.time || new Date().toISOString()

      setProfileMap(prev => {
        const existing: PodProfile = prev[key] ?? {
          namespace: ns,
          pod,
          binaries: [],
          filePaths: [],
          netDests: [],
          firstSeen: now,
          lastSeen: now,
        }

        const binaries = evt.binary && !existing.binaries.includes(evt.binary)
          ? [...existing.binaries, evt.binary]
          : existing.binaries
        const filePaths = evt.filePath && !existing.filePaths.includes(evt.filePath)
          ? [...existing.filePaths, evt.filePath]
          : existing.filePaths
        const netDests = evt.netDest && !existing.netDests.includes(evt.netDest)
          ? [...existing.netDests, evt.netDest]
          : existing.netDests
        const lastSeen = now > existing.lastSeen ? now : existing.lastSeen

        // Skip state update if nothing changed
        if (
          binaries === existing.binaries &&
          filePaths === existing.filePaths &&
          netDests === existing.netDests &&
          lastSeen === existing.lastSeen
        ) return prev

        return { ...prev, [key]: { ...existing, binaries, filePaths, netDests, lastSeen } }
      })
    } catch {}
  }, [])

  useEffect(() => {
    return subscribeRaw(handleRaw)
  }, [subscribeRaw, handleRaw])

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
