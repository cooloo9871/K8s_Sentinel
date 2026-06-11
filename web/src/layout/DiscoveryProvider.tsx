import { createContext, useCallback, useContext, useEffect, useState } from 'react'

export interface PodProfile {
  namespace: string
  pod: string
  workloadKind?: string  // "Deployment", "DaemonSet", "StatefulSet", etc.
  workloadName?: string  // controller name
  binaries: string[]
  firstSeen: string
  lastSeen: string
}

/** Aggregated view of multiple pods that share the same workload. */
export interface WorkloadProfile {
  namespace: string
  workloadKind: string   // e.g. "Deployment"
  workloadName: string   // e.g. "my-app"
  pods: string[]         // pod names in this group
  binaries: string[]     // union of all pod binaries
  firstSeen: string
  lastSeen: string
}

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

export function DiscoveryProvider({ children }: { children: React.ReactNode }) {
  const [profiles, setProfiles] = useState<PodProfile[]>([])

  useEffect(() => {
    let seq = 0 // sequence number to discard stale concurrent responses
    let cancelled = false
    const load = () => {
      const mySeq = ++seq
      fetch('/api/discovery/profiles')
        .then(r => r.json())
        .then(data => {
          if (!cancelled && mySeq === seq) setProfiles(data.profiles ?? [])
        })
        .catch(() => {})
    }
    load()
    const timer = setInterval(load, 2000)
    return () => { cancelled = true; clearInterval(timer) }
  }, [])

  const clearProfiles = useCallback(() => {
    fetch('/api/discovery/profiles', { method: 'DELETE' })
      .then(() => setProfiles([]))
      .catch(() => {})
  }, [])

  return (
    <DiscoveryContext.Provider value={{ profiles, clearProfiles }}>
      {children}
    </DiscoveryContext.Provider>
  )
}
