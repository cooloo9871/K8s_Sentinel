import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import { admissionRetentionApi } from '../api/client'

interface AdmissionRetentionContextValue {
  maxEvents: number
  maxEventsRef: React.MutableRefObject<number>
  loaded: boolean
  applyRetention: (maxEvents: number) => void
}

const AdmissionRetentionContext = createContext<AdmissionRetentionContextValue>({
  maxEvents: 500,
  maxEventsRef: { current: 500 },
  loaded: false,
  applyRetention: () => {},
})

export function useAdmissionRetention() {
  return useContext(AdmissionRetentionContext)
}

export function AdmissionRetentionProvider({ children }: { children: React.ReactNode }) {
  const [maxEvents, setMaxEvents] = useState(500)
  const [loaded, setLoaded] = useState(false)
  // Ref kept in sync so SSE closures always read the latest cap without stale capture.
  const maxEventsRef = useRef(500)

  useEffect(() => {
    admissionRetentionApi.get()
      .then(r => {
        maxEventsRef.current = r.maxEvents
        setMaxEvents(r.maxEvents)
      })
      .catch(() => {})
      .finally(() => setLoaded(true))
  }, [])

  const applyRetention = useCallback((n: number) => {
    maxEventsRef.current = n
    setMaxEvents(n)
  }, [])

  return (
    <AdmissionRetentionContext.Provider value={{ maxEvents, maxEventsRef, loaded, applyRetention }}>
      {children}
    </AdmissionRetentionContext.Provider>
  )
}
