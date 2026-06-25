import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { admissionRetentionApi } from '../api/client'

interface AdmissionRetentionContextValue {
  maxEvents: number
  applyRetention: (maxEvents: number) => void
}

const AdmissionRetentionContext = createContext<AdmissionRetentionContextValue>({
  maxEvents: 500,
  applyRetention: () => {},
})

export function useAdmissionRetention() {
  return useContext(AdmissionRetentionContext)
}

export function AdmissionRetentionProvider({ children }: { children: React.ReactNode }) {
  const [maxEvents, setMaxEvents] = useState(500)

  useEffect(() => {
    admissionRetentionApi.get()
      .then(r => setMaxEvents(r.maxEvents))
      .catch(() => {})
  }, [])

  const applyRetention = useCallback((n: number) => setMaxEvents(n), [])

  return (
    <AdmissionRetentionContext.Provider value={{ maxEvents, applyRetention }}>
      {children}
    </AdmissionRetentionContext.Provider>
  )
}
