import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import { ciliumApi, type CiliumFlow, type CiliumStatus } from '../api/client'

interface CiliumContextValue {
  flows: CiliumFlow[]
  status: CiliumStatus | null
  connected: boolean
}

const CiliumContext = createContext<CiliumContextValue>({
  flows: [],
  status: null,
  connected: false,
})

export function useCilium() {
  return useContext(CiliumContext)
}

const MAX_FLOWS = 1000

export function CiliumProvider({ children }: { children: React.ReactNode }) {
  const [flows, setFlows] = useState<CiliumFlow[]>([])
  const [status, setStatus] = useState<CiliumStatus | null>(null)
  const [connected, setConnected] = useState(false)
  const esRef = useRef<EventSource | null>(null)

  const startSSE = useCallback(() => {
    esRef.current?.close()
    setConnected(false)
    const es = new EventSource('/api/cilium/flows/stream')
    esRef.current = es
    es.onopen = () => setConnected(true)
    es.onmessage = (raw) => {
      try {
        const flow: CiliumFlow = JSON.parse(raw.data)
        setFlows(prev => [flow, ...prev].slice(0, MAX_FLOWS))
      } catch { /* ignore */ }
    }
    es.onerror = () => setConnected(false)
  }, [])

  useEffect(() => {
    // Check Cilium/Hubble status first
    ciliumApi.status()
      .then(s => {
        setStatus(s)
        if (s.available && s.ready) {
          startSSE()
        }
      })
      .catch(() => setStatus({ available: false, ready: false }))
    return () => esRef.current?.close()
  }, [startSSE])

  return (
    <CiliumContext.Provider value={{ flows, status, connected }}>
      {children}
    </CiliumContext.Provider>
  )
}
