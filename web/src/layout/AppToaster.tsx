import { createContext, useCallback, useContext, useRef, useState } from 'react'
import { CToast, CToastBody, CToaster } from '@coreui/react'

interface ToastItem { id: number; color: string; message: string }

interface ToastContextValue {
  success: (msg: string) => void
  error: (msg: string) => void
}

const ToastContext = createContext<ToastContextValue>({
  success: () => {},
  error: () => {},
})

export function useToast() {
  return useContext(ToastContext)
}

export function AppToaster({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([])
  const nextId = useRef(0)

  const addToast = useCallback((color: string, message: string) => {
    const id = ++nextId.current
    setToasts((prev) => [...prev, { id, color, message }])
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id))
    }, 4000)
  }, [])

  const value: ToastContextValue = {
    success: (msg) => addToast('success', msg),
    error: (msg) => addToast('danger', msg),
  }

  return (
    <ToastContext.Provider value={value}>
      {children}
      <CToaster
        placement="top-end"
        style={{ position: 'fixed', top: '1rem', right: '1rem', zIndex: 9999 }}
      >
        {toasts.map((t) => (
          <CToast key={t.id} visible autohide={false} color={t.color}>
            <CToastBody className="text-white">{t.message}</CToastBody>
          </CToast>
        ))}
      </CToaster>
    </ToastContext.Provider>
  )
}
