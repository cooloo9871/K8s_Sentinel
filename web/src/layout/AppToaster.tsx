import { useMemo } from 'react'
import { toast } from 'sonner'
import { Toaster } from '@/components/ui/sonner'

// Memoised because callers put it in dependency arrays. Returning a fresh object
// each render made every such array change on every render — a useCallback built
// on it was never stable, so an effect depending on that callback re-ran forever,
// refetching on every render it caused.
export function useToast() {
  return useMemo(() => ({
    success: (msg: string) => toast.success(msg),
    error: (msg: string) => toast.error(msg),
  }), [])
}

export function AppToaster({ children }: { children: React.ReactNode }) {
  return (
    <>
      {children}
      <Toaster position="top-right" />
    </>
  )
}
