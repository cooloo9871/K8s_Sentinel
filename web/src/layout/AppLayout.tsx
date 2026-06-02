import { Outlet } from 'react-router-dom'
import { CContainer } from '@coreui/react'
import { AppSidebar } from './AppSidebar'
import { AppHeader } from './AppHeader'

export function AppLayout() {
  return (
    <div style={{ display: 'flex', minHeight: '100vh' }}>
      <AppSidebar />
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        <AppHeader />
        <main style={{ flex: 1, background: '#f5f6fa' }}>
          <CContainer lg className="py-4">
            <Outlet />
          </CContainer>
        </main>
      </div>
    </div>
  )
}
