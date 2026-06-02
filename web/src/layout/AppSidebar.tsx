import {
  CSidebar,
  CSidebarBrand,
  CSidebarNav,
  CNavTitle,
  CNavItem,
  CNavGroup,
} from '@coreui/react'
import { NavLink } from 'react-router-dom'

const navLinkClass = ({ isActive }: { isActive: boolean }) =>
  isActive ? 'nav-link active' : 'nav-link'

export function AppSidebar() {
  return (
    <CSidebar
      colorScheme="dark"
      style={{ background: '#1b2a3b', minHeight: '100vh', width: 240, flexShrink: 0 }}
    >
      <CSidebarBrand
        style={{
          background: '#142030',
          color: '#fff',
          fontWeight: 700,
          fontSize: '1.1rem',
          padding: '1rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
        }}
      >
        <span
          style={{
            width: 28,
            height: 28,
            background: '#2d7dd2',
            borderRadius: 6,
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
            <rect x="1" y="1" width="12" height="12" rx="2" stroke="white" strokeWidth="2" />
          </svg>
        </span>
        Sentinel
      </CSidebarBrand>

      <CSidebarNav>
        <CNavItem>
          <NavLink to="/dashboard" className={navLinkClass}>Dashboard</NavLink>
        </CNavItem>

        <CNavTitle>Policies</CNavTitle>
        <CNavGroup toggler="All Policies" visible>
          <CNavItem>
            <NavLink to="/policies/tracing" className={navLinkClass}>TracingPolicy</NavLink>
          </CNavItem>
        </CNavGroup>

        <CNavTitle>Cluster</CNavTitle>
        <CNavItem>
          <NavLink to="/cluster/mode" className={navLinkClass}>Mode Control</NavLink>
        </CNavItem>
        <CNavItem>
          <NavLink to="/cluster/namespaces" className={navLinkClass}>Namespaces</NavLink>
        </CNavItem>
      </CSidebarNav>
    </CSidebar>
  )
}
