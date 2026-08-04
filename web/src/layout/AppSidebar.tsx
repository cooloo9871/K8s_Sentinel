import { useState } from 'react'
import { useLocation, NavLink } from 'react-router-dom'
import { IconChevronRight } from '@tabler/icons-react'
import logoUrl from '../assets/sentinel-logo-black.svg'
import { useAuth } from './AuthContext'
import {
  Sidebar,
  SidebarHeader,
  SidebarContent,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarGroupContent,
  SidebarMenu,
  SidebarMenuItem,
  SidebarMenuButton,
} from '@/components/ui/sidebar'

type NavItem = { to: string; label: string }
type NavGroup = { label: string; items: NavItem[]; adminOnly?: boolean }

// The collapsible groups, as data: the open/closed state is keyed by label, so
// declaring them here keeps that state and the markup from drifting apart.
const GROUPS: NavGroup[] = [
  {
    label: 'Policies',
    items: [
      { to: '/policies/tracing', label: 'Tracing Policy' },
      { to: '/security/discovery', label: 'Behavior Discovery' },
      { to: '/policies/templates', label: 'Templates' },
      { to: '/policies/admission', label: 'Admission Policy' },
      { to: '/policies/network', label: 'Network Policy' },
    ],
  },
  {
    label: 'Notifications',
    items: [
      { to: '/security/events', label: 'Security Events' },
      { to: '/security/admission', label: 'Admission Events' },
    ],
  },
  {
    label: 'Cluster',
    items: [{ to: '/cluster/tetragon', label: 'Tetragon Agents' }],
  },
  {
    label: 'Settings',
    adminOnly: true,
    items: [
      { to: '/settings/users', label: 'Users' },
      { to: '/security/alerts', label: 'Alerts' },
      { to: '/security/rsyslog', label: 'Syslog' },
      { to: '/settings/retention', label: 'Event Retention' },
    ],
  },
]

// A group header is a top-level entry, the same rank as the ungrouped links, so
// they share a size. The links inside a group are the larger ones.
const TOP_LEVEL_CLASS = 'h-9 text-base'
const GROUP_ITEM_CLASS = 'h-10 text-lg'

export function AppSidebar() {
  const { pathname } = useLocation()
  const { user } = useAuth()

  const isActive = (path: string) =>
    pathname === path || pathname.startsWith(path + '/')

  // Groups start closed. The one holding the current page is opened, so a reload
  // or a shared link still shows where you are rather than four shut headers.
  // Clicking a link does not remount this component, so an open group stays open
  // while navigating.
  const [open, setOpen] = useState<Record<string, boolean>>(() => {
    const current = GROUPS.find(g => g.items.some(i => isActive(i.to)))
    return current ? { [current.label]: true } : {}
  })

  const toggle = (label: string) =>
    setOpen(prev => ({ ...prev, [label]: !prev[label] }))

  return (
    <Sidebar collapsible="offcanvas">
      <SidebarHeader>
        <div className="flex items-center gap-2.5 px-2 py-3">
          <img src={logoUrl} alt="K8s Sentinel" className="size-8 shrink-0" />
          <span className="text-base font-bold text-sidebar-foreground">K8s Sentinel</span>
        </div>
      </SidebarHeader>

      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu>
              <SidebarMenuItem>
                <SidebarMenuButton asChild isActive={isActive('/dashboard')} className={TOP_LEVEL_CLASS}>
                  <NavLink to="/dashboard">Dashboard</NavLink>
                </SidebarMenuButton>
              </SidebarMenuItem>
              <SidebarMenuItem>
                <SidebarMenuButton asChild isActive={isActive('/network/topology')} className={TOP_LEVEL_CLASS}>
                  <NavLink to="/network/topology">Network Topology</NavLink>
                </SidebarMenuButton>
              </SidebarMenuItem>
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        {GROUPS.filter(g => !g.adminOnly || user?.role === 'admin').map(group => {
          const expanded = !!open[group.label]
          return (
            <SidebarGroup key={group.label}>
              <SidebarGroupLabel asChild>
                <button
                  type="button"
                  aria-expanded={expanded}
                  onClick={() => toggle(group.label)}
                  className={`${TOP_LEVEL_CLASS} w-full cursor-pointer justify-between hover:text-sidebar-foreground`}
                >
                  {group.label}
                  <IconChevronRight
                    className={`transition-transform ${expanded ? 'rotate-90' : ''}`}
                  />
                </button>
              </SidebarGroupLabel>
              {expanded && (
                <SidebarGroupContent>
                  <SidebarMenu>
                    {group.items.map(item => (
                      <SidebarMenuItem key={item.to}>
                        <SidebarMenuButton asChild isActive={isActive(item.to)} className={GROUP_ITEM_CLASS}>
                          <NavLink to={item.to}>{item.label}</NavLink>
                        </SidebarMenuButton>
                      </SidebarMenuItem>
                    ))}
                  </SidebarMenu>
                </SidebarGroupContent>
              )}
            </SidebarGroup>
          )
        })}
      </SidebarContent>
    </Sidebar>
  )
}
