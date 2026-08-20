import { useState } from 'react'
import { useLocation, NavLink } from 'react-router-dom'
import { IconChevronRight } from '@tabler/icons-react'
import logoUrl from '../assets/sentinel-logo-black.svg'
import { useAuth } from './AuthContext'
import {
  Sidebar,
  SidebarHeader,
  SidebarContent,
  SidebarFooter,
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
      { to: '/policies/quarantine', label: 'Quarantine' },
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
    items: [{ to: '/cluster/tetragon', label: 'Event Sources' }],
  },
  {
    label: 'Settings',
    adminOnly: true,
    items: [
      { to: '/settings/users', label: 'Users' },
      { to: '/security/alerts', label: 'Alerts' },
      { to: '/security/rsyslog', label: 'Syslog' },
      { to: '/settings/retention', label: 'Event Retention' },
      { to: '/settings/audit', label: 'Audit Log' },
    ],
  },
]

// A group header is a top-level entry, the same rank as the ungrouped links, so
// they share a size. The links revealed inside a group sit a step below: smaller
// and dimmed, so the two ranks are told apart by more than 2px of type. The
// active item still takes the full accent colour — the base style applies that
// under data-active, which outranks this.
const TOP_LEVEL_CLASS = 'h-9 text-base'
const GROUP_ITEM_CLASS = 'h-8 text-sm text-sidebar-foreground/70'

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
              {/* The classes belong on SidebarGroupLabel, not on the button:
                  asChild concatenates the two className strings without
                  tailwind-merge, so the label's own text-xs and h-8 survived
                  alongside anything set here and won on stylesheet order — the
                  header stayed 12px however large this was set. Passed to the
                  label they go through cn(), which drops the conflicts. */}
              <SidebarGroupLabel
                asChild
                className={`${TOP_LEVEL_CLASS} w-full cursor-pointer justify-between text-sidebar-foreground`}
              >
                <button
                  type="button"
                  aria-expanded={expanded}
                  onClick={() => toggle(group.label)}
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

      <SidebarFooter>
        <span className="px-2 text-[11px] text-muted-foreground">
          {import.meta.env.VITE_APP_VERSION ?? 'dev'}
        </span>
      </SidebarFooter>
    </Sidebar>
  )
}
