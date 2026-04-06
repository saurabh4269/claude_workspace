import React from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import {
  Shield,
  LayoutDashboard,
  Plus,
  History,
  Settings,
} from 'lucide-react'
import { cn } from '@/lib/utils'

interface NavItem {
  label: string
  to: string
  icon: React.ElementType
}

const navItems: NavItem[] = [
  { label: 'Dashboard', to: '/', icon: LayoutDashboard },
  { label: 'New Scan', to: '/scan/new', icon: Plus },
  { label: 'History', to: '/history', icon: History },
  { label: 'Settings', to: '/settings', icon: Settings },
]

export function Sidebar() {
  const location = useLocation()

  return (
    <aside className="fixed left-0 top-0 h-full w-60 bg-white border-r border-[#e5e7eb] flex flex-col z-20">
      {/* Logo */}
      <div className="flex items-center gap-2.5 px-6 py-5 border-b border-[#e5e7eb]">
        <Shield size={22} className="text-[#1c9770]" strokeWidth={2.5} />
        <span className="font-display font-bold text-xl text-[#1c9770]">
          Verity
        </span>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-0.5">
        {navItems.map((item) => {
          const Icon = item.icon
          const isActive =
            item.to === '/'
              ? location.pathname === '/'
              : location.pathname.startsWith(item.to)

          return (
            <NavLink
              key={item.to}
              to={item.to}
              className={cn(
                'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-display font-bold transition-colors',
                isActive
                  ? 'bg-[#bef3e2] text-[#1c9770]'
                  : 'text-[#464646] hover:bg-gray-50',
              )}
            >
              <Icon
                size={18}
                className={cn(
                  isActive ? 'text-[#1c9770]' : 'text-[#464646]',
                )}
                strokeWidth={2}
              />
              {item.label}
            </NavLink>
          )
        })}
      </nav>

      {/* Footer */}
      <div className="px-6 py-4 border-t border-[#e5e7eb]">
        <span className="text-xs text-gray-400 font-sans">v0.1.0</span>
      </div>
    </aside>
  )
}
