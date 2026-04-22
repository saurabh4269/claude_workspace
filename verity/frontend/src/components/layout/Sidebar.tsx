import React from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { cn } from '@/lib/utils'

interface NavItem {
  label: string
  to: string
}

const navItems: NavItem[] = [
  { label: 'Dashboard', to: '/' },
  { label: 'New Scan', to: '/scan/new' },
  { label: 'History', to: '/history' },
  { label: 'Analytics', to: '/analytics' },
  { label: 'Settings', to: '/settings' },
]

export function Sidebar() {
  const location = useLocation()

  return (
    <aside className="fixed left-0 top-0 h-full w-56 bg-white border-r border-gray-100 flex flex-col z-20">
      {/* Logo */}
      <div className="px-8 py-8">
        <span className="font-display font-bold text-lg text-[#1c9770]">Verity</span>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-8 space-y-0.5">
        {navItems.map((item) => {
          const isActive =
            item.to === '/'
              ? location.pathname === '/'
              : location.pathname.startsWith(item.to)

          return (
            <NavLink
              key={item.to}
              to={item.to}
              className={cn(
                'block px-0 py-2 text-[15px] font-display font-bold transition-colors',
                isActive
                  ? 'text-[#1c9770]'
                  : 'text-gray-400 hover:text-[#464646]',
              )}
            >
              {item.label}
            </NavLink>
          )
        })}
      </nav>
    </aside>
  )
}
