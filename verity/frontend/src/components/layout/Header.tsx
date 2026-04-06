import React from 'react'
import { useLocation } from 'react-router-dom'
import { LogOut } from 'lucide-react'
import { Button } from '@/components/ui/Button'

const pageTitles: Record<string, string> = {
  '/': 'Dashboard',
  '/scan/new': 'New Scan',
  '/history': 'History',
  '/settings': 'Settings',
}

function getPageTitle(pathname: string): string {
  if (pageTitles[pathname]) return pageTitles[pathname]
  if (pathname.startsWith('/scan/')) return 'Scan Results'
  return 'Verity'
}

export function Header() {
  const location = useLocation()
  const title = getPageTitle(location.pathname)

  const token = localStorage.getItem('access_token')
  const userEmail = localStorage.getItem('user_email')

  const handleLogout = () => {
    localStorage.removeItem('access_token')
    localStorage.removeItem('refresh_token')
    localStorage.removeItem('user_email')
    window.location.href = '/login'
  }

  return (
    <header className="h-14 flex items-center justify-between px-8 bg-white border-b border-[#e5e7eb]">
      <h1 className="font-display font-bold text-lg text-[#464646]">{title}</h1>

      {token && userEmail && (
        <div className="flex items-center gap-4">
          <span className="text-sm text-gray-500 font-sans">{userEmail}</span>
          <Button
            variant="ghost"
            size="sm"
            onClick={handleLogout}
            className="text-gray-500 hover:text-[#464646]"
          >
            <LogOut size={15} />
            Sign out
          </Button>
        </div>
      )}
    </header>
  )
}
