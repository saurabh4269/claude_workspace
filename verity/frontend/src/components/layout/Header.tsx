import React from 'react'
import { LogOut } from 'lucide-react'

export function Header() {
  const token = localStorage.getItem('access_token')
  const userEmail = localStorage.getItem('user_email')

  const handleLogout = () => {
    localStorage.removeItem('access_token')
    localStorage.removeItem('refresh_token')
    localStorage.removeItem('user_email')
    window.location.href = '/login'
  }

  if (!token || !userEmail) return null

  return (
    <header className="flex items-center justify-end gap-4 px-10 py-4 border-b border-gray-100">
      <span className="text-sm text-gray-400 font-sans">{userEmail}</span>
      <button
        onClick={handleLogout}
        className="flex items-center gap-1.5 text-sm text-gray-400 hover:text-[#464646] font-sans transition-colors"
      >
        <LogOut size={14} />
        Sign out
      </button>
    </header>
  )
}
