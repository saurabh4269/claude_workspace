import React, { Suspense } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { Sidebar } from '@/components/layout/Sidebar'
import { Header } from '@/components/layout/Header'
import { Spinner } from '@/components/ui/Spinner'
import Dashboard from '@/pages/Dashboard'
import NewScan from '@/pages/NewScan'
import ScanDetail from '@/pages/ScanDetail'
import History from '@/pages/History'
import Settings from '@/pages/Settings'
import Login from '@/pages/Login'

function PageLoader() {
  return (
    <div className="flex items-center justify-center h-64">
      <Spinner size={28} />
    </div>
  )
}

function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen bg-white">
      <Sidebar />
      <div className="flex-1 flex flex-col ml-60">
        <Header />
        <main className="flex-1 overflow-y-auto">
          <Suspense fallback={<PageLoader />}>{children}</Suspense>
        </main>
      </div>
    </div>
  )
}

export default function App() {
  return (
    <Routes>
      {/* Login page - no sidebar */}
      <Route path="/login" element={<Login />} />

      {/* Main app with sidebar layout */}
      <Route
        path="/"
        element={
          <AppLayout>
            <Dashboard />
          </AppLayout>
        }
      />
      <Route
        path="/scan/new"
        element={
          <AppLayout>
            <NewScan />
          </AppLayout>
        }
      />
      <Route
        path="/scan/:id"
        element={
          <AppLayout>
            <ScanDetail />
          </AppLayout>
        }
      />
      <Route
        path="/history"
        element={
          <AppLayout>
            <History />
          </AppLayout>
        }
      />
      <Route
        path="/settings"
        element={
          <AppLayout>
            <Settings />
          </AppLayout>
        }
      />

      {/* Catch-all redirect */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
