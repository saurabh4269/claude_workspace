import React from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Plus, FileText, TrendingUp, ShieldCheck, AlertTriangle } from 'lucide-react'
import { scans, type ScanSummary } from '@/lib/api'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { RiskBadge } from '@/components/RiskBadge'
import { RiskChart } from '@/components/RiskChart'
import { Badge } from '@/components/ui/Badge'
import { formatDate, formatScore } from '@/lib/utils'

function StatCardSkeleton() {
  return (
    <div className="rounded-lg border border-[#e5e7eb] bg-white p-6 shadow-sm animate-pulse">
      <div className="h-4 w-24 bg-gray-100 rounded mb-3" />
      <div className="h-8 w-16 bg-gray-100 rounded" />
    </div>
  )
}

function ScanRowSkeleton() {
  return (
    <div className="flex items-center gap-4 py-3 border-b border-[#e5e7eb] animate-pulse">
      <div className="h-4 w-48 bg-gray-100 rounded" />
      <div className="h-4 w-20 bg-gray-100 rounded" />
      <div className="h-4 w-16 bg-gray-100 rounded ml-auto" />
    </div>
  )
}

interface StatCardProps {
  label: string
  value: string | number
  icon: React.ElementType
  iconColor: string
  sub?: string
}

function StatCard({ label, value, icon: Icon, iconColor, sub }: StatCardProps) {
  return (
    <Card>
      <CardContent className="p-6">
        <div className="flex items-start justify-between">
          <div>
            <p className="text-sm font-sans text-gray-400 mb-1">{label}</p>
            <p className="font-display font-bold text-3xl text-[#464646]">{value}</p>
            {sub && <p className="text-xs text-gray-400 font-sans mt-1">{sub}</p>}
          </div>
          <div className={`rounded-xl p-3 ${iconColor}`}>
            <Icon size={20} className="text-white" />
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

function formatBadgeVariant(
  format: string,
): 'default' | 'info' | 'success' | 'warning' | 'error' {
  const f = format?.toLowerCase()
  if (f?.includes('cyclonedx')) return 'info'
  if (f?.includes('spdx')) return 'success'
  return 'default'
}

export default function Dashboard() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['scans', { perPage: 10, page: 1 }],
    queryFn: () => scans.list({ perPage: 10, page: 1 }),
  })

  const items: ScanSummary[] = data?.items ?? []
  const total = data?.total ?? 0

  const totalVulnerable = items.reduce((sum, s) => sum + (s.vulnerableComponents ?? 0), 0)
  const ntiaCompliant = items.length
    ? Math.round((items.filter((s) => s.ntiaCompliant).length / items.length) * 100)
    : 0
  const avgScore =
    items.length > 0
      ? items.reduce((sum, s) => sum + s.riskScore, 0) / items.length
      : 0

  const highCriticalComponents = items.flatMap(() => []).slice(0, 0) // placeholder

  if (isLoading) {
    return (
      <div className="p-8 space-y-8">
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <StatCardSkeleton key={i} />
          ))}
        </div>
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          <div className="rounded-lg border border-[#e5e7eb] bg-white p-6 shadow-sm animate-pulse h-64" />
          <div className="rounded-lg border border-[#e5e7eb] bg-white p-6 shadow-sm animate-pulse h-64" />
        </div>
        <div className="rounded-lg border border-[#e5e7eb] bg-white p-6 shadow-sm animate-pulse">
          {[...Array(5)].map((_, i) => (
            <ScanRowSkeleton key={i} />
          ))}
        </div>
      </div>
    )
  }

  if (isError) {
    return (
      <div className="p-8">
        <div className="rounded-lg bg-[#f2eeee] px-6 py-4 text-[#dc2626] font-sans text-sm">
          Failed to load dashboard data. Please try refreshing the page.
        </div>
      </div>
    )
  }

  if (total === 0 && !isLoading) {
    return (
      <div className="p-8 flex flex-col items-center justify-center min-h-[60vh] text-center gap-6">
        <div className="flex h-20 w-20 items-center justify-center rounded-full bg-[#bef3e2]">
          <FileText size={36} className="text-[#1c9770]" />
        </div>
        <div>
          <h2 className="font-display font-bold text-2xl text-[#464646] mb-2">
            No scans yet
          </h2>
          <p className="text-gray-400 font-sans text-sm max-w-sm">
            Upload your first SBOM to validate and assess risk across your software supply chain.
          </p>
        </div>
        <Link to="/scan/new">
          <Button size="lg">
            <Plus size={18} />
            Upload your first SBOM
          </Button>
        </Link>
      </div>
    )
  }

  return (
    <div className="p-8 space-y-8">
      {/* Stat cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <StatCard
          label="Total Scans"
          value={total}
          icon={FileText}
          iconColor="bg-[#1c9770]"
        />
        <StatCard
          label="Vulnerable Components"
          value={totalVulnerable}
          icon={AlertTriangle}
          iconColor="bg-[#f97316]"
          sub="across recent scans"
        />
        <StatCard
          label="NTIA Compliant"
          value={`${ntiaCompliant}%`}
          icon={ShieldCheck}
          iconColor="bg-[#93cb52]"
          sub="of recent scans"
        />
        <StatCard
          label="Avg Risk Score"
          value={formatScore(avgScore)}
          icon={TrendingUp}
          iconColor="bg-[#f59e0b]"
          sub="out of 100"
        />
      </div>

      {/* Chart + Recent scans */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Risk Score Trend</CardTitle>
          </CardHeader>
          <CardContent>
            <RiskChart scans={items} mode="trend" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex-row items-center justify-between pb-2">
            <CardTitle>Recent Scans</CardTitle>
            <Link
              to="/history"
              className="text-sm font-sans text-[#1c9770] hover:underline"
            >
              View all
            </Link>
          </CardHeader>
          <CardContent>
            <div className="divide-y divide-[#e5e7eb]">
              {items.slice(0, 6).map((scan) => (
                <Link
                  key={scan.id}
                  to={`/scan/${scan.id}`}
                  className="flex items-center gap-3 py-3 hover:bg-gray-50 -mx-2 px-2 rounded-lg transition-colors group"
                >
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-sans font-medium text-[#464646] truncate group-hover:text-[#1c9770] transition-colors">
                      {scan.filename}
                    </p>
                    <p className="text-xs text-gray-400 font-sans mt-0.5">
                      {formatDate(scan.createdAt)}
                    </p>
                  </div>
                  <Badge variant={formatBadgeVariant(scan.sbomFormat)}>
                    {scan.sbomFormat}
                  </Badge>
                  <RiskBadge level={scan.riskLevel} />
                </Link>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* HIGH/CRITICAL alert section */}
      {items.some((s) => s.riskLevel === 'HIGH' || s.riskLevel === 'CRITICAL') && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-[#dc2626]">
              <AlertTriangle size={18} className="text-[#dc2626]" />
              High Risk Scans
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="divide-y divide-[#e5e7eb]">
              {items
                .filter((s) => s.riskLevel === 'HIGH' || s.riskLevel === 'CRITICAL')
                .map((scan) => (
                  <div
                    key={scan.id}
                    className="flex items-center gap-4 py-3"
                  >
                    <div className="flex-1 min-w-0">
                      <Link
                        to={`/scan/${scan.id}`}
                        className="text-sm font-sans font-medium text-[#464646] hover:text-[#1c9770] transition-colors truncate block"
                      >
                        {scan.filename}
                      </Link>
                      <p className="text-xs text-gray-400 font-sans">
                        {scan.vulnerableComponents} vulnerable
                        {' | '}
                        {formatDate(scan.createdAt)}
                      </p>
                    </div>
                    <RiskBadge level={scan.riskLevel} />
                    <span className="text-sm font-display font-bold text-[#464646]">
                      {formatScore(scan.riskScore)}
                    </span>
                  </div>
                ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
