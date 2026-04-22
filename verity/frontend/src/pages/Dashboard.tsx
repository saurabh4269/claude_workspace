import React from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { scans, type ScanSummary } from '@/lib/api'
import { Button } from '@/components/ui/Button'
import { RiskBadge } from '@/components/RiskBadge'
import { formatDate } from '@/lib/utils'

function LoadingSkeleton() {
  return (
    <div className="p-10 space-y-10 animate-pulse">
      <div className="grid grid-cols-2 sm:grid-cols-4 border border-gray-100 rounded-xl divide-x divide-y sm:divide-y-0 divide-gray-100">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="px-8 py-6">
            <div className="h-10 w-16 bg-gray-100 rounded mb-2" />
            <div className="h-3 w-24 bg-gray-100 rounded" />
          </div>
        ))}
      </div>
      <div className="space-y-3">
        <div className="h-3 w-32 bg-gray-100 rounded" />
        {[...Array(4)].map((_, i) => (
          <div key={i} className="flex items-center gap-3 py-2">
            <div className="h-3 w-16 bg-gray-100 rounded" />
            <div className="flex-1 h-1 bg-gray-100 rounded-full" />
            <div className="h-3 w-4 bg-gray-100 rounded" />
          </div>
        ))}
      </div>
      <div className="space-y-3">
        <div className="h-3 w-28 bg-gray-100 rounded" />
        {[...Array(5)].map((_, i) => (
          <div key={i} className="flex items-center gap-4 py-4 border-b border-gray-100">
            <div className="h-4 w-48 bg-gray-100 rounded" />
            <div className="h-3 w-24 bg-gray-100 rounded ml-auto" />
            <div className="h-3 w-12 bg-gray-100 rounded" />
          </div>
        ))}
      </div>
    </div>
  )
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
  const highCriticalCount = items.filter(
    (s) => s.riskLevel === 'HIGH' || s.riskLevel === 'CRITICAL',
  ).length

  const levelCounts = {
    LOW: items.filter((s) => s.riskLevel === 'LOW').length,
    MEDIUM: items.filter((s) => s.riskLevel === 'MEDIUM').length,
    HIGH: items.filter((s) => s.riskLevel === 'HIGH').length,
    CRITICAL: items.filter((s) => s.riskLevel === 'CRITICAL').length,
  }

  if (isLoading) return <LoadingSkeleton />

  if (isError) {
    return (
      <div className="p-10">
        <div className="bg-[#f2eeee] px-6 py-4 rounded-lg text-[#dc2626] font-sans text-[15px]">
          Failed to load dashboard data. Please try refreshing the page.
        </div>
      </div>
    )
  }

  if (total === 0 && !isLoading) {
    return (
      <div className="p-10 flex flex-col items-center justify-center min-h-[60vh] text-center gap-6">
        <h2 className="font-display font-bold text-2xl text-[#464646]">
          No scans yet
        </h2>
        <p className="text-gray-400 font-sans text-[15px] max-w-sm">
          Upload your first SBOM to validate and assess risk across your software supply chain.
        </p>
        <Link to="/scan/new">
          <Button size="lg">Upload your first SBOM</Button>
        </Link>
      </div>
    )
  }

  return (
    <div className="p-10 space-y-12">
      {/* Stats row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 border border-gray-100 rounded-xl divide-x divide-y sm:divide-y-0 divide-gray-100">
        {[
          { label: 'Total Scans', value: total },
          { label: 'Vulnerable Components', value: totalVulnerable },
          { label: 'NTIA Compliant', value: `${ntiaCompliant}%` },
          { label: 'High / Critical', value: highCriticalCount },
        ].map(({ label, value }) => (
          <div key={label} className="px-8 py-6">
            <p className="text-4xl font-display font-bold text-[#464646]">{value}</p>
            <p className="text-xs font-display font-bold text-gray-400 uppercase tracking-widest mt-1">{label}</p>
          </div>
        ))}
      </div>

      {/* Risk distribution */}
      <div>
        <p className="text-xs font-display font-bold text-gray-400 uppercase tracking-widest mb-6">
          Risk Distribution
        </p>
        <div className="space-y-3">
          {(
            [
              { level: 'CRITICAL', color: 'bg-[#dc2626]', text: 'text-[#dc2626]' },
              { level: 'HIGH', color: 'bg-[#f97316]', text: 'text-[#f97316]' },
              { level: 'MEDIUM', color: 'bg-[#f59e0b]', text: 'text-[#f59e0b]' },
              { level: 'LOW', color: 'bg-[#93cb52]', text: 'text-[#93cb52]' },
            ] as const
          ).map(({ level, color, text }) => {
            const count = levelCounts[level]
            const pct = items.length > 0 ? (count / items.length) * 100 : 0
            return (
              <div key={level} className="flex items-center gap-4">
                <span className={`w-20 text-[15px] font-display font-bold ${text}`}>{level}</span>
                <div className="flex-1 h-1.5 rounded-full bg-gray-100">
                  <div
                    className={`h-1.5 rounded-full ${color} transition-all`}
                    style={{ width: `${pct}%` }}
                  />
                </div>
                <span className="w-6 text-right text-[15px] font-sans text-gray-400">{count}</span>
              </div>
            )
          })}
        </div>
      </div>

      {/* Recent scans */}
      <div>
        <div className="flex items-center justify-between mb-6">
          <p className="text-xs font-display font-bold text-gray-400 uppercase tracking-widest">
            Recent Scans
          </p>
          <Link to="/history" className="text-sm font-sans text-[#1c9770] hover:underline">
            View all
          </Link>
        </div>
        <div className="border-t border-gray-100">
          {items.slice(0, 8).map((scan) => (
            <Link
              key={scan.id}
              to={`/scan/${scan.id}`}
              className="flex items-center gap-4 py-4 border-b border-gray-100 hover:bg-gray-50/50 -mx-2 px-2 transition-colors group"
            >
              <div className="flex-1 min-w-0">
                <p className="text-[15px] font-sans font-medium text-[#464646] truncate group-hover:text-[#1c9770] transition-colors">
                  {scan.filename}
                </p>
              </div>
              <span className="text-sm font-sans text-gray-400 whitespace-nowrap shrink-0">
                {formatDate(scan.createdAt)}
              </span>
              <RiskBadge level={scan.riskLevel} />
            </Link>
          ))}
        </div>
      </div>

      {/* High/Critical alert section */}
      {items.some((s) => s.riskLevel === 'HIGH' || s.riskLevel === 'CRITICAL') && (
        <div>
          <p className="text-xs font-display font-bold text-[#dc2626] uppercase tracking-widest mb-6">
            Requires Attention
          </p>
          <div className="border-t border-gray-100">
            {items
              .filter((s) => s.riskLevel === 'HIGH' || s.riskLevel === 'CRITICAL')
              .map((scan) => (
                <div key={scan.id} className="flex items-center gap-4 py-4 border-b border-gray-100">
                  <div className="flex-1 min-w-0">
                    <Link
                      to={`/scan/${scan.id}`}
                      className="text-[15px] font-sans font-medium text-[#464646] hover:text-[#1c9770] transition-colors truncate block"
                    >
                      {scan.filename}
                    </Link>
                    <p className="text-sm text-gray-400 font-sans mt-0.5">
                      {scan.vulnerableComponents} vulnerable · {formatDate(scan.createdAt)}
                    </p>
                  </div>
                  <RiskBadge level={scan.riskLevel} />
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  )
}
