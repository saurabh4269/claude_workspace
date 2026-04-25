import React from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { BarChart3, TrendingUp, ShieldCheck, AlertTriangle } from 'lucide-react'
import { workspaces } from '@/lib/api'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card'
import { Spinner } from '@/components/ui/Spinner'

function StatCard({ icon: Icon, label, value, sub }: {
  icon: React.ElementType
  label: string
  value: React.ReactNode
  sub?: string
}) {
  return (
    <Card>
      <CardContent>
        <div className="flex items-start gap-4 pt-4">
          <div className="p-2 rounded-lg bg-[#edfaf3]">
            <Icon size={20} className="text-[#1c9770]" />
          </div>
          <div>
            <p className="text-2xl font-display font-bold text-[#464646]">{value}</p>
            <p className="text-sm font-sans text-gray-400 mt-0.5">{label}</p>
            {sub && <p className="text-xs text-gray-300 font-sans mt-0.5">{sub}</p>}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

function RiskDistBar({ dist }: { dist: Record<string, number> }) {
  const total = Object.values(dist).reduce((a, b) => a + b, 0)
  if (total === 0) return <p className="text-sm text-gray-400 font-sans">No data</p>

  const colors: Record<string, string> = {
    LOW: 'bg-[#22c55e]',
    MEDIUM: 'bg-[#f59e0b]',
    HIGH: 'bg-[#f97316]',
    CRITICAL: 'bg-[#dc2626]',
  }

  return (
    <div className="space-y-2">
      {['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((level) => {
        const count = dist[level] || 0
        const pct = total > 0 ? (count / total) * 100 : 0
        return (
          <div key={level} className="flex items-center gap-3 text-sm font-sans">
            <span className="w-16 text-xs text-gray-400 uppercase">{level}</span>
            <div className="flex-1 h-2 bg-gray-100 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full ${colors[level] || 'bg-gray-300'}`}
                style={{ width: `${pct}%` }}
              />
            </div>
            <span className="w-8 text-right text-xs text-gray-500">{count}</span>
          </div>
        )
      })}
    </div>
  )
}

function TrendLine({ trend }: { trend: { date: string; riskScore: number; qualityScore?: number }[] }) {
  if (!trend.length) return <p className="text-sm text-gray-400 font-sans">No trend data.</p>

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full text-xs font-sans">
        <thead>
          <tr className="border-b border-[#e5e7eb]">
            <th className="px-3 py-2 text-left text-gray-400">Date</th>
            <th className="px-3 py-2 text-right text-gray-400">Risk Score</th>
            <th className="px-3 py-2 text-right text-gray-400">Quality</th>
          </tr>
        </thead>
        <tbody>
          {trend.map((row, i) => (
            <tr key={i} className="border-b border-[#e5e7eb] odd:bg-white even:bg-gray-50/50">
              <td className="px-3 py-2 text-gray-500">{new Date(row.date).toLocaleDateString()}</td>
              <td className="px-3 py-2 text-right font-mono">{row.riskScore.toFixed(1)}</td>
              <td className="px-3 py-2 text-right font-mono">
                {row.qualityScore != null ? row.qualityScore.toFixed(1) : 'N/A'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default function Analytics() {
  const [selectedWorkspaceId, setSelectedWorkspaceId] = React.useState<string>('')

  const { data: workspaceList, isLoading: wsLoading } = useQuery({
    queryKey: ['workspaces'],
    queryFn: () => workspaces.list(),
    retry: false,
  })

  // Auto-select first workspace when list loads
  React.useEffect(() => {
    if (workspaceList && workspaceList.length > 0 && !selectedWorkspaceId) {
      setSelectedWorkspaceId(workspaceList[0].id)
    }
  }, [workspaceList, selectedWorkspaceId])

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['workspace-analytics', selectedWorkspaceId],
    queryFn: () => workspaces.analytics(selectedWorkspaceId),
    enabled: selectedWorkspaceId.length > 0,
    retry: false,
  })

  return (
    <div className="p-8 pb-24 space-y-6">
      <div>
        <h1 className="font-display font-bold text-2xl text-[#464646]">Workspace Analytics</h1>
        <p className="text-sm text-gray-400 font-sans mt-1">
          Aggregate statistics across all scans in a workspace.
        </p>
      </div>

      {/* Workspace selector */}
      {wsLoading ? (
        <div className="flex items-center gap-2">
          <Spinner size={16} />
          <span className="text-sm text-gray-400 font-sans">Loading workspaces...</span>
        </div>
      ) : !workspaceList || workspaceList.length === 0 ? (
        <div className="rounded-xl bg-gray-50 px-6 py-8 text-center">
          <BarChart3 size={40} className="text-gray-300 mx-auto mb-3" />
          <p className="text-sm text-gray-400 font-sans">No workspaces found. Create one in <Link to="/settings" className="underline hover:text-gray-600">Settings</Link>.</p>
        </div>
      ) : (
        <div className="flex gap-3 items-end flex-wrap">
          <div>
            <label className="block text-xs font-display font-bold text-gray-500 mb-1">
              Workspace
            </label>
            <select
              value={selectedWorkspaceId}
              onChange={(e) => setSelectedWorkspaceId(e.target.value)}
              className="h-10 px-3 text-sm border border-[#e5e7eb] rounded-lg font-sans focus:outline-none focus:ring-2 focus:ring-[#1c9770] bg-white text-[#464646]"
            >
              {workspaceList.map((ws) => (
                <option key={ws.id} value={ws.id}>
                  {ws.name}
                </option>
              ))}
            </select>
          </div>
        </div>
      )}

      {selectedWorkspaceId && isLoading && (
        <div className="flex justify-center py-12">
          <Spinner size={28} />
        </div>
      )}

      {selectedWorkspaceId && isError && (
        <div className="rounded-xl bg-[#f2eeee] px-6 py-4 text-[#dc2626] text-sm font-sans">
          {(error as Error)?.message || 'Failed to load analytics.'}
        </div>
      )}

      {data && data.totalScans === 0 && (
        <div className="rounded-xl bg-gray-50 px-6 py-8 text-center">
          <BarChart3 size={40} className="text-gray-300 mx-auto mb-3" />
          <p className="text-sm text-gray-400 font-sans">
            No scans yet in this workspace. Run a scan and associate it with this workspace to see analytics.
          </p>
        </div>
      )}

      {data && data.totalScans > 0 && (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard
              icon={BarChart3}
              label="Total Scans"
              value={data.totalScans}
            />
            <StatCard
              icon={TrendingUp}
              label="Avg Quality Score"
              value={data.avgQualityScore != null ? data.avgQualityScore.toFixed(1) : 'N/A'}
              sub="out of 10"
            />
            <StatCard
              icon={AlertTriangle}
              label="Avg Risk Score"
              value={data.avgRiskScore.toFixed(1)}
              sub="out of 100"
            />
            <StatCard
              icon={ShieldCheck}
              label="NTIA Pass Rate"
              value={`${(data.ntiaPassRate * 100).toFixed(0)}%`}
            />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader><CardTitle>Risk Distribution</CardTitle></CardHeader>
              <CardContent>
                <RiskDistBar dist={data.riskDistribution} />
              </CardContent>
            </Card>

            <Card>
              <CardHeader><CardTitle>Top Vulnerabilities</CardTitle></CardHeader>
              <CardContent>
                {!data.topVulnerabilities?.length ? (
                  <p className="text-sm text-gray-400 font-sans">No vulnerabilities found.</p>
                ) : (
                  <div className="space-y-1">
                    {data.topVulnerabilities.map((v) => (
                      <div key={v.id} className="flex items-center justify-between text-xs font-sans">
                        <span className="font-mono text-[#464646]">{v.id}</span>
                        <span className="text-gray-400">{v.count} scan{v.count !== 1 ? 's' : ''}</span>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader><CardTitle>Score Trend (last 30 scans)</CardTitle></CardHeader>
            <CardContent>
              <TrendLine trend={data.scoreTrend} />
            </CardContent>
          </Card>
        </>
      )}
    </div>
  )
}
