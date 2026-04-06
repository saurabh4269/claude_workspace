import React from 'react'
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Legend,
} from 'recharts'
import { type Component, type ScanSummary } from '@/lib/api'
import { formatDate, formatScore } from '@/lib/utils'

const RISK_COLORS: Record<string, string> = {
  LOW: '#93cb52',
  MEDIUM: '#f59e0b',
  HIGH: '#f97316',
  CRITICAL: '#dc2626',
}

const RISK_ORDER = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

interface RiskChartProps {
  components?: Component[]
  scans?: ScanSummary[]
  mode: 'donut' | 'trend'
}

interface CustomLabelProps {
  cx: number
  cy: number
  total: number
}

function CenterLabel({ cx, cy, total }: CustomLabelProps) {
  return (
    <g>
      <text
        x={cx}
        y={cy - 8}
        textAnchor="middle"
        dominantBaseline="central"
        className="font-display"
        style={{ fontFamily: 'DM Sans, sans-serif', fontWeight: 700, fontSize: 28, fill: '#464646' }}
      >
        {total}
      </text>
      <text
        x={cx}
        y={cy + 16}
        textAnchor="middle"
        dominantBaseline="central"
        style={{ fontFamily: 'Inter, sans-serif', fontSize: 12, fill: '#9ca3af' }}
      >
        components
      </text>
    </g>
  )
}

interface DonutTooltipProps {
  active?: boolean
  payload?: Array<{ name: string; value: number; payload: { color: string } }>
}

function DonutTooltip({ active, payload }: DonutTooltipProps) {
  if (!active || !payload?.length) return null
  const { name, value } = payload[0]
  const color = RISK_COLORS[name] ?? '#9ca3af'
  return (
    <div className="rounded-lg border border-[#e5e7eb] bg-white px-3 py-2 shadow-md text-sm font-sans">
      <span style={{ color }} className="font-semibold">{name}</span>
      <span className="ml-2 text-[#464646]">{value}</span>
    </div>
  )
}

interface TrendTooltipProps {
  active?: boolean
  payload?: Array<{ value: number; name: string }>
  label?: string
}

function TrendTooltip({ active, payload, label }: TrendTooltipProps) {
  if (!active || !payload?.length) return null
  return (
    <div className="rounded-lg border border-[#e5e7eb] bg-white px-3 py-2 shadow-md text-sm font-sans">
      <p className="font-semibold text-[#464646] mb-1">{label}</p>
      {payload.map((p) => (
        <p key={p.name} className="text-gray-500">
          Score: <span className="text-[#464646] font-semibold">{p.value}</span>
        </p>
      ))}
    </div>
  )
}

export function RiskChart({ components, scans, mode }: RiskChartProps) {
  if (mode === 'donut') {
    if (!components || components.length === 0) {
      return (
        <div className="flex items-center justify-center h-48 text-gray-400 text-sm font-sans">
          No component data available.
        </div>
      )
    }

    const counts: Record<string, number> = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 }
    for (const c of components) {
      const lvl = c.riskLevel?.toUpperCase()
      if (lvl && counts[lvl] !== undefined) {
        counts[lvl]++
      }
    }

    const donutData = RISK_ORDER.filter((k) => counts[k] > 0).map((k) => ({
      name: k,
      value: counts[k],
      color: RISK_COLORS[k],
    }))

    if (donutData.length === 0) {
      return (
        <div className="flex items-center justify-center h-48 text-gray-400 text-sm font-sans">
          No risk data to display.
        </div>
      )
    }

    const total = components.length

    return (
      <div className="flex flex-col items-center gap-4">
        <ResponsiveContainer width="100%" height={220}>
          <PieChart>
            <Pie
              data={donutData}
              cx="50%"
              cy="50%"
              innerRadius={70}
              outerRadius={100}
              paddingAngle={2}
              dataKey="value"
              startAngle={90}
              endAngle={-270}
            >
              {donutData.map((entry) => (
                <Cell key={entry.name} fill={entry.color} stroke="none" />
              ))}
            </Pie>
            <Tooltip content={<DonutTooltip />} />
            {/* Center label via custom label */}
          </PieChart>
        </ResponsiveContainer>

        {/* Manual center label overlay hack */}
        <div className="flex items-center justify-center gap-4 flex-wrap">
          {donutData.map((entry) => (
            <div key={entry.name} className="flex items-center gap-1.5">
              <div
                className="h-2.5 w-2.5 rounded-full"
                style={{ backgroundColor: entry.color }}
              />
              <span className="text-xs font-sans text-gray-500">
                {entry.name}{' '}
                <span className="font-semibold text-[#464646]">{entry.value}</span>
              </span>
            </div>
          ))}
        </div>

        <p className="text-xs text-gray-400 font-sans">{total} total components</p>
      </div>
    )
  }

  // Trend mode
  if (!scans || scans.length === 0) {
    return (
      <div className="flex items-center justify-center h-48 text-gray-400 text-sm font-sans">
        No scan history available.
      </div>
    )
  }

  const trendData = [...scans]
    .sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime())
    .map((s) => ({
      date: formatDate(s.createdAt),
      score: parseFloat(formatScore(s.riskScore)),
      name: s.filename,
    }))

  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart data={trendData} margin={{ top: 4, right: 8, left: -20, bottom: 4 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" vertical={false} />
        <XAxis
          dataKey="date"
          tick={{ fontSize: 11, fill: '#9ca3af', fontFamily: 'Inter, sans-serif' }}
          axisLine={false}
          tickLine={false}
        />
        <YAxis
          domain={[0, 100]}
          tick={{ fontSize: 11, fill: '#9ca3af', fontFamily: 'Inter, sans-serif' }}
          axisLine={false}
          tickLine={false}
        />
        <Tooltip content={<TrendTooltip />} cursor={{ fill: '#f9fafb' }} />
        <Bar dataKey="score" name="Risk Score" radius={[4, 4, 0, 0]}>
          {trendData.map((entry, index) => {
            let fill = '#93cb52'
            if (entry.score >= 75) fill = '#dc2626'
            else if (entry.score >= 50) fill = '#f97316'
            else if (entry.score >= 25) fill = '#f59e0b'
            return <Cell key={index} fill={fill} />
          })}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}
