import React from 'react'
import type { ComplianceSummary } from '@/lib/api'

function ScoreBar({ score }: { score: number }) {
  const pct = Math.min(score * 10, 100) // score is 0–10
  const color = pct >= 70 ? 'bg-[#93cb52]' : pct >= 40 ? 'bg-[#6b7280]' : 'bg-[#dc2626]'
  return (
    <div className="flex items-center gap-3 flex-1">
      <div className="flex-1 h-1 bg-gray-100 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[15px] font-display font-bold text-[#464646] w-8 text-right shrink-0">
        {score.toFixed(1)}
      </span>
    </div>
  )
}

interface StandardRow {
  name: string
  score: number
  pass: boolean
  note?: string
}

interface Props {
  compliance: ComplianceSummary
}

export function CompliancePanel({ compliance }: Props) {
  const rows: StandardRow[] = []

  if (compliance.ntia) {
    rows.push({
      name: compliance.ntia.standard,
      score: compliance.ntia.overallScore,
      pass: compliance.ntia.overallCompliant,
    })
  }

  if (compliance.bsiV21) {
    rows.push({
      name: compliance.bsiV21.standard,
      score: compliance.bsiV21.overallScore,
      pass: compliance.bsiV21.compliant,
      note: `Required: ${compliance.bsiV21.requiredPassed}/${compliance.bsiV21.requiredTotal} · Additional: ${compliance.bsiV21.additionalPassed}/${compliance.bsiV21.additionalTotal}`,
    })
  }

  if (compliance.fsct) {
    rows.push({
      name: compliance.fsct.standard,
      score: compliance.fsct.overallScore,
      pass: compliance.fsct.overallScore >= 8.0,
    })
  }

  if (compliance.oct) {
    rows.push({
      name: compliance.oct.standard,
      score: compliance.oct.overallScore,
      pass: compliance.oct.overallScore >= 8.0 && !compliance.oct.spdxOnlyFail,
      note: compliance.oct.spdxOnlyFail ? 'Requires SPDX format' : undefined,
    })
  }

  if (rows.length === 0) {
    return (
      <div>
        <p className="text-[15px] text-gray-400 font-sans">
          No compliance data available for this scan.
        </p>
      </div>
    )
  }

  return (
    <div>
      <div className="overflow-x-auto">
        <table className="min-w-full">
          <thead>
            <tr className="border-b border-gray-100">
              <th className="pb-3 text-left text-xs font-display font-bold text-gray-400 uppercase tracking-widest pr-8">
                Standard
              </th>
              <th className="pb-3 text-left text-xs font-display font-bold text-gray-400 uppercase tracking-widest pr-8 min-w-[200px]">
                Score
              </th>
              <th className="pb-3 text-left text-xs font-display font-bold text-gray-400 uppercase tracking-widest pr-8">
                Status
              </th>
              <th className="pb-3 text-left text-xs font-display font-bold text-gray-400 uppercase tracking-widest">
                Notes
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.name} className="border-b border-gray-100 hover:bg-gray-50/50">
                <td className="py-4 pr-8 font-sans font-medium text-[15px] text-[#464646] whitespace-nowrap">
                  {row.name}
                </td>
                <td className="py-4 pr-8">
                  <ScoreBar score={row.score} />
                </td>
                <td className="py-4 pr-8">
                  {row.pass ? (
                    <span className="text-sm font-display font-bold text-[#93cb52]">Pass</span>
                  ) : (
                    <span className="text-sm font-display font-bold text-[#dc2626]">Fail</span>
                  )}
                </td>
                <td className="py-4 text-sm text-gray-400 font-sans">
                  {row.note ? (
                    <span>{row.note}</span>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
