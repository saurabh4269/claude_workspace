import React from 'react'
import { CheckCircle, XCircle, AlertTriangle } from 'lucide-react'
import type { ComplianceSummary } from '@/lib/api'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card'

function ScoreBar({ score }: { score: number }) {
  const pct = Math.min(score * 10, 100)  // score is 0–10
  const color = pct >= 80 ? 'bg-[#22c55e]' : pct >= 50 ? 'bg-[#f59e0b]' : 'bg-[#dc2626]'
  return (
    <div className="flex items-center gap-2 flex-1">
      <div className="flex-1 h-1.5 bg-gray-100 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-mono text-gray-500 w-10 text-right">
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
      note: compliance.oct.spdxOnlyFail
        ? 'Requires SPDX format'
        : undefined,
    })
  }

  if (rows.length === 0) {
    return (
      <Card>
        <CardContent className="py-6">
          <p className="text-sm text-gray-400 font-sans">
            No compliance data available for this scan.
          </p>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Compliance Standards</CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-5 py-3 text-left text-xs font-display font-bold text-gray-500 uppercase tracking-wide w-6"></th>
                <th className="px-5 py-3 text-left text-xs font-display font-bold text-gray-500 uppercase tracking-wide">
                  Standard
                </th>
                <th className="px-5 py-3 text-left text-xs font-display font-bold text-gray-500 uppercase tracking-wide min-w-[200px]">
                  Score
                </th>
                <th className="px-5 py-3 text-left text-xs font-display font-bold text-gray-500 uppercase tracking-wide">
                  Status
                </th>
                <th className="px-5 py-3 text-left text-xs font-display font-bold text-gray-500 uppercase tracking-wide">
                  Notes
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row, idx) => (
                <tr
                  key={row.name}
                  className={`border-t border-[#e5e7eb] ${idx % 2 === 0 ? 'bg-white' : 'bg-gray-50/50'}`}
                >
                  <td className="px-5 py-4">
                    {row.pass ? (
                      <CheckCircle size={16} className="text-[#93cb52]" />
                    ) : (
                      <XCircle size={16} className="text-[#dc2626]" />
                    )}
                  </td>
                  <td className="px-5 py-4 font-display font-bold text-sm text-[#464646] whitespace-nowrap">
                    {row.name}
                  </td>
                  <td className="px-5 py-4">
                    <ScoreBar score={row.score} />
                  </td>
                  <td className="px-5 py-4">
                    {row.pass ? (
                      <span className="inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold bg-green-50 text-[#1c9770]">
                        Pass
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold bg-[#f2eeee] text-[#dc2626]">
                        Fail
                      </span>
                    )}
                  </td>
                  <td className="px-5 py-4 text-xs text-gray-400 font-sans">
                    {row.note ? (
                      <span className="flex items-center gap-1">
                        {row.note.includes('Requires') && (
                          <AlertTriangle size={11} className="text-[#f59e0b] shrink-0" />
                        )}
                        {row.note}
                      </span>
                    ) : (
                      <span className="text-gray-300">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  )
}
