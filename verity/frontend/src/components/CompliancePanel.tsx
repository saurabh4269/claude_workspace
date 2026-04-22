import React from 'react'
import { CheckCircle, XCircle, AlertTriangle } from 'lucide-react'
import type { ComplianceSummary, NTIAResult, BSIResult, FSCTResult, OCTResult, ComplianceRecord } from '@/lib/api'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'

function ScoreBar({ score }: { score: number }) {
  const pct = Math.min(score * 100, 100)
  const color = pct >= 80 ? 'bg-[#22c55e]' : pct >= 50 ? 'bg-[#f59e0b]' : 'bg-[#dc2626]'
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-gray-100 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-mono text-gray-500 w-10 text-right">
        {(score * 100).toFixed(0)}%
      </span>
    </div>
  )
}

function RecordRow({ rec }: { rec: ComplianceRecord }) {
  const pass = rec.score >= 1.0
  return (
    <tr className="border-t border-[#e5e7eb] odd:bg-white even:bg-gray-50/50 text-xs font-sans">
      <td className="px-3 py-2">
        {pass
          ? <CheckCircle size={13} className="text-[#93cb52]" />
          : <XCircle size={13} className="text-[#dc2626]" />}
      </td>
      <td className="px-3 py-2 font-mono text-gray-500">{rec.checkKey}</td>
      <td className="px-3 py-2">
        <Badge variant={rec.tier === 'required' ? 'error' : rec.tier === 'additional' ? 'warning' : 'default'}>
          {rec.tier}
        </Badge>
      </td>
      <td className="px-3 py-2 text-[#464646] max-w-xs truncate">{rec.detail}</td>
    </tr>
  )
}

function RecordTable({ records }: { records: ComplianceRecord[] }) {
  if (!records?.length) return null
  return (
    <div className="mt-3 overflow-x-auto rounded-lg border border-[#e5e7eb]">
      <table className="min-w-full text-xs">
        <thead className="bg-gray-50">
          <tr>
            <th className="px-3 py-2 text-left text-gray-500 uppercase tracking-wide"></th>
            <th className="px-3 py-2 text-left text-gray-500 uppercase tracking-wide">Check</th>
            <th className="px-3 py-2 text-left text-gray-500 uppercase tracking-wide">Tier</th>
            <th className="px-3 py-2 text-left text-gray-500 uppercase tracking-wide">Detail</th>
          </tr>
        </thead>
        <tbody>
          {records.map((r, i) => <RecordRow key={i} rec={r} />)}
        </tbody>
      </table>
    </div>
  )
}

function NTIASection({ ntia }: { ntia: NTIAResult }) {
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3">
        {ntia.overallCompliant
          ? <CheckCircle size={18} className="text-[#93cb52]" />
          : <XCircle size={18} className="text-[#dc2626]" />}
        <span className="font-display font-bold text-[#464646]">{ntia.standard}</span>
        <ScoreBar score={ntia.overallScore} />
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        {ntia.elements?.map((el) => (
          <div key={el.elementName} className="flex items-start gap-2 text-xs font-sans">
            {el.compliant
              ? <CheckCircle size={12} className="text-[#93cb52] mt-0.5 shrink-0" />
              : <XCircle size={12} className="text-[#dc2626] mt-0.5 shrink-0" />}
            <div>
              <span className="font-medium text-[#464646]">{el.elementName}</span>
              {!el.compliant && el.failingComponents?.length > 0 && (
                <p className="text-gray-400 truncate">
                  Failing: {el.failingComponents.slice(0, 3).join(', ')}
                  {el.failingComponents.length > 3 && ` +${el.failingComponents.length - 3}`}
                </p>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function BSISection({ bsi }: { bsi: BSIResult }) {
  const [expanded, setExpanded] = React.useState(false)
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-3">
        {bsi.compliant
          ? <CheckCircle size={18} className="text-[#93cb52]" />
          : <XCircle size={18} className="text-[#dc2626]" />}
        <span className="font-display font-bold text-[#464646]">{bsi.standard}</span>
        <ScoreBar score={bsi.overallScore} />
      </div>
      <div className="text-xs text-gray-400 font-sans flex gap-4">
        <span>Required: {bsi.requiredPassed}/{bsi.requiredTotal}</span>
        <span>Additional: {bsi.additionalPassed}/{bsi.additionalTotal}</span>
      </div>
      <button
        type="button"
        className="text-xs text-[#1c9770] hover:underline font-sans"
        onClick={() => setExpanded((v) => !v)}
      >
        {expanded ? 'Hide records' : 'Show records'}
      </button>
      {expanded && <RecordTable records={bsi.records} />}
    </div>
  )
}

function FSCTSection({ fsct }: { fsct: FSCTResult }) {
  const [expanded, setExpanded] = React.useState(false)
  const pass = fsct.overallScore >= 0.8
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-3">
        {pass
          ? <CheckCircle size={18} className="text-[#93cb52]" />
          : <XCircle size={18} className="text-[#dc2626]" />}
        <span className="font-display font-bold text-[#464646]">{fsct.standard}</span>
        <ScoreBar score={fsct.overallScore} />
      </div>
      <button
        type="button"
        className="text-xs text-[#1c9770] hover:underline font-sans"
        onClick={() => setExpanded((v) => !v)}
      >
        {expanded ? 'Hide records' : 'Show records'}
      </button>
      {expanded && <RecordTable records={fsct.records} />}
    </div>
  )
}

function OCTSection({ oct }: { oct: OCTResult }) {
  const [expanded, setExpanded] = React.useState(false)
  const pass = oct.overallScore >= 0.8 && !oct.spdxOnlyFail
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-3">
        {pass
          ? <CheckCircle size={18} className="text-[#93cb52]" />
          : <XCircle size={18} className="text-[#dc2626]" />}
        <span className="font-display font-bold text-[#464646]">{oct.standard}</span>
        <ScoreBar score={oct.overallScore} />
      </div>
      {oct.spdxOnlyFail && (
        <div className="flex items-center gap-1.5 text-xs text-[#f59e0b] font-sans">
          <AlertTriangle size={12} />
          OpenChain Telco requires SPDX format — this SBOM uses a different format.
        </div>
      )}
      <button
        type="button"
        className="text-xs text-[#1c9770] hover:underline font-sans"
        onClick={() => setExpanded((v) => !v)}
      >
        {expanded ? 'Hide records' : 'Show records'}
      </button>
      {expanded && <RecordTable records={oct.records} />}
    </div>
  )
}

interface Props {
  compliance: ComplianceSummary
}

export function CompliancePanel({ compliance }: Props) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Compliance Standards</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="divide-y divide-[#e5e7eb] space-y-4">
          {compliance.ntia && (
            <div className="pt-4 first:pt-0">
              <NTIASection ntia={compliance.ntia} />
            </div>
          )}
          {compliance.bsiV21 && (
            <div className="pt-4">
              <BSISection bsi={compliance.bsiV21} />
            </div>
          )}
          {compliance.fsct && (
            <div className="pt-4">
              <FSCTSection fsct={compliance.fsct} />
            </div>
          )}
          {compliance.oct && (
            <div className="pt-4">
              <OCTSection oct={compliance.oct} />
            </div>
          )}
          {!compliance.ntia && !compliance.bsiV21 && !compliance.fsct && !compliance.oct && (
            <p className="text-sm text-gray-400 font-sans py-4">
              No compliance data available for this scan.
            </p>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
