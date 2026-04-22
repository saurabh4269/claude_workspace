import React from 'react'
import { ChevronDown, ChevronRight, Check, X as XIcon, Minus } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { ComplianceSummary, ComplianceRecord } from '@/lib/api'

function ScoreBar({ score, max = 10 }: { score: number; max?: number }) {
  const pct = Math.min((score / max) * 100, 100)
  const color = pct >= 70 ? 'bg-[#93cb52]' : pct >= 40 ? 'bg-[#6b7280]' : 'bg-[#dc2626]'
  return (
    <div className="flex items-center gap-2 min-w-[120px]">
      <div className="flex-1 h-1 bg-gray-100 rounded-full overflow-hidden">
        <div className={cn('h-full rounded-full', color)} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[13px] font-display font-bold text-[#464646] w-8 text-right shrink-0">
        {score.toFixed(1)}
      </span>
    </div>
  )
}

function TierBadge({ tier }: { tier: string }) {
  if (tier === 'required') return (
    <span className="inline-block rounded px-1.5 py-0.5 text-[11px] font-display font-bold bg-[#f2eeee] text-[#dc2626] uppercase tracking-wide">SHALL</span>
  )
  if (tier === 'additional') return (
    <span className="inline-block rounded px-1.5 py-0.5 text-[11px] font-display font-bold bg-[#f5f5f5] text-[#6b7280] uppercase tracking-wide">SHOULD</span>
  )
  return (
    <span className="inline-block rounded px-1.5 py-0.5 text-[11px] font-display font-bold bg-gray-50 text-gray-400 uppercase tracking-wide">MAY</span>
  )
}

function RecordIcon({ score, applicable }: { score: number; applicable: boolean }) {
  if (!applicable) return <Minus size={13} className="text-gray-300 shrink-0" />
  if (score >= 10) return <Check size={13} strokeWidth={2.5} className="text-[#93cb52] shrink-0" />
  if (score >= 5) return <Minus size={13} strokeWidth={2.5} className="text-[#6b7280] shrink-0" />
  return <XIcon size={13} strokeWidth={2.5} className="text-[#dc2626] shrink-0" />
}

function RecordsTable({ records }: { records: ComplianceRecord[] }) {
  const applicable = records.filter(r => r.applicable)
  const tiers = ['required', 'additional', 'optional'] as const
  return (
    <div className="mt-2 mb-4 border border-gray-100 rounded-lg overflow-hidden">
      {tiers.map(tier => {
        const group = applicable.filter(r => r.tier === tier)
        if (group.length === 0) return null
        const tierLabel = tier === 'required' ? 'SHALL' : tier === 'additional' ? 'SHOULD' : 'MAY'
        return (
          <div key={tier}>
            <div className="px-4 py-2 bg-gray-50 border-b border-gray-100">
              <span className="text-[11px] font-display font-bold text-gray-400 uppercase tracking-widest">{tierLabel}</span>
            </div>
            {group.map((r, i) => (
              <div
                key={`${r.checkKey}-${r.subjectId}-${i}`}
                className={cn(
                  'flex items-start gap-3 px-4 py-2.5 border-b border-gray-50 last:border-b-0',
                  i % 2 === 1 ? 'bg-gray-50/30' : 'bg-white',
                )}
              >
                <RecordIcon score={r.score} applicable={r.applicable} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-[13px] font-mono text-[#464646]">{r.checkKey}</span>
                    {r.subjectId && r.subjectId !== 'document' && (
                      <span className="text-[11px] text-gray-400 truncate max-w-[160px]" title={r.subjectId}>
                        {r.subjectId}
                      </span>
                    )}
                  </div>
                  {r.detail && (
                    <p className="text-[12px] text-gray-400 mt-0.5">{r.detail}</p>
                  )}
                </div>
                <span className={cn(
                  'text-[12px] font-display font-bold shrink-0',
                  r.score >= 10 ? 'text-[#93cb52]' : r.score >= 5 ? 'text-[#6b7280]' : 'text-[#dc2626]'
                )}>
                  {r.score.toFixed(0)}/10
                </span>
              </div>
            ))}
          </div>
        )
      })}
    </div>
  )
}

function StandardSection({
  name,
  score,
  pass,
  note,
  records,
  defaultOpen = false,
}: {
  name: string
  score: number
  pass: boolean
  note?: string
  records?: ComplianceRecord[]
  defaultOpen?: boolean
}) {
  const [open, setOpen] = React.useState(defaultOpen)
  const hasRecords = records && records.length > 0

  return (
    <div className="border border-gray-100 rounded-xl overflow-hidden mb-3">
      <button
        type="button"
        onClick={() => hasRecords && setOpen(o => !o)}
        className={cn(
          'w-full flex items-center gap-4 px-5 py-4 text-left',
          hasRecords ? 'hover:bg-gray-50/50 cursor-pointer' : 'cursor-default',
        )}
      >
        {hasRecords ? (
          open
            ? <ChevronDown size={15} className="text-gray-400 shrink-0" />
            : <ChevronRight size={15} className="text-gray-400 shrink-0" />
        ) : (
          <span className="w-[15px] shrink-0" />
        )}
        <span className="font-sans font-medium text-[15px] text-[#464646] flex-1">{name}</span>
        <div className="w-36 shrink-0">
          <ScoreBar score={score} />
        </div>
        <span className={cn(
          'text-sm font-display font-bold w-14 text-right shrink-0',
          pass ? 'text-[#93cb52]' : 'text-[#dc2626]',
        )}>
          {pass ? 'Pass' : 'Fail'}
        </span>
        {note && (
          <span className="text-[12px] text-gray-400 font-sans ml-2 shrink-0 hidden lg:block">{note}</span>
        )}
      </button>

      {open && hasRecords && (
        <div className="px-5 pb-1 border-t border-gray-100">
          <RecordsTable records={records!} />
        </div>
      )}
    </div>
  )
}

interface Props {
  compliance: ComplianceSummary
}

export function CompliancePanel({ compliance }: Props) {
  if (!compliance.ntia && !compliance.bsiV21 && !compliance.fsct && !compliance.oct) {
    return (
      <p className="text-[15px] text-gray-400 font-sans">
        No compliance data available for this scan.
      </p>
    )
  }

  return (
    <div>
      <p className="text-[12px] text-gray-400 font-sans mb-5">
        Click a standard to expand individual check results. SHALL = required · SHOULD = recommended · MAY = optional.
      </p>

      {compliance.ntia && (
        <StandardSection
          name={compliance.ntia.standard ?? 'NTIA Minimum Elements'}
          score={compliance.ntia.overallScore}
          pass={compliance.ntia.overallCompliant}
          note={`${compliance.ntia.elements?.filter(e => e.compliant).length ?? 0}/${compliance.ntia.elements?.length ?? 0} elements`}
          records={
            compliance.ntia.elements?.map(el => ({
              checkKey: el.elementName,
              tier: 'required' as const,
              score: el.compliant ? 10 : 0,
              applicable: true,
              subjectId: el.failingComponents?.length
                ? el.failingComponents.slice(0, 3).join(', ') + (el.failingComponents.length > 3 ? '…' : '')
                : 'document',
              foundValue: '',
              expected: '',
              detail: el.detail,
            })) ?? []
          }
          defaultOpen={false}
        />
      )}

      {compliance.bsiV21 && (
        <StandardSection
          name={compliance.bsiV21.standard ?? 'BSI TR-03183-2'}
          score={compliance.bsiV21.overallScore}
          pass={compliance.bsiV21.compliant}
          note={`SHALL: ${compliance.bsiV21.requiredPassed}/${compliance.bsiV21.requiredTotal} · SHOULD: ${compliance.bsiV21.additionalPassed}/${compliance.bsiV21.additionalTotal}`}
          records={compliance.bsiV21.records}
        />
      )}

      {compliance.fsct && (
        <StandardSection
          name={compliance.fsct.standard ?? 'FSCT v3'}
          score={compliance.fsct.overallScore}
          pass={compliance.fsct.overallScore >= 8.0}
          records={compliance.fsct.records}
        />
      )}

      {compliance.oct && (
        <StandardSection
          name={compliance.oct.standard ?? 'OpenChain Telco v1.1'}
          score={compliance.oct.overallScore}
          pass={compliance.oct.overallScore >= 8.0 && !compliance.oct.spdxOnlyFail}
          note={compliance.oct.spdxOnlyFail ? 'Requires SPDX format' : undefined}
          records={compliance.oct.records}
        />
      )}
    </div>
  )
}
