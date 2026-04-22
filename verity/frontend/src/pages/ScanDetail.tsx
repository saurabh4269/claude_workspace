import React from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import * as Tabs from '@radix-ui/react-tabs'
import { Download, ChevronLeft } from 'lucide-react'
import { scans } from '@/lib/api'
import { RiskBadge } from '@/components/RiskBadge'
import { ComponentTable } from '@/components/ComponentTable'
import { CompliancePanel } from '@/components/CompliancePanel'
import { Spinner } from '@/components/ui/Spinner'
import { formatDate } from '@/lib/utils'
import { cn } from '@/lib/utils'
import type { QualityScore, NTIAResult } from '@/lib/api'

function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

function gradeColor(grade: string): string {
  if (grade === 'A') return 'text-[#22c55e]'
  if (grade === 'B') return 'text-[#93cb52]'
  if (grade === 'C') return 'text-[#f59e0b]'
  if (grade === 'D') return 'text-[#f97316]'
  return 'text-[#dc2626]'
}

function scoreBarColor(score: number): string {
  if (score >= 8) return 'bg-[#22c55e]'
  if (score >= 6) return 'bg-[#93cb52]'
  if (score >= 4) return 'bg-[#f59e0b]'
  if (score >= 2) return 'bg-[#f97316]'
  return 'bg-[#dc2626]'
}

function IssueSeverityText({ severity }: { severity: string }) {
  const s = severity?.toLowerCase()
  if (s === 'error') return <span className="text-[15px] font-display font-bold text-[#dc2626]">Error</span>
  if (s === 'warning') return <span className="text-[15px] font-display font-bold text-[#f59e0b]">Warning</span>
  if (s === 'info') return <span className="text-[15px] font-display font-bold text-[#1c9770]">Info</span>
  return <span className="text-[15px] font-display font-bold text-gray-400">{severity}</span>
}

function QualityBreakdown({ quality }: { quality: QualityScore }) {
  const { grade, overallScore, categories } = quality
  return (
    <div className="mb-10">
      <p className="text-xs font-display font-bold text-gray-400 uppercase tracking-widest mb-6">
        Quality Score
      </p>
      <div className="flex items-end gap-4 mb-8">
        <span className={cn('text-6xl font-display font-bold leading-none', gradeColor(grade))}>
          {grade}
        </span>
        <div className="pb-1">
          <span className="text-2xl font-display font-bold text-[#464646]">{overallScore.toFixed(1)}</span>
          <span className="text-base text-gray-400 font-sans"> / 10</span>
        </div>
      </div>
      <div>
        {categories.map((cat) => {
          const pct = Math.min((cat.score / 10) * 100, 100)
          return (
            <div key={cat.name} className="py-3 border-b border-gray-100 last:border-b-0">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[15px] font-sans text-[#464646]">{cat.name}</span>
                <span className="text-[15px] font-display font-bold text-[#464646]">{cat.score.toFixed(1)}</span>
              </div>
              <div className="h-1 bg-gray-100 rounded-full">
                <div
                  className={cn('h-1 rounded-full', scoreBarColor(cat.score))}
                  style={{ width: `${pct}%` }}
                />
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function NTIAChecklist({
  ntiaCompliant,
  ntia,
  invalidComponents,
}: {
  ntiaCompliant: boolean
  ntia?: NTIAResult
  invalidComponents: number
}) {
  return (
    <div className="mt-10">
      <div className="flex items-center justify-between mb-6">
        <p className="text-xs font-display font-bold text-gray-400 uppercase tracking-widest">
          NTIA Minimum Elements
        </p>
        <span
          className={cn(
            'text-sm font-display font-bold',
            ntiaCompliant ? 'text-[#93cb52]' : 'text-[#dc2626]',
          )}
        >
          {ntiaCompliant ? 'Compliant' : 'Non-compliant'}
        </span>
      </div>

      {ntia?.elements ? (
        <div>
          {ntia.elements.map((el) => (
            <div
              key={el.elementName}
              className="flex items-start gap-4 py-3 border-b border-gray-100 last:border-b-0"
            >
              <span
                className={cn(
                  'text-sm font-bold mt-0.5 shrink-0',
                  el.compliant ? 'text-[#93cb52]' : 'text-[#dc2626]',
                )}
              >
                {el.compliant ? '✓' : '✗'}
              </span>
              <div className="flex-1 flex items-center justify-between gap-4">
                <span className="text-[15px] font-sans text-[#464646]">{el.elementName}</span>
                {el.detail && (
                  <span className="text-sm font-sans text-gray-400 text-right max-w-xs shrink-0">
                    {el.detail}
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      ) : ntiaCompliant ? (
        <p className="text-[15px] font-sans text-[#464646]">
          All NTIA minimum elements are present.
        </p>
      ) : (
        <div className="text-[15px] font-sans text-[#464646] space-y-2">
          <p>Missing required fields. Check the Validation Issues tab for details.</p>
          {invalidComponents > 0 && (
            <p className="text-sm text-[#dc2626]">
              {invalidComponents} component{invalidComponents !== 1 ? 's' : ''} missing required fields.
            </p>
          )}
        </div>
      )}
    </div>
  )
}

function TopComponentsList({ components }: { components: any[] }) {
  if (components.length === 0) {
    return <p className="text-[15px] text-gray-400 font-sans">No components found.</p>
  }
  return (
    <div>
      {components.map((comp: any) => (
        <div key={comp.id} className="flex items-center gap-4 py-3 border-b border-gray-100 last:border-b-0">
          <div className="flex-1 min-w-0">
            <p className="text-[15px] font-sans font-medium text-[#464646] truncate">{comp.name}</p>
          </div>
          <span className="text-sm font-mono text-gray-400 shrink-0">{comp.version || 'no version'}</span>
          <RiskBadge level={comp.riskLevel} />
          <span className="text-sm font-mono text-gray-400 w-8 text-right shrink-0">
            {comp.riskScore.toFixed(0)}
          </span>
        </div>
      ))}
    </div>
  )
}

const TAB_TRIGGER_CLASS =
  'px-0 mr-8 py-3 text-[15px] font-display font-bold border-b-2 border-transparent transition-colors whitespace-nowrap data-[state=active]:border-[#1c9770] data-[state=active]:text-[#1c9770] text-gray-400 hover:text-[#464646]'

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>()
  const [exportingPdf, setExportingPdf] = React.useState(false)
  const [exportingJson, setExportingJson] = React.useState(false)
  const [exportError, setExportError] = React.useState<string | null>(null)

  const { data, isLoading, isError } = useQuery({
    queryKey: ['scan', id],
    queryFn: () => scans.get(id!),
    enabled: Boolean(id),
  })

  const handleExportPdf = async () => {
    if (!id) return
    setExportingPdf(true)
    setExportError(null)
    try {
      const blob = await scans.exportPdf(id)
      triggerDownload(blob, `verity-scan-${id}.pdf`)
    } catch {
      setExportError('PDF export failed.')
    } finally {
      setExportingPdf(false)
    }
  }

  const handleExportJson = async () => {
    if (!id) return
    setExportingJson(true)
    setExportError(null)
    try {
      const blob = await scans.exportJson(id)
      triggerDownload(blob, `verity-scan-${id}.json`)
    } catch {
      setExportError('JSON export failed.')
    } finally {
      setExportingJson(false)
    }
  }

  if (isLoading) {
    return (
      <div className="p-10 space-y-6 animate-pulse">
        <div className="h-4 w-24 bg-gray-100 rounded" />
        <div className="h-8 w-64 bg-gray-100 rounded" />
        <div className="h-4 w-48 bg-gray-100 rounded" />
        <div className="grid grid-cols-4 gap-0 border-y border-gray-100 my-6">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="px-0 py-6 text-center">
              <div className="h-8 w-16 bg-gray-100 rounded mx-auto mb-2" />
              <div className="h-3 w-24 bg-gray-100 rounded mx-auto" />
            </div>
          ))}
        </div>
        <div className="h-64 bg-gray-100 rounded" />
      </div>
    )
  }

  if (isError || !data) {
    return (
      <div className="p-10">
        <Link
          to="/history"
          className="inline-flex items-center gap-1.5 text-sm text-gray-400 hover:text-[#464646] font-sans mb-6"
        >
          <ChevronLeft size={14} />
          Back to History
        </Link>
        <div className="bg-[#f2eeee] px-6 py-5 rounded-lg text-[#dc2626] font-sans text-[15px]">
          Failed to load scan details. The scan may have been deleted or does not exist.
        </div>
      </div>
    )
  }

  const topComponents = [...(data.components ?? [])]
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 6)

  const ntiaData = data.compliance?.ntia
  const issueCount = data.validationIssues?.length ?? 0

  return (
    <div className="p-10 pb-24">
      {/* Back link */}
      <Link
        to="/history"
        className="inline-flex items-center gap-1.5 text-sm text-gray-400 hover:text-[#464646] font-sans transition-colors mb-4"
      >
        <ChevronLeft size={14} />
        Back to History
      </Link>

      {/* Header row */}
      <div className="flex items-start justify-between gap-6">
        <div className="min-w-0">
          <h1 className="font-display font-bold text-2xl text-[#464646] truncate leading-tight">
            {data.filename}
          </h1>
          <div className="flex items-center gap-3 mt-2 flex-wrap">
            <span className="text-sm font-sans text-gray-400">{data.sbomFormat}</span>
            {data.formatVersion && (
              <span className="text-sm font-sans text-gray-400">{data.formatVersion}</span>
            )}
            <span className="text-sm font-sans text-gray-400">{formatDate(data.createdAt)}</span>
          </div>
        </div>

        {/* Export text links */}
        <div className="flex items-center gap-5 shrink-0 pt-1">
          {exportError && (
            <span className="text-sm text-[#dc2626] font-sans">{exportError}</span>
          )}
          <button
            type="button"
            onClick={handleExportJson}
            disabled={exportingJson}
            className="flex items-center gap-1.5 text-sm font-sans text-gray-400 hover:text-[#464646] transition-colors disabled:opacity-50"
          >
            {exportingJson ? <Spinner size={13} /> : null}
            Export JSON
          </button>
          <button
            type="button"
            onClick={handleExportPdf}
            disabled={exportingPdf}
            className="flex items-center gap-1.5 text-sm font-sans text-gray-400 hover:text-[#464646] transition-colors disabled:opacity-50"
          >
            {exportingPdf ? <Spinner size={13} /> : null}
            Export PDF
          </button>
        </div>
      </div>

      {/* Stats strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 border-y border-gray-100 my-8">
        {/* Total Components */}
        <div className="py-6 pr-8">
          <p className="text-3xl font-display font-bold text-[#464646]">{data.totalComponents}</p>
          <p className="text-xs font-display font-bold text-gray-400 uppercase tracking-widest mt-1">
            Total Components
          </p>
        </div>

        {/* Vulnerable */}
        <div className="py-6 pr-8 pl-8 border-l border-gray-100">
          <p className={cn('text-3xl font-display font-bold', data.vulnerableComponents > 0 ? 'text-[#dc2626]' : 'text-[#464646]')}>
            {data.vulnerableComponents}
          </p>
          <p className="text-xs font-display font-bold text-gray-400 uppercase tracking-widest mt-1">
            Vulnerable
          </p>
        </div>

        {/* Quality */}
        <div className="py-6 pr-8 pl-8 border-l border-gray-100">
          {data.qualityScore != null ? (
            <>
              <div className="flex items-baseline gap-2">
                <span className={cn('text-3xl font-display font-bold', data.qualityGrade ? gradeColor(data.qualityGrade) : 'text-[#464646]')}>
                  {data.qualityGrade ?? '—'}
                </span>
                <span className="text-base text-gray-400 font-sans">
                  {data.qualityScore.toFixed(1)}/10
                </span>
              </div>
            </>
          ) : (
            <p className="text-3xl font-display font-bold text-gray-300">—</p>
          )}
          <p className="text-xs font-display font-bold text-gray-400 uppercase tracking-widest mt-1">
            Quality
          </p>
        </div>

        {/* Risk */}
        <div className="py-6 pl-8 border-l border-gray-100">
          <RiskBadge level={data.riskLevel} className="text-3xl" />
          <p className="text-xs font-display font-bold text-gray-400 uppercase tracking-widest mt-1">
            Risk Level
          </p>
        </div>
      </div>

      {/* Tabs */}
      <Tabs.Root defaultValue="overview">
        <Tabs.List className="flex border-b border-gray-100 overflow-x-auto">
          <Tabs.Trigger value="overview" className={TAB_TRIGGER_CLASS}>
            Overview
          </Tabs.Trigger>
          <Tabs.Trigger value="components" className={TAB_TRIGGER_CLASS}>
            Components ({data.totalComponents})
          </Tabs.Trigger>
          {data.compliance && (
            <Tabs.Trigger value="compliance" className={TAB_TRIGGER_CLASS}>
              Compliance
            </Tabs.Trigger>
          )}
          <Tabs.Trigger value="issues" className={TAB_TRIGGER_CLASS}>
            Issues {issueCount > 0 && `(${issueCount})`}
          </Tabs.Trigger>
          <Tabs.Trigger value="raw" className={TAB_TRIGGER_CLASS}>
            Raw JSON
          </Tabs.Trigger>
        </Tabs.List>

        {/* Overview tab */}
        <Tabs.Content value="overview" className="pt-8">
          {/* Quality */}
          {data.quality ? (
            <QualityBreakdown quality={data.quality} />
          ) : (
            <div className="mb-10">
              <p className="text-xs font-display font-bold text-gray-400 uppercase tracking-widest mb-4">
                Quality Score
              </p>
              <p className="text-[15px] font-sans text-gray-400">
                Quality data is not available for this scan.
              </p>
            </div>
          )}

          {/* NTIA */}
          <NTIAChecklist
            ntiaCompliant={data.ntiaCompliant}
            ntia={ntiaData}
            invalidComponents={data.invalidComponents}
          />

          {/* Top risk components */}
          <div className="mt-10">
            <p className="text-xs font-display font-bold text-gray-400 uppercase tracking-widest mb-6">
              Top Risk Components
            </p>
            <TopComponentsList components={topComponents} />
          </div>
        </Tabs.Content>

        {/* Components tab */}
        <Tabs.Content value="components" className="pt-6">
          <ComponentTable components={data.components ?? []} />
        </Tabs.Content>

        {/* Compliance tab */}
        {data.compliance && (
          <Tabs.Content value="compliance" className="pt-8">
            <CompliancePanel compliance={data.compliance} />
          </Tabs.Content>
        )}

        {/* Validation Issues tab */}
        <Tabs.Content value="issues" className="pt-8">
          {issueCount === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 gap-3 text-center">
              <p className="font-display font-bold text-lg text-[#93cb52]">✓ No validation issues</p>
              <p className="text-[15px] text-gray-400 font-sans">This SBOM passed all validation checks.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full">
                <thead>
                  <tr className="border-b border-gray-100">
                    <th className="pb-3 text-left text-xs font-display font-bold text-gray-400 uppercase tracking-widest pr-8">
                      Severity
                    </th>
                    <th className="pb-3 text-left text-xs font-display font-bold text-gray-400 uppercase tracking-widest pr-8">
                      Code
                    </th>
                    <th className="pb-3 text-left text-xs font-display font-bold text-gray-400 uppercase tracking-widest pr-8">
                      Message
                    </th>
                    <th className="pb-3 text-left text-xs font-display font-bold text-gray-400 uppercase tracking-widest">
                      Component
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {data.validationIssues!.map((issue, idx) => (
                    <tr key={idx} className="border-b border-gray-100 hover:bg-gray-50/50">
                      <td className="py-4 pr-8">
                        <IssueSeverityText severity={issue.severity} />
                      </td>
                      <td className="py-4 pr-8 font-mono text-sm text-gray-400">{issue.code}</td>
                      <td className="py-4 pr-8 text-[15px] font-sans text-[#464646] max-w-sm">{issue.message}</td>
                      <td className="py-4 text-[15px] font-sans text-gray-400">
                        {issue.componentName || <span className="text-gray-300">N/A</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Tabs.Content>

        {/* Raw JSON tab */}
        <Tabs.Content value="raw" className="pt-8">
          <div className="rounded-xl bg-[#1a1a2e] border border-[#2a2a3e] overflow-hidden">
            <div className="flex items-center justify-between px-4 py-2.5 border-b border-[#2a2a3e]">
              <span className="text-xs font-mono text-gray-500">scan.json</span>
              <button
                type="button"
                onClick={() => {
                  navigator.clipboard.writeText(JSON.stringify(data, null, 2)).catch(() => undefined)
                }}
                className="text-xs text-gray-400 hover:text-white font-sans transition-colors flex items-center gap-1.5"
              >
                <Download size={12} />
                Copy
              </button>
            </div>
            <pre className="overflow-auto max-h-[60vh] p-4 text-xs font-mono text-green-300 leading-relaxed whitespace-pre-wrap">
              {JSON.stringify(data, null, 2)}
            </pre>
          </div>
        </Tabs.Content>
      </Tabs.Root>
    </div>
  )
}
