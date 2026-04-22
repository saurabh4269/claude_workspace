import React from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import * as Tabs from '@radix-ui/react-tabs'
import { Download, ChevronLeft, ChevronRight, ChevronDown, Check, X as XIcon, Minus } from 'lucide-react'
import { scans } from '@/lib/api'
import { RiskBadge } from '@/components/RiskBadge'
import { ComponentTable } from '@/components/ComponentTable'
import { CompliancePanel } from '@/components/CompliancePanel'
import { Spinner } from '@/components/ui/Spinner'
import { formatDate } from '@/lib/utils'
import { cn } from '@/lib/utils'
import type { QualityScore, NTIAResult, FeatureResult } from '@/lib/api'

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
  if (grade === 'A' || grade === 'B') return 'text-[#93cb52]'
  if (grade === 'C' || grade === 'D') return 'text-[#6b7280]'
  return 'text-[#dc2626]'
}

function scoreBarColor(score: number): string {
  if (score >= 7) return 'bg-[#93cb52]'
  if (score >= 4) return 'bg-[#6b7280]'
  return 'bg-[#dc2626]'
}

function IssueSeverityText({ severity }: { severity: string }) {
  const s = severity?.toLowerCase()
  if (s === 'error') return <span className="text-[15px] font-display font-bold text-[#dc2626]">Error</span>
  if (s === 'warning') return <span className="text-[15px] font-display font-bold text-[#464646]">Warning</span>
  if (s === 'info') return <span className="text-[15px] font-display font-bold text-[#6b7280]">Info</span>
  return <span className="text-[15px] font-display font-bold text-gray-400">{severity}</span>
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2 mb-6">
      <span className="w-0.5 h-4 bg-[#1c9770] rounded-full" />
      <p className="text-xs font-display font-bold text-gray-400 uppercase tracking-widest">{children}</p>
    </div>
  )
}

function FeatureRow({ f }: { f: FeatureResult }) {
  if (!f.applicable) return null
  const pass = f.score >= 10
  const partial = f.score > 0 && f.score < 10
  return (
    <div className="flex items-start gap-2.5 py-2 border-b border-gray-50 last:border-b-0">
      {pass
        ? <Check size={12} strokeWidth={2.5} className="text-[#93cb52] mt-0.5 shrink-0" />
        : partial
          ? <Minus size={12} strokeWidth={2.5} className="text-[#6b7280] mt-0.5 shrink-0" />
          : <XIcon size={12} strokeWidth={2.5} className="text-[#dc2626] mt-0.5 shrink-0" />
      }
      <div className="flex-1 min-w-0">
        <span className="text-[12px] font-mono text-[#464646]">{f.key}</span>
        {f.detail && <p className="text-[11px] text-gray-400 mt-0.5">{f.detail}</p>}
      </div>
      <span className={cn(
        'text-[12px] font-display font-bold shrink-0',
        pass ? 'text-[#93cb52]' : partial ? 'text-[#6b7280]' : 'text-[#dc2626]'
      )}>
        {f.score.toFixed(1)}
      </span>
    </div>
  )
}

function CategoryRow({ cat }: { cat: { name: string; score: number; weight: number; features: FeatureResult[] } }) {
  const [open, setOpen] = React.useState(false)
  const pct = Math.min((cat.score / 10) * 100, 100)
  const applicableFeatures = cat.features.filter(f => f.applicable)
  return (
    <div className="border-b border-gray-100 last:border-b-0">
      <button
        type="button"
        onClick={() => applicableFeatures.length > 0 && setOpen(o => !o)}
        className={cn(
          'w-full py-3 flex items-center gap-3 text-left',
          applicableFeatures.length > 0 ? 'cursor-pointer' : 'cursor-default',
        )}
      >
        {applicableFeatures.length > 0
          ? open
            ? <ChevronDown size={13} className="text-gray-400 shrink-0" />
            : <ChevronRight size={13} className="text-gray-400 shrink-0" />
          : <span className="w-[13px] shrink-0" />
        }
        <span className="text-[15px] font-sans text-[#464646] flex-1 text-left">{cat.name}</span>
        <div className="w-28 shrink-0">
          <div className="h-1 bg-gray-100 rounded-full">
            <div
              className={cn('h-1 rounded-full', scoreBarColor(cat.score))}
              style={{ width: `${pct}%` }}
            />
          </div>
        </div>
        <span className="text-[15px] font-display font-bold text-[#464646] w-8 text-right shrink-0">
          {cat.score.toFixed(1)}
        </span>
      </button>
      {open && applicableFeatures.length > 0 && (
        <div className="ml-5 mb-2 pl-3 border-l border-gray-100">
          {applicableFeatures.map(f => <FeatureRow key={f.key} f={f} />)}
        </div>
      )}
    </div>
  )
}

function QualityBreakdown({ quality }: { quality: QualityScore }) {
  const { grade, overallScore, categories } = quality
  return (
    <div>
      <SectionLabel>Quality Score</SectionLabel>
      <div className="flex items-end gap-4 mb-8">
        <span className={cn('text-6xl font-display font-bold leading-none', gradeColor(grade))}>
          {grade}
        </span>
        <div className="pb-1">
          <span className="text-2xl font-display font-bold text-[#464646]">{overallScore.toFixed(1)}</span>
          <span className="text-base text-gray-400 font-sans"> / 10</span>
        </div>
      </div>
      <p className="text-[12px] text-gray-400 font-sans mb-4">Click a category to expand individual feature checks.</p>
      <div>
        {categories.map((cat) => (
          <CategoryRow key={cat.name} cat={cat} />
        ))}
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
    <div>
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-2">
          <span className="w-0.5 h-4 bg-[#1c9770] rounded-full" />
          <p className="text-xs font-display font-bold text-gray-400 uppercase tracking-widest">
            NTIA Minimum Elements
          </p>
        </div>
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
              {el.compliant
                ? <Check size={14} strokeWidth={2.5} className="text-[#93cb52] mt-0.5 shrink-0" />
                : <XIcon size={14} strokeWidth={2.5} className="text-[#dc2626] mt-0.5 shrink-0" />
              }
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
      {components.map((comp: any) => {
        const vulnCount = comp.vulnerabilities?.length ?? 0
        return (
          <div key={comp.id} className="flex items-center gap-4 py-3.5 border-b border-gray-100 last:border-b-0">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1.5">
                <p className="text-[15px] font-sans font-medium text-[#464646] truncate">{comp.name}</p>
                {vulnCount > 0 && (
                  <span className="inline-flex items-center shrink-0 rounded-full px-1.5 py-0.5 text-xs font-semibold bg-[#f2eeee] text-[#dc2626]">
                    {vulnCount} CVE{vulnCount !== 1 ? 's' : ''}
                  </span>
                )}
              </div>
              <div className="h-1 bg-gray-100 rounded-full">
                <div
                  className={cn('h-1 rounded-full transition-all', scoreBarColor(comp.riskScore))}
                  style={{ width: `${Math.min(comp.riskScore, 100)}%` }}
                />
              </div>
            </div>
            <span className="text-xs font-mono text-gray-400 shrink-0">{comp.version || 'N/A'}</span>
            <RiskBadge level={comp.riskLevel} />
          </div>
        )
      })}
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
        <div className="grid grid-cols-4 gap-0 border border-gray-100 rounded-xl my-6">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="px-8 py-6">
              <div className="h-8 w-16 bg-gray-100 rounded mb-2" />
              <div className="h-3 w-24 bg-gray-100 rounded" />
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
  const formatLabel = [data.sbomFormat, data.formatVersion].filter(Boolean).join(' ')

  return (
    <div className="p-10 pb-24">
      {/* Back link */}
      <Link
        to="/history"
        className="inline-flex items-center gap-1.5 text-sm text-gray-400 hover:text-[#464646] font-sans transition-colors mb-6"
      >
        <ChevronLeft size={14} />
        Back to History
      </Link>

      {/* Header row */}
      <div className="flex items-start justify-between gap-6 mb-8">
        <div className="min-w-0">
          <h1 className="font-display font-bold text-2xl text-[#464646] truncate leading-tight">
            {data.filename}
          </h1>
          <div className="flex items-center gap-2 mt-2 flex-wrap">
            {formatLabel && (
              <span className="text-sm font-sans text-gray-400">{formatLabel}</span>
            )}
            {formatLabel && (
              <span className="text-gray-200 select-none">·</span>
            )}
            <span className="text-sm font-sans text-gray-400">{formatDate(data.createdAt)}</span>
          </div>
        </div>

        {/* Export buttons */}
        <div className="flex items-center gap-2 shrink-0 pt-1">
          {exportError && (
            <span className="text-sm text-[#dc2626] font-sans mr-2">{exportError}</span>
          )}
          <button
            type="button"
            onClick={handleExportJson}
            disabled={exportingJson}
            className="flex items-center gap-1.5 text-sm font-sans text-[#464646] border border-gray-200 rounded-lg px-3 py-1.5 hover:border-gray-300 hover:bg-gray-50 transition-colors disabled:opacity-50"
          >
            {exportingJson ? <Spinner size={13} /> : <Download size={13} />}
            JSON
          </button>
          <button
            type="button"
            onClick={handleExportPdf}
            disabled={exportingPdf}
            className="flex items-center gap-1.5 text-sm font-sans text-[#464646] border border-gray-200 rounded-lg px-3 py-1.5 hover:border-gray-300 hover:bg-gray-50 transition-colors disabled:opacity-50"
          >
            {exportingPdf ? <Spinner size={13} /> : <Download size={13} />}
            PDF
          </button>
        </div>
      </div>

      {/* Stats strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 border border-gray-100 rounded-xl divide-x divide-y sm:divide-y-0 divide-gray-100 mb-10">
        <div className="px-8 py-6">
          <p className="text-3xl font-display font-bold text-[#1c9770]">{data.totalComponents}</p>
          <p className="text-xs font-display font-bold text-gray-400 uppercase tracking-widest mt-1">
            Total Components
          </p>
        </div>

        <div className="px-8 py-6">
          <p className={cn('text-3xl font-display font-bold', data.vulnerableComponents > 0 ? 'text-[#dc2626]' : 'text-[#464646]')}>
            {data.vulnerableComponents}
          </p>
          <p className="text-xs font-display font-bold text-gray-400 uppercase tracking-widest mt-1">
            Vulnerable
          </p>
        </div>

        <div className="px-8 py-6">
          {data.qualityScore != null ? (
            <>
              <div className="flex items-baseline gap-2">
                <span className={cn('text-3xl font-display font-bold', data.qualityGrade ? gradeColor(data.qualityGrade) : 'text-[#464646]')}>
                  {data.qualityGrade ?? 'N/A'}
                </span>
                <span className="text-base text-gray-400 font-sans">
                  {data.qualityScore.toFixed(1)}/10
                </span>
              </div>
            </>
          ) : (
            <p className="text-3xl font-display font-bold text-gray-300">N/A</p>
          )}
          <p className="text-xs font-display font-bold text-gray-400 uppercase tracking-widest mt-1">
            Quality
          </p>
        </div>

        <div className="px-8 py-6">
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
            Issues
            {issueCount > 0 && (
              <span className="ml-1.5 inline-flex items-center rounded-full px-1.5 py-0.5 text-xs font-sans font-semibold bg-[#f2eeee] text-[#dc2626]">
                {issueCount}
              </span>
            )}
          </Tabs.Trigger>
        </Tabs.List>

        {/* Overview tab */}
        <Tabs.Content value="overview" className="pt-8">
          {/* Quality + NTIA side by side */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 mb-12">
            {data.quality ? (
              <QualityBreakdown quality={data.quality} />
            ) : (
              <div>
                <SectionLabel>Quality Score</SectionLabel>
                <p className="text-[15px] font-sans text-gray-400">
                  Quality data is not available for this scan.
                </p>
              </div>
            )}

            <NTIAChecklist
              ntiaCompliant={data.ntiaCompliant}
              ntia={ntiaData}
              invalidComponents={data.invalidComponents}
            />
          </div>

          {/* Top risk components */}
          <div>
            <SectionLabel>Top Risk Components</SectionLabel>
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
            <div className="flex flex-col items-center justify-center py-16 gap-4 text-center">
              <div className="w-12 h-12 rounded-full bg-[#edfaf3] flex items-center justify-center">
                <Check size={22} strokeWidth={2.5} className="text-[#1c9770]" />
              </div>
              <div>
                <p className="font-display font-bold text-lg text-[#464646]">No validation issues</p>
                <p className="text-[15px] text-gray-400 font-sans mt-1">This SBOM passed all validation checks.</p>
              </div>
            </div>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-[#e5e7eb]">
              <table className="min-w-full">
                <thead className="bg-gray-50">
                  <tr className="border-b border-gray-100">
                    <th className="px-4 py-3 text-left text-xs font-display font-bold text-gray-500 uppercase tracking-wide">
                      Severity
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-display font-bold text-gray-500 uppercase tracking-wide">
                      Code
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-display font-bold text-gray-500 uppercase tracking-wide">
                      Message
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-display font-bold text-gray-500 uppercase tracking-wide">
                      Component
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {data.validationIssues!.map((issue, idx) => (
                    <tr
                      key={idx}
                      className={cn(
                        'border-b border-gray-100 last:border-b-0 hover:bg-gray-50/50',
                        idx % 2 === 1 ? 'bg-gray-50/30' : 'bg-white',
                      )}
                    >
                      <td className="px-4 py-4">
                        <IssueSeverityText severity={issue.severity} />
                      </td>
                      <td className="px-4 py-4 font-mono text-sm text-gray-400">{issue.code}</td>
                      <td className="px-4 py-4 text-[15px] font-sans text-[#464646] max-w-sm">{issue.message}</td>
                      <td className="px-4 py-4 text-[15px] font-sans text-gray-400">
                        {issue.componentName || <span className="text-gray-300">N/A</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Tabs.Content>

      </Tabs.Root>
    </div>
  )
}
