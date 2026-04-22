import React from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import * as Tabs from '@radix-ui/react-tabs'
import {
  Download,
  FileJson,
  FileText,
  CheckCircle,
  XCircle,
  ChevronLeft,
  Package,
  ShieldAlert,
  BarChart3,
  Star,
} from 'lucide-react'
import { scans } from '@/lib/api'
import { RiskBadge } from '@/components/RiskBadge'
import { ComponentTable } from '@/components/ComponentTable'
import { CompliancePanel } from '@/components/CompliancePanel'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card'
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

function IssueSeverityBadge({ severity }: { severity: string }) {
  const s = severity?.toLowerCase()
  if (s === 'error') return <Badge variant="error">Error</Badge>
  if (s === 'warning') return <Badge variant="warning">Warning</Badge>
  if (s === 'info') return <Badge variant="info">Info</Badge>
  return <Badge variant="default">{severity}</Badge>
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

/** Icon metric card for the summary strip */
function MetricCard({
  icon: Icon,
  label,
  value,
  iconBg = 'bg-[#edfaf3]',
  iconColor = 'text-[#1c9770]',
}: {
  icon: React.ElementType
  label: string
  value: React.ReactNode
  iconBg?: string
  iconColor?: string
}) {
  return (
    <div className="flex items-center gap-3 px-5 py-4">
      <div className={cn('flex h-9 w-9 items-center justify-center rounded-lg shrink-0', iconBg)}>
        <Icon size={17} className={iconColor} />
      </div>
      <div className="min-w-0">
        <div className="text-xl font-display font-bold text-[#464646] leading-tight">{value}</div>
        <p className="text-xs text-gray-400 font-sans mt-0.5">{label}</p>
      </div>
    </div>
  )
}

/** All quality categories as horizontal bars */
function QualityBreakdown({ quality }: { quality: QualityScore }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-3">
          <span className={cn('text-4xl font-display font-bold leading-none', gradeColor(quality.grade))}>
            {quality.grade}
          </span>
          <div>
            <span className="text-lg font-display font-bold text-[#464646]">
              {quality.overallScore.toFixed(1)}
              <span className="text-sm font-sans text-gray-400"> / 10</span>
            </span>
            <p className="text-xs text-gray-400 font-sans">Quality Score</p>
          </div>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {quality.categories.map((cat) => {
            const pct = Math.min((cat.score / 10) * 100, 100)
            return (
              <div key={cat.name}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-sans text-gray-600">{cat.name}</span>
                  <span className="text-xs font-mono text-gray-400">{cat.score.toFixed(1)}</span>
                </div>
                <div className="w-full h-1.5 bg-gray-100 rounded-full overflow-hidden">
                  <div
                    className={cn('h-full rounded-full transition-all', scoreBarColor(cat.score))}
                    style={{ width: `${pct}%` }}
                  />
                </div>
              </div>
            )
          })}
        </div>
      </CardContent>
    </Card>
  )
}

/** NTIA compliance as a checklist */
function NTIAChecklist({ ntiaCompliant, ntia, invalidComponents }: {
  ntiaCompliant: boolean
  ntia?: NTIAResult
  invalidComponents: number
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          {ntiaCompliant
            ? <CheckCircle size={16} className="text-[#93cb52]" />
            : <XCircle size={16} className="text-[#dc2626]" />}
          NTIA Minimum Elements
          <span className={cn(
            'ml-auto text-xs font-semibold px-2 py-0.5 rounded-full',
            ntiaCompliant ? 'bg-green-50 text-[#1c9770]' : 'bg-[#f2eeee] text-[#dc2626]'
          )}>
            {ntiaCompliant ? 'Compliant' : 'Non-compliant'}
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        {ntia?.elements ? (
          <div className="space-y-2">
            {ntia.elements.map((el) => (
              <div key={el.elementName} className="flex items-start gap-2">
                {el.compliant
                  ? <CheckCircle size={14} className="text-[#93cb52] mt-0.5 shrink-0" />
                  : <XCircle size={14} className="text-[#dc2626] mt-0.5 shrink-0" />}
                <div className="min-w-0">
                  <p className="text-xs font-medium text-[#464646]">{el.elementName}</p>
                  {el.detail && (
                    <p className="text-xs text-gray-400 mt-0.5">{el.detail}</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        ) : ntiaCompliant ? (
          <p className="text-sm font-sans text-[#464646]">
            All NTIA minimum elements are present.
          </p>
        ) : (
          <div className="space-y-2 text-sm font-sans text-[#464646]">
            <p>Missing required fields. Check the Validation Issues tab for details.</p>
            {invalidComponents > 0 && (
              <p className="text-xs text-[#dc2626]">
                {invalidComponents} component{invalidComponents !== 1 ? 's' : ''} missing required fields.
              </p>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

/** Top risky components list */
function TopComponentsList({ components }: { components: ReturnType<typeof Array.prototype.slice> }) {
  if (components.length === 0) {
    return <p className="text-sm text-gray-400 font-sans">No components found.</p>
  }
  return (
    <div className="divide-y divide-[#e5e7eb]">
      {components.map((comp: any) => (
        <div key={comp.id} className="flex items-center gap-3 py-3">
          <div className="flex-1 min-w-0">
            <p className="text-sm font-sans font-medium text-[#464646] truncate">{comp.name}</p>
            <p className="text-xs text-gray-400 font-sans font-mono">{comp.version || 'no version'}</p>
          </div>
          <RiskBadge level={comp.riskLevel} />
          <span className="text-sm font-mono text-gray-400 w-10 text-right shrink-0">
            {comp.riskScore.toFixed(0)}
          </span>
        </div>
      ))}
    </div>
  )
}

const TAB_TRIGGER_CLASS = cn(
  'px-4 py-2.5 text-sm font-display font-bold text-gray-400 border-b-2 border-transparent transition-colors whitespace-nowrap',
  'data-[state=active]:text-[#1c9770] data-[state=active]:border-[#1c9770]',
  'hover:text-[#464646]',
)

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
      <div className="p-8 space-y-6">
        <div className="animate-pulse space-y-4">
          <div className="h-8 w-64 bg-gray-100 rounded" />
          <div className="h-4 w-40 bg-gray-100 rounded" />
          <div className="grid grid-cols-4 gap-4">
            {[...Array(4)].map((_, i) => <div key={i} className="h-20 bg-gray-100 rounded-lg" />)}
          </div>
          <div className="h-64 bg-gray-100 rounded-lg" />
        </div>
      </div>
    )
  }

  if (isError || !data) {
    return (
      <div className="p-8">
        <Link
          to="/history"
          className="inline-flex items-center gap-1.5 text-sm text-gray-400 hover:text-[#464646] font-sans mb-6"
        >
          <ChevronLeft size={14} />
          Back to History
        </Link>
        <div className="rounded-xl bg-[#f2eeee] px-6 py-5 text-[#dc2626] font-sans text-sm">
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
    <div className="p-8 pb-24 space-y-5">
      {/* Back + header row */}
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <Link
            to="/history"
            className="inline-flex items-center gap-1.5 text-sm text-gray-400 hover:text-[#464646] font-sans transition-colors mb-2"
          >
            <ChevronLeft size={14} />
            Back to History
          </Link>
          <h1 className="font-display font-bold text-2xl text-[#464646] truncate leading-tight">
            {data.filename}
          </h1>
          <div className="flex items-center gap-2 mt-1.5 flex-wrap">
            <Badge variant="info">{data.sbomFormat}</Badge>
            {data.formatVersion && (
              <span className="text-xs text-gray-400 font-sans">{data.formatVersion}</span>
            )}
            <span className="text-xs text-gray-400 font-sans">{formatDate(data.createdAt)}</span>
          </div>
        </div>

        {/* Export buttons — integrated in header */}
        <div className="flex items-center gap-2 shrink-0 pt-7">
          {exportError && (
            <span className="text-xs text-[#dc2626] font-sans">{exportError}</span>
          )}
          <Button variant="outline" size="sm" onClick={handleExportJson} disabled={exportingJson}>
            {exportingJson ? <Spinner size={13} /> : <FileJson size={13} />}
            JSON
          </Button>
          <Button variant="outline" size="sm" onClick={handleExportPdf} disabled={exportingPdf}>
            {exportingPdf ? <Spinner size={13} /> : <FileText size={13} />}
            PDF
          </Button>
        </div>
      </div>

      {/* Metric strip */}
      <Card>
        <div className="grid grid-cols-2 sm:grid-cols-4 divide-x divide-y sm:divide-y-0 divide-[#e5e7eb]">
          <MetricCard
            icon={Package}
            label="Total Components"
            value={data.totalComponents}
          />
          <MetricCard
            icon={ShieldAlert}
            label="Vulnerable"
            value={
              <span className={data.vulnerableComponents > 0 ? 'text-[#dc2626]' : ''}>
                {data.vulnerableComponents}
              </span>
            }
            iconBg={data.vulnerableComponents > 0 ? 'bg-[#f2eeee]' : 'bg-gray-50'}
            iconColor={data.vulnerableComponents > 0 ? 'text-[#dc2626]' : 'text-gray-400'}
          />
          <MetricCard
            icon={BarChart3}
            label="Risk Level"
            value={<RiskBadge level={data.riskLevel} />}
          />
          <MetricCard
            icon={Star}
            label="Quality"
            value={
              data.qualityScore != null ? (
                <span className="flex items-center gap-1.5">
                  <span className={data.qualityGrade ? gradeColor(data.qualityGrade) : ''}>
                    {data.qualityGrade ?? '—'}
                  </span>
                  <span className="text-base text-gray-400 font-sans font-normal">
                    {data.qualityScore.toFixed(1)}/10
                  </span>
                </span>
              ) : (
                <span className="text-gray-300">—</span>
              )
            }
          />
        </div>
      </Card>

      {/* Tabs */}
      <Tabs.Root defaultValue="overview">
        <Tabs.List className="flex border-b border-[#e5e7eb] gap-0 overflow-x-auto">
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
        <Tabs.Content value="overview" className="pt-5">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            {/* Quality breakdown — all categories */}
            {data.quality ? (
              <QualityBreakdown quality={data.quality} />
            ) : (
              <Card>
                <CardContent className="py-8 text-center">
                  <p className="text-sm text-gray-400 font-sans">Quality data not available for this scan.</p>
                </CardContent>
              </Card>
            )}

            {/* NTIA checklist */}
            <NTIAChecklist
              ntiaCompliant={data.ntiaCompliant}
              ntia={ntiaData}
              invalidComponents={data.invalidComponents}
            />
          </div>

          {/* Top risky components */}
          <Card className="mt-5">
            <CardHeader>
              <CardTitle>Top Risk Components</CardTitle>
            </CardHeader>
            <CardContent>
              <TopComponentsList components={topComponents} />
            </CardContent>
          </Card>
        </Tabs.Content>

        {/* Components tab */}
        <Tabs.Content value="components" className="pt-5">
          <ComponentTable components={data.components ?? []} />
        </Tabs.Content>

        {/* Compliance tab */}
        {data.compliance && (
          <Tabs.Content value="compliance" className="pt-5">
            <CompliancePanel compliance={data.compliance} />
          </Tabs.Content>
        )}

        {/* Validation Issues tab */}
        <Tabs.Content value="issues" className="pt-5">
          {issueCount === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 gap-3 text-center">
              <CheckCircle size={40} className="text-[#93cb52]" />
              <p className="font-display font-bold text-lg text-[#464646]">No validation issues</p>
              <p className="text-sm text-gray-400 font-sans">This SBOM passed all validation checks.</p>
            </div>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-[#e5e7eb]">
              <table className="min-w-full text-sm">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-display font-bold text-gray-500 uppercase tracking-wide">Severity</th>
                    <th className="px-4 py-3 text-left text-xs font-display font-bold text-gray-500 uppercase tracking-wide">Code</th>
                    <th className="px-4 py-3 text-left text-xs font-display font-bold text-gray-500 uppercase tracking-wide">Message</th>
                    <th className="px-4 py-3 text-left text-xs font-display font-bold text-gray-500 uppercase tracking-wide">Component</th>
                  </tr>
                </thead>
                <tbody>
                  {data.validationIssues!.map((issue, idx) => (
                    <tr key={idx} className="border-t border-[#e5e7eb] odd:bg-white even:bg-gray-50/50">
                      <td className="px-4 py-3"><IssueSeverityBadge severity={issue.severity} /></td>
                      <td className="px-4 py-3 font-mono text-xs text-gray-500">{issue.code}</td>
                      <td className="px-4 py-3 text-sm font-sans text-[#464646] max-w-sm">{issue.message}</td>
                      <td className="px-4 py-3 text-sm font-sans text-gray-400">
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
        <Tabs.Content value="raw" className="pt-5">
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
