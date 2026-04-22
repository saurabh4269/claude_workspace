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
  AlertTriangle,
  ChevronLeft,
  GitBranch,
} from 'lucide-react'
import type { DependencyGraph } from '@/lib/api'
import { scans } from '@/lib/api'
import { RiskBadge } from '@/components/RiskBadge'
import { RiskChart } from '@/components/RiskChart'
import { ComponentTable } from '@/components/ComponentTable'
import { QualityScorePanel } from '@/components/QualityScorePanel'
import { CompliancePanel } from '@/components/CompliancePanel'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card'
import { Spinner } from '@/components/ui/Spinner'
import { formatDate } from '@/lib/utils'
import { cn } from '@/lib/utils'

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
  if (s === 'error')
    return <Badge variant="error">Error</Badge>
  if (s === 'warning')
    return <Badge variant="warning">Warning</Badge>
  if (s === 'info')
    return <Badge variant="info">Info</Badge>
  return <Badge variant="default">{severity}</Badge>
}

function StatCell({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-col items-center px-6 py-4 text-center">
      <p className="text-2xl font-display font-bold text-[#464646]">{value}</p>
      <p className="text-xs text-gray-400 font-sans mt-1">{label}</p>
    </div>
  )
}

function DependencyGraphPanel({ graph }: { graph: DependencyGraph }) {
  const orphanSet = new Set(graph.orphans)

  return (
    <div className="space-y-6">
      {/* Stats row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: 'Nodes', value: graph.nodes.length },
          { label: 'Edges', value: graph.edges.length },
          { label: 'Max Depth', value: graph.maxDepth },
          { label: 'Orphans', value: graph.orphans.length },
        ].map(({ label, value }) => (
          <Card key={label}>
            <div className="flex flex-col items-center py-4">
              <p className="text-2xl font-display font-bold text-[#464646]">{value}</p>
              <p className="text-xs text-gray-400 font-sans mt-1">{label}</p>
            </div>
          </Card>
        ))}
      </div>

      {/* Completeness banner */}
      <div
        className={cn(
          'rounded-xl px-5 py-3 flex items-center gap-2 text-sm font-sans',
          graph.isComplete
            ? 'bg-green-50 text-[#1c9770]'
            : 'bg-amber-50 text-amber-700',
        )}
      >
        {graph.isComplete ? (
          <CheckCircle size={16} />
        ) : (
          <AlertTriangle size={16} />
        )}
        {graph.isComplete
          ? 'Dependency graph is declared complete — all components are reachable.'
          : 'Dependency graph is incomplete or completeness not declared. Orphan components may exist.'}
      </div>

      {/* Orphans */}
      {graph.orphans.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-amber-600">
              <AlertTriangle size={16} />
              Orphan Components ({graph.orphans.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-gray-400 font-sans mb-3">
              These components are not reachable from the primary component via declared dependency
              relationships.
            </p>
            <div className="flex flex-wrap gap-2">
              {graph.orphans.map((id) => (
                <span
                  key={id}
                  className="px-2 py-1 rounded-md bg-amber-50 text-amber-700 text-xs font-mono border border-amber-200"
                >
                  {id}
                </span>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Edge table */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <GitBranch size={16} />
            Dependency Edges
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {graph.edges.length === 0 ? (
            <p className="text-sm text-gray-400 font-sans px-6 py-4">
              No dependency relationships declared in this SBOM.
            </p>
          ) : (
            <div className="overflow-x-auto max-h-[50vh]">
              <table className="min-w-full text-sm">
                <thead className="bg-gray-50 sticky top-0">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-display font-bold text-gray-500 uppercase tracking-wide">
                      From
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-display font-bold text-gray-500 uppercase tracking-wide">
                      Relationship
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-display font-bold text-gray-500 uppercase tracking-wide">
                      To
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {graph.edges.map((edge, idx) => {
                    const [from, to, rel] = edge
                    const fromOrphan = orphanSet.has(from)
                    const toOrphan = orphanSet.has(to)
                    return (
                      <tr
                        key={idx}
                        className="border-t border-[#e5e7eb] odd:bg-white even:bg-gray-50/50"
                      >
                        <td
                          className={cn(
                            'px-4 py-2 font-mono text-xs',
                            fromOrphan ? 'text-amber-600' : 'text-gray-600',
                          )}
                        >
                          {from}
                        </td>
                        <td className="px-4 py-2 text-xs text-[#1c9770] font-display font-bold">
                          {rel || '→'}
                        </td>
                        <td
                          className={cn(
                            'px-4 py-2 font-mono text-xs',
                            toOrphan ? 'text-amber-600' : 'text-gray-600',
                          )}
                        >
                          {to}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

const TAB_TRIGGER_CLASS = cn(
  'px-4 py-2 text-sm font-display font-bold text-gray-400 border-b-2 border-transparent transition-colors',
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
    } catch (err) {
      setExportError(err instanceof Error ? err.message : 'PDF export failed.')
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
    } catch (err) {
      setExportError(err instanceof Error ? err.message : 'JSON export failed.')
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
            {[...Array(4)].map((_, i) => (
              <div key={i} className="h-20 bg-gray-100 rounded-lg" />
            ))}
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
    .slice(0, 5)

  return (
    <div className="p-8 pb-24 space-y-6">
      {/* Back link */}
      <Link
        to="/history"
        className="inline-flex items-center gap-1.5 text-sm text-gray-400 hover:text-[#464646] font-sans transition-colors"
      >
        <ChevronLeft size={14} />
        Back to History
      </Link>

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <h1 className="font-display font-bold text-2xl text-[#464646] truncate">
            {data.filename}
          </h1>
          <div className="flex items-center gap-3 mt-2 flex-wrap">
            <Badge variant="info">{data.sbomFormat}</Badge>
            {data.formatVersion && (
              <span className="text-xs text-gray-400 font-sans">{data.formatVersion}</span>
            )}
            <span className="text-xs text-gray-400 font-sans">{formatDate(data.createdAt)}</span>
          </div>
        </div>
        <div className="flex flex-col items-end gap-2">
          <RiskBadge level={data.riskLevel} className="text-sm px-3 py-1" />
        </div>
      </div>

      {/* Stats row */}
      <Card>
        <div className="grid grid-cols-2 sm:grid-cols-5 divide-x divide-y sm:divide-y-0 divide-[#e5e7eb]">
          <StatCell label="Total Components" value={data.totalComponents} />
          <StatCell
            label="Vulnerable"
            value={
              <span className={data.vulnerableComponents > 0 ? 'text-[#dc2626]' : ''}>
                {data.vulnerableComponents}
              </span>
            }
          />
          <StatCell
            label="NTIA Compliant"
            value={
              data.ntiaCompliant ? (
                <CheckCircle size={24} className="text-[#93cb52] mx-auto" />
              ) : (
                <XCircle size={24} className="text-[#dc2626] mx-auto" />
              )
            }
          />
          <StatCell
            label="Invalid Components"
            value={
              <span className={data.invalidComponents > 0 ? 'text-[#f59e0b]' : ''}>
                {data.invalidComponents}
              </span>
            }
          />
          {data.qualityScore != null && (
            <StatCell
              label="Quality Score"
              value={
                <span className="flex items-center justify-center gap-1">
                  <span>{data.qualityScore.toFixed(1)}</span>
                  {data.qualityGrade && (
                    <Badge variant="info" className="text-xs">{data.qualityGrade}</Badge>
                  )}
                </span>
              }
            />
          )}
        </div>
      </Card>

      {/* Export bar */}
      {exportError && (
        <p className="text-xs text-[#dc2626] font-sans text-right">{exportError}</p>
      )}
      <div className="flex items-center justify-end gap-3">
        <Button
          variant="outline"
          size="sm"
          onClick={handleExportJson}
          disabled={exportingJson}
        >
          {exportingJson ? (
            <Spinner size={14} />
          ) : (
            <FileJson size={14} />
          )}
          Export JSON
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={handleExportPdf}
          disabled={exportingPdf}
        >
          {exportingPdf ? (
            <Spinner size={14} />
          ) : (
            <FileText size={14} />
          )}
          Export PDF
        </Button>
      </div>

      {/* Tabs */}
      <Tabs.Root defaultValue="overview">
        <Tabs.List className="flex border-b border-[#e5e7eb] mb-6 gap-0 flex-wrap">
          <Tabs.Trigger value="overview" className={TAB_TRIGGER_CLASS}>
            Overview
          </Tabs.Trigger>
          <Tabs.Trigger value="components" className={TAB_TRIGGER_CLASS}>
            Components ({data.totalComponents})
          </Tabs.Trigger>
          {data.quality && (
            <Tabs.Trigger value="quality" className={TAB_TRIGGER_CLASS}>
              Quality
            </Tabs.Trigger>
          )}
          {data.compliance && (
            <Tabs.Trigger value="compliance" className={TAB_TRIGGER_CLASS}>
              Compliance
            </Tabs.Trigger>
          )}
          {data.dependencyGraph && (
            <Tabs.Trigger value="dependencies" className={TAB_TRIGGER_CLASS}>
              Dependencies
            </Tabs.Trigger>
          )}
          <Tabs.Trigger value="issues" className={TAB_TRIGGER_CLASS}>
            Validation Issues ({data.validationIssues?.length ?? 0})
          </Tabs.Trigger>
          <Tabs.Trigger value="raw" className={TAB_TRIGGER_CLASS}>
            Raw JSON
          </Tabs.Trigger>
        </Tabs.List>

        {/* Overview tab */}
        <Tabs.Content value="overview">
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            {/* Donut chart */}
            <Card>
              <CardHeader>
                <CardTitle>Risk Distribution</CardTitle>
              </CardHeader>
              <CardContent>
                <RiskChart components={data.components ?? []} mode="donut" />
              </CardContent>
            </Card>

            {/* Top risk components */}
            <Card>
              <CardHeader>
                <CardTitle>Top Risk Components</CardTitle>
              </CardHeader>
              <CardContent>
                {topComponents.length === 0 ? (
                  <p className="text-sm text-gray-400 font-sans">No components found.</p>
                ) : (
                  <div className="divide-y divide-[#e5e7eb]">
                    {topComponents.map((comp) => (
                      <div key={comp.id} className="flex items-center gap-3 py-3">
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-sans font-medium text-[#464646] truncate">
                            {comp.name}
                          </p>
                          <p className="text-xs text-gray-400 font-sans">
                            {comp.version || 'no version'}
                          </p>
                        </div>
                        <RiskBadge level={comp.riskLevel} />
                        <span className="text-sm font-display font-bold text-[#464646] w-10 text-right">
                          {comp.riskScore.toFixed(1)}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* NTIA compliance card */}
            <Card className="xl:col-span-2">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  {data.ntiaCompliant ? (
                    <CheckCircle size={18} className="text-[#93cb52]" />
                  ) : (
                    <XCircle size={18} className="text-[#dc2626]" />
                  )}
                  NTIA Compliance
                </CardTitle>
              </CardHeader>
              <CardContent>
                {data.ntiaCompliant ? (
                  <div className="rounded-xl bg-green-50 px-5 py-4">
                    <p className="text-sm font-sans text-[#464646]">
                      This SBOM meets the NTIA minimum elements for Software Bill of Materials.
                    </p>
                  </div>
                ) : (
                  <div className="rounded-xl bg-[#f2eeee] px-5 py-4">
                    <p className="text-sm font-sans text-[#464646] mb-2">
                      This SBOM does not fully meet NTIA minimum elements. Review validation issues
                      for details on missing or non-conformant fields.
                    </p>
                    {data.invalidComponents > 0 && (
                      <p className="text-xs text-[#dc2626] font-sans">
                        {data.invalidComponents} component(s) are missing required fields.
                      </p>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </Tabs.Content>

        {/* Components tab */}
        <Tabs.Content value="components">
          <ComponentTable components={data.components ?? []} />
        </Tabs.Content>

        {/* Quality tab */}
        {data.quality && (
          <Tabs.Content value="quality">
            <QualityScorePanel quality={data.quality} />
          </Tabs.Content>
        )}

        {/* Compliance tab */}
        {data.compliance && (
          <Tabs.Content value="compliance">
            <CompliancePanel compliance={data.compliance} />
          </Tabs.Content>
        )}

        {/* Dependencies tab */}
        {data.dependencyGraph && (
          <Tabs.Content value="dependencies">
            <DependencyGraphPanel graph={data.dependencyGraph} />
          </Tabs.Content>
        )}

        {/* Validation Issues tab */}
        <Tabs.Content value="issues">
          {!data.validationIssues || data.validationIssues.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 gap-3 text-center">
              <CheckCircle size={40} className="text-[#93cb52]" />
              <p className="font-display font-bold text-lg text-[#464646]">
                No validation issues
              </p>
              <p className="text-sm text-gray-400 font-sans">
                This SBOM passed all validation checks.
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-[#e5e7eb]">
              <table className="min-w-full text-sm">
                <thead className="bg-gray-50">
                  <tr>
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
                  {data.validationIssues.map((issue, idx) => (
                    <tr
                      key={idx}
                      className="border-t border-[#e5e7eb] odd:bg-white even:bg-gray-50/50"
                    >
                      <td className="px-4 py-3">
                        <IssueSeverityBadge severity={issue.severity} />
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-gray-500">
                        {issue.code}
                      </td>
                      <td className="px-4 py-3 text-sm font-sans text-[#464646] max-w-sm">
                        {issue.message}
                      </td>
                      <td className="px-4 py-3 text-sm font-sans text-gray-400">
                        {issue.componentName || (
                          <span className="text-gray-300">N/A</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Tabs.Content>

        {/* Raw JSON tab */}
        <Tabs.Content value="raw">
          <div className="rounded-xl bg-[#1a1a2e] border border-[#2a2a3e] overflow-hidden">
            <div className="flex items-center justify-between px-4 py-2 border-b border-[#2a2a3e]">
              <span className="text-xs font-mono text-gray-400">scan.json</span>
              <button
                type="button"
                onClick={() => {
                  navigator.clipboard
                    .writeText(JSON.stringify(data, null, 2))
                    .catch(() => undefined)
                }}
                className="text-xs text-gray-400 hover:text-white font-sans transition-colors flex items-center gap-1"
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
