import React, { useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import * as Dialog from '@radix-ui/react-dialog'
import * as Select from '@radix-ui/react-select'
import { ChevronDown, Check, ExternalLink, Trash2, X, AlertTriangle, GitCompare } from 'lucide-react'
import { scans, workspaces, type ScanSummary, type ScanDiff } from '@/lib/api'
import { RiskBadge } from '@/components/RiskBadge'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Spinner } from '@/components/ui/Spinner'
import { formatDate } from '@/lib/utils'
import { cn } from '@/lib/utils'

const RISK_LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
const PER_PAGE = 20

function DeleteDialog({
  scan,
  open,
  onOpenChange,
  onConfirm,
  loading,
}: {
  scan: ScanSummary | null
  open: boolean
  onOpenChange: (v: boolean) => void
  onConfirm: () => void
  loading: boolean
}) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/30 z-40 animate-in fade-in-0" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 -translate-x-1/2 -translate-y-1/2 w-full max-w-md rounded-2xl bg-white p-6 shadow-xl border border-[#e5e7eb] animate-in fade-in-0 zoom-in-95">
          <div className="flex items-start gap-4">
            <div className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-full bg-[#f2eeee]">
              <AlertTriangle size={18} className="text-[#dc2626]" />
            </div>
            <div className="flex-1">
              <Dialog.Title className="font-display font-bold text-lg text-[#464646]">
                Delete scan
              </Dialog.Title>
              <Dialog.Description className="mt-1 text-sm text-gray-400 font-sans">
                Are you sure you want to delete{' '}
                <span className="font-semibold text-[#464646]">{scan?.filename}</span>?
                This action cannot be undone.
              </Dialog.Description>
            </div>
          </div>
          <div className="mt-6 flex justify-end gap-3">
            <Dialog.Close asChild>
              <Button variant="ghost" size="sm" disabled={loading}>
                Cancel
              </Button>
            </Dialog.Close>
            <Button
              variant="destructive"
              size="sm"
              onClick={onConfirm}
              disabled={loading}
            >
              {loading ? <Spinner size={14} className="text-white" /> : <Trash2 size={14} />}
              Delete
            </Button>
          </div>
          <Dialog.Close asChild>
            <button
              className="absolute right-4 top-4 text-gray-400 hover:text-[#464646] transition-colors"
              aria-label="Close"
            >
              <X size={16} />
            </button>
          </Dialog.Close>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}

function DiffResultView({ diff }: { diff: ScanDiff }) {
  const delta = diff.scoreDelta
  const deltaColor = delta > 0 ? 'text-[#dc2626]' : delta < 0 ? 'text-[#93cb52]' : 'text-gray-400'
  const deltaText = delta > 0 ? `+${delta.toFixed(1)}` : delta.toFixed(1)

  const Section = ({ title, items, color }: { title: string; items: Record<string, unknown>[]; color: string }) => {
    if (!items.length) return null
    return (
      <div className="mb-4">
        <p className="text-xs font-display font-bold uppercase tracking-widest mb-2" style={{ color }}>{title} ({items.length})</p>
        <div className="border border-gray-100 rounded-lg overflow-hidden">
          {items.map((item, i) => {
            const name = String(item.name ?? item.component ?? '')
            const version = item.version != null ? String(item.version) : null
            const oldV = item.old != null ? String(item.old) : null
            const newV = item.new != null ? String(item.new) : null
            const id = item.id != null ? String(item.id) : null
            return (
              <div key={i} className="flex items-center gap-3 px-4 py-2 border-b border-gray-50 last:border-b-0 text-sm font-sans">
                <span className="font-medium text-[#464646]">{name}</span>
                {version && <span className="text-gray-400 font-mono text-xs">{version}</span>}
                {oldV && newV && (
                  <span className="text-gray-400 text-xs">
                    <span className="line-through">{oldV}</span>
                    {' → '}
                    <span className="font-semibold text-[#464646]">{newV}</span>
                  </span>
                )}
                {id && <span className="font-mono text-xs text-gray-400">{id}</span>}
              </div>
            )
          })}
        </div>
      </div>
    )
  }

  return (
    <div className="mt-4">
      <div className="flex items-center gap-4 mb-5 p-4 bg-gray-50 rounded-xl">
        <div>
          <p className="text-xs text-gray-400 font-sans mb-0.5">Risk Score Δ</p>
          <p className={cn('text-xl font-display font-bold', deltaColor)}>{deltaText}</p>
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-sans text-gray-400 truncate">{diff.filenameA}</p>
          <p className="text-xs text-gray-300 font-sans">vs</p>
          <p className="text-sm font-sans text-gray-400 truncate">{diff.filenameB}</p>
        </div>
      </div>
      <Section title="Added" items={diff.added} color="#1c9770" />
      <Section title="Removed" items={diff.removed} color="#dc2626" />
      <Section title="Version Changed" items={diff.versionChanged} color="#6b7280" />
      <Section title="New Vulnerabilities" items={diff.newVulnerabilities} color="#dc2626" />
      <Section title="Resolved Vulnerabilities" items={diff.resolvedVulnerabilities} color="#1c9770" />
      {!diff.added.length && !diff.removed.length && !diff.versionChanged.length &&
        !diff.newVulnerabilities.length && !diff.resolvedVulnerabilities.length && (
        <p className="text-sm text-gray-400 font-sans text-center py-4">No differences found between the two scans.</p>
      )}
    </div>
  )
}

function DiffDialog({
  open, onOpenChange, items,
}: {
  open: boolean
  onOpenChange: (v: boolean) => void
  items: ScanSummary[]
}) {
  const [idA, setIdA] = useState('')
  const [idB, setIdB] = useState('')
  const [diffResult, setDiffResult] = useState<ScanDiff | null>(null)
  const [comparing, setComparing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleCompare = async () => {
    if (!idA || !idB || idA === idB) return
    setComparing(true)
    setError(null)
    setDiffResult(null)
    try {
      const result = await scans.diff(idA, idB)
      setDiffResult(result)
    } catch {
      setError('Failed to compare scans.')
    } finally {
      setComparing(false)
    }
  }

  const handleOpenChange = (v: boolean) => {
    if (!v) { setIdA(''); setIdB(''); setDiffResult(null); setError(null) }
    onOpenChange(v)
  }

  const selectClass = "flex h-10 min-w-0 w-full items-center justify-between rounded-lg border border-gray-200 bg-white px-3 text-sm font-sans text-[#464646] focus:outline-none focus:ring-2 focus:ring-[#1c9770] data-[placeholder]:text-gray-400"
  const itemClass = "flex cursor-pointer items-center rounded-md px-3 py-2 text-sm font-sans text-[#464646] hover:bg-gray-50 focus:outline-none focus:bg-gray-50"

  const SelectScan = ({ value, onChange, exclude }: { value: string; onChange: (v: string) => void; exclude: string }) => (
    <Select.Root value={value} onValueChange={onChange}>
      <Select.Trigger className={selectClass}>
        <Select.Value placeholder="Select a scan…" />
        <Select.Icon><ChevronDown size={14} className="text-gray-400" /></Select.Icon>
      </Select.Trigger>
      <Select.Portal>
        <Select.Content className="z-50 overflow-hidden rounded-lg border border-[#e5e7eb] bg-white shadow-lg max-h-60 overflow-y-auto">
          <Select.Viewport className="p-1">
            {items.filter(s => s.id !== exclude).map(s => (
              <Select.Item key={s.id} value={s.id} className={itemClass}>
                <Select.ItemText>{s.filename}</Select.ItemText>
                <Select.ItemIndicator className="ml-auto"><Check size={13} className="text-[#1c9770]" /></Select.ItemIndicator>
              </Select.Item>
            ))}
          </Select.Viewport>
        </Select.Content>
      </Select.Portal>
    </Select.Root>
  )

  return (
    <Dialog.Root open={open} onOpenChange={handleOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/30 z-40 animate-in fade-in-0" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 -translate-x-1/2 -translate-y-1/2 w-full max-w-2xl max-h-[85vh] overflow-y-auto rounded-2xl bg-white p-6 shadow-xl border border-[#e5e7eb] animate-in fade-in-0 zoom-in-95">
          <div className="flex items-center gap-3 mb-5">
            <GitCompare size={18} className="text-[#1c9770]" />
            <Dialog.Title className="font-display font-bold text-lg text-[#464646]">Compare Scans</Dialog.Title>
          </div>
          <div className="grid grid-cols-2 gap-4 mb-4">
            <div>
              <label className="text-xs font-display font-bold text-gray-400 uppercase tracking-widest block mb-1.5">Scan A (baseline)</label>
              <SelectScan value={idA} onChange={setIdA} exclude={idB} />
            </div>
            <div>
              <label className="text-xs font-display font-bold text-gray-400 uppercase tracking-widest block mb-1.5">Scan B (comparison)</label>
              <SelectScan value={idB} onChange={setIdB} exclude={idA} />
            </div>
          </div>
          {error && <p className="text-sm text-[#dc2626] font-sans mb-3">{error}</p>}
          <Button onClick={handleCompare} disabled={!idA || !idB || idA === idB || comparing} className="w-full">
            {comparing ? <Spinner size={14} className="text-white" /> : <GitCompare size={14} />}
            Compare
          </Button>
          {diffResult && <DiffResultView diff={diffResult} />}
          <Dialog.Close asChild>
            <button className="absolute right-4 top-4 text-gray-400 hover:text-[#464646] transition-colors" aria-label="Close">
              <X size={16} />
            </button>
          </Dialog.Close>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}

export default function History() {
  const queryClient = useQueryClient()
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [riskLevel, setRiskLevel] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [workspaceId, setWorkspaceId] = useState('')
  const [deleteTarget, setDeleteTarget] = useState<ScanSummary | null>(null)
  const [diffOpen, setDiffOpen] = useState(false)

  const { data: workspaceList } = useQuery({
    queryKey: ['workspaces'],
    queryFn: () => workspaces.list(),
    retry: false,
  })

  const { data, isLoading, isError } = useQuery({
    queryKey: ['scans', { page, perPage: PER_PAGE, riskLevel, workspaceId }],
    queryFn: () =>
      scans.list({
        page,
        perPage: PER_PAGE,
        riskLevel: riskLevel || undefined,
        workspaceId: workspaceId || undefined,
      }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => scans.delete(id),
    onSuccess: () => {
      setDeleteTarget(null)
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
  })

  const handleClearFilters = useCallback(() => {
    setSearch('')
    setRiskLevel('')
    setDateFrom('')
    setDateTo('')
    setWorkspaceId('')
    setPage(1)
  }, [])

  // Client-side filter by search and date (server may not support these)
  const filteredItems = (data?.items ?? []).filter((s) => {
    if (search && !s.filename.toLowerCase().includes(search.toLowerCase())) return false
    if (dateFrom && new Date(s.createdAt) < new Date(dateFrom)) return false
    if (dateTo && new Date(s.createdAt) > new Date(dateTo + 'T23:59:59')) return false
    return true
  })

  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE))
  const hasFilters = search || riskLevel || dateFrom || dateTo || workspaceId

  const historyDisabled =
    isError &&
    // Check if it's a 501/disabled type error - in practice we just show banner if no data
    false

  return (
    <div className="p-10 space-y-8">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="font-display font-bold text-2xl text-[#464646]">History</h1>
          <p className="mt-1 text-[15px] text-gray-400 font-sans">
            Browse and manage all previous scans.
          </p>
        </div>
        {(data?.items?.length ?? 0) >= 2 && (
          <Button variant="ghost" size="sm" onClick={() => setDiffOpen(true)} className="shrink-0 mt-1">
            <GitCompare size={14} />
            Compare
          </Button>
        )}
      </div>

      {/* History disabled banner */}
      {historyDisabled && (
        <div className="rounded-xl border border-[#f59e0b] bg-amber-50 px-5 py-4">
          <p className="text-[15px] font-sans text-[#464646]">
            <span className="font-semibold text-[#f59e0b]">History is disabled.</span>{' '}
            Enable it in your configuration to track scans over time.
          </p>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap items-end gap-3">
        <div className="flex-1 min-w-[200px]">
          <label className="text-xs font-display font-bold text-gray-400 uppercase tracking-widest block mb-1.5">
            Search
          </label>
          <Input
            placeholder="Filter by filename..."
            value={search}
            onChange={(e) => {
              setSearch(e.target.value)
              setPage(1)
            }}
          />
        </div>

        {/* Risk level filter */}
        <div>
          <label className="text-xs font-display font-bold text-gray-400 uppercase tracking-widest block mb-1.5">
            Risk Level
          </label>
          <Select.Root
            value={riskLevel}
            onValueChange={(v) => {
              setRiskLevel(v === 'ALL' ? '' : v)
              setPage(1)
            }}
          >
            <Select.Trigger className="flex h-10 min-w-[140px] items-center justify-between rounded-lg border border-gray-200 bg-white px-3 text-[15px] font-sans text-[#464646] focus:outline-none focus:ring-2 focus:ring-[#1c9770] data-[placeholder]:text-gray-400">
              <Select.Value placeholder="All levels" />
              <Select.Icon>
                <ChevronDown size={14} className="text-gray-400" />
              </Select.Icon>
            </Select.Trigger>
            <Select.Portal>
              <Select.Content className="z-50 overflow-hidden rounded-lg border border-[#e5e7eb] bg-white shadow-lg">
                <Select.Viewport className="p-1">
                  <Select.Item
                    value="ALL"
                    className="flex cursor-pointer items-center rounded-md px-3 py-2 text-[15px] font-sans text-gray-400 hover:bg-gray-50 focus:outline-none focus:bg-gray-50"
                  >
                    <Select.ItemText>All levels</Select.ItemText>
                  </Select.Item>
                  {RISK_LEVELS.map((level) => (
                    <Select.Item
                      key={level}
                      value={level}
                      className="flex cursor-pointer items-center rounded-md px-3 py-2 text-[15px] font-sans text-[#464646] hover:bg-gray-50 focus:outline-none focus:bg-gray-50"
                    >
                      <Select.ItemText>{level}</Select.ItemText>
                      <Select.ItemIndicator className="ml-auto">
                        <Check size={14} className="text-[#1c9770]" />
                      </Select.ItemIndicator>
                    </Select.Item>
                  ))}
                </Select.Viewport>
              </Select.Content>
            </Select.Portal>
          </Select.Root>
        </div>

        {/* Date range */}
        <div>
          <label className="text-xs font-display font-bold text-gray-400 uppercase tracking-widest block mb-1.5">
            From
          </label>
          <Input
            type="date"
            value={dateFrom}
            onChange={(e) => {
              setDateFrom(e.target.value)
              setPage(1)
            }}
            className="w-36"
          />
        </div>
        <div>
          <label className="text-xs font-display font-bold text-gray-400 uppercase tracking-widest block mb-1.5">
            To
          </label>
          <Input
            type="date"
            value={dateTo}
            onChange={(e) => {
              setDateTo(e.target.value)
              setPage(1)
            }}
            className="w-36"
          />
        </div>

        {/* Workspace filter */}
        {workspaceList && workspaceList.length > 0 && (
          <div>
            <label className="text-xs font-display font-bold text-gray-400 uppercase tracking-widest block mb-1.5">
              Workspace
            </label>
            <Select.Root
              value={workspaceId}
              onValueChange={(v) => {
                setWorkspaceId(v === 'ALL' ? '' : v)
                setPage(1)
              }}
            >
              <Select.Trigger className="flex h-10 min-w-[150px] items-center justify-between rounded-lg border border-gray-200 bg-white px-3 text-[15px] font-sans text-[#464646] focus:outline-none focus:ring-2 focus:ring-[#1c9770] data-[placeholder]:text-gray-400">
                <Select.Value placeholder="All workspaces" />
                <Select.Icon>
                  <ChevronDown size={14} className="text-gray-400" />
                </Select.Icon>
              </Select.Trigger>
              <Select.Portal>
                <Select.Content className="z-50 overflow-hidden rounded-lg border border-[#e5e7eb] bg-white shadow-lg">
                  <Select.Viewport className="p-1">
                    <Select.Item
                      value="ALL"
                      className="flex cursor-pointer items-center rounded-md px-3 py-2 text-[15px] font-sans text-gray-400 hover:bg-gray-50 focus:outline-none focus:bg-gray-50"
                    >
                      <Select.ItemText>All workspaces</Select.ItemText>
                    </Select.Item>
                    {workspaceList.map((ws) => (
                      <Select.Item
                        key={ws.id}
                        value={ws.id}
                        className="flex cursor-pointer items-center rounded-md px-3 py-2 text-[15px] font-sans text-[#464646] hover:bg-gray-50 focus:outline-none focus:bg-gray-50"
                      >
                        <Select.ItemText>{ws.name}</Select.ItemText>
                        <Select.ItemIndicator className="ml-auto">
                          <Check size={14} className="text-[#1c9770]" />
                        </Select.ItemIndicator>
                      </Select.Item>
                    ))}
                  </Select.Viewport>
                </Select.Content>
              </Select.Portal>
            </Select.Root>
          </div>
        )}

        {hasFilters && (
          <button
            onClick={handleClearFilters}
            className="h-10 px-3 text-[15px] font-sans text-[#1c9770] hover:underline transition-colors self-end"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Table */}
      {isLoading ? (
        <div className="flex items-center justify-center py-24">
          <Spinner size={32} />
        </div>
      ) : isError ? (
        <div className="bg-[#f2eeee] px-6 py-4 rounded-lg text-[15px] text-[#dc2626] font-sans">
          Failed to load scan history. Please try refreshing the page.
        </div>
      ) : filteredItems.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-24 text-center gap-4">
          <p className="font-display font-bold text-lg text-[#464646]">No scans found</p>
          <p className="text-[15px] text-gray-400 font-sans max-w-xs">
            {hasFilters
              ? 'No scans match your current filters. Try adjusting or clearing them.'
              : 'No scans have been recorded yet. Run a scan to get started.'}
          </p>
          {!hasFilters && (
            <Link to="/scan/new">
              <Button size="sm">New Scan</Button>
            </Link>
          )}
        </div>
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="min-w-full">
              <thead>
                <tr className="border-b border-gray-100">
                  <th className="pb-3 text-left text-xs font-display font-bold text-gray-400 uppercase tracking-widest pr-6">
                    Filename
                  </th>
                  <th className="pb-3 text-left text-xs font-display font-bold text-gray-400 uppercase tracking-widest pr-6">
                    Format
                  </th>
                  <th className="pb-3 text-left text-xs font-display font-bold text-gray-400 uppercase tracking-widest pr-6">
                    Risk Level
                  </th>
                  <th className="pb-3 text-left text-xs font-display font-bold text-gray-400 uppercase tracking-widest pr-6">
                    Components
                  </th>
                  <th className="pb-3 text-left text-xs font-display font-bold text-gray-400 uppercase tracking-widest pr-6">
                    Vulnerable
                  </th>
                  <th className="pb-3 text-left text-xs font-display font-bold text-gray-400 uppercase tracking-widest pr-6">
                    Quality
                  </th>
                  <th className="pb-3 text-left text-xs font-display font-bold text-gray-400 uppercase tracking-widest pr-6">
                    NTIA
                  </th>
                  <th className="pb-3 text-left text-xs font-display font-bold text-gray-400 uppercase tracking-widest pr-6">
                    Date
                  </th>
                  <th className="pb-3 text-right text-xs font-display font-bold text-gray-400 uppercase tracking-widest">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody>
                {filteredItems.map((scan) => (
                  <tr
                    key={scan.id}
                    className="border-b border-gray-100 hover:bg-gray-50/50 transition-colors"
                  >
                    <td className="py-4 pr-6 font-sans font-medium text-[15px] text-[#464646] max-w-[220px]">
                      <span className="truncate block" title={scan.filename}>
                        {scan.filename}
                      </span>
                    </td>
                    <td className="py-4 pr-6 text-sm font-sans text-gray-400">
                      {scan.sbomFormat}
                    </td>
                    <td className="py-4 pr-6">
                      <RiskBadge level={scan.riskLevel} />
                    </td>
                    <td className="py-4 pr-6 text-[15px] font-sans text-gray-500">
                      {scan.totalComponents}
                    </td>
                    <td className="py-4 pr-6">
                      {scan.vulnerableComponents > 0 ? (
                        <span className="text-[15px] font-sans font-semibold text-[#dc2626]">
                          {scan.vulnerableComponents}
                        </span>
                      ) : (
                        <span className="text-[15px] text-gray-400 font-sans">0</span>
                      )}
                    </td>
                    <td className="py-4 pr-6 text-[15px] font-sans text-gray-500">
                      {scan.qualityGrade != null ? (
                        <span className="font-display font-bold text-[#464646]">
                          {scan.qualityGrade}
                          {scan.qualityScore != null && (
                            <span className="text-sm text-gray-400 font-sans ml-1">
                              {scan.qualityScore.toFixed(1)}
                            </span>
                          )}
                        </span>
                      ) : (
                        <span className="text-gray-300">—</span>
                      )}
                    </td>
                    <td className="py-4 pr-6">
                      {scan.ntiaCompliant ? (
                        <span className="text-sm font-display font-bold text-[#93cb52]">Yes</span>
                      ) : (
                        <span className="text-sm font-display font-bold text-[#dc2626]">No</span>
                      )}
                    </td>
                    <td className="py-4 pr-6 text-sm font-sans text-gray-400 whitespace-nowrap">
                      {formatDate(scan.createdAt)}
                    </td>
                    <td className="py-4">
                      <div className="flex items-center justify-end gap-2">
                        <Link to={`/scan/${scan.id}`}>
                          <Button variant="ghost" size="sm" className="text-[#1c9770]">
                            <ExternalLink size={13} />
                            View
                          </Button>
                        </Link>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-[#dc2626] hover:bg-[#f2eeee]"
                          onClick={() => setDeleteTarget(scan)}
                        >
                          <Trash2 size={13} />
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between pt-2">
              <p className="text-sm text-gray-400 font-sans">
                Page {page} of {totalPages} ({total} total)
              </p>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="rounded-lg border border-gray-100 px-4 py-2 text-sm font-display font-bold text-[#464646] disabled:opacity-40 hover:bg-gray-50 transition-colors"
                >
                  Previous
                </button>
                <button
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page === totalPages}
                  className="rounded-lg border border-gray-100 px-4 py-2 text-sm font-display font-bold text-[#464646] disabled:opacity-40 hover:bg-gray-50 transition-colors"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </>
      )}

      {/* SBOM diff dialog */}
      <DiffDialog
        open={diffOpen}
        onOpenChange={setDiffOpen}
        items={data?.items ?? []}
      />

      {/* Delete confirmation dialog */}
      <DeleteDialog
        scan={deleteTarget}
        open={deleteTarget !== null}
        onOpenChange={(open) => {
          if (!open) setDeleteTarget(null)
        }}
        onConfirm={() => {
          if (deleteTarget) deleteMutation.mutate(deleteTarget.id)
        }}
        loading={deleteMutation.isPending}
      />
    </div>
  )
}
