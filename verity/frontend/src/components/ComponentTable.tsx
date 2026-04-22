import React, { useState, useMemo } from 'react'
import { AlertTriangle, ChevronUp, ChevronDown, ChevronRight } from 'lucide-react'
import * as Tooltip from '@radix-ui/react-tooltip'
import { type Component, type Vulnerability } from '@/lib/api'
import { RiskBadge } from '@/components/RiskBadge'
import { cn } from '@/lib/utils'

interface ComponentTableProps {
  components: Component[]
}

function severityColor(severity: string): string {
  const s = severity?.toUpperCase()
  if (s === 'CRITICAL') return 'text-[#dc2626]'
  if (s === 'HIGH') return 'text-[#464646]'
  if (s === 'MEDIUM') return 'text-[#6b7280]'
  if (s === 'LOW') return 'text-[#93cb52]'
  return 'text-gray-400'
}

function VulnExpandedRow({ vulns, colSpan }: { vulns: Vulnerability[]; colSpan: number }) {
  return (
    <tr className="bg-[#fafaf9]">
      <td colSpan={colSpan} className="px-6 pb-3 pt-1">
        <div className="rounded-lg border border-[#e5e7eb] overflow-hidden">
          <table className="min-w-full text-xs font-sans">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-3 py-2 text-left font-display font-bold text-gray-500 uppercase tracking-wide">CVE / ID</th>
                <th className="px-3 py-2 text-left font-display font-bold text-gray-500 uppercase tracking-wide">Severity</th>
                <th className="px-3 py-2 text-left font-display font-bold text-gray-500 uppercase tracking-wide">CVSS</th>
                <th className="px-3 py-2 text-left font-display font-bold text-gray-500 uppercase tracking-wide">EPSS</th>
                <th className="px-3 py-2 text-left font-display font-bold text-gray-500 uppercase tracking-wide">KEV</th>
                <th className="px-3 py-2 text-left font-display font-bold text-gray-500 uppercase tracking-wide">Fixed In</th>
                <th className="px-3 py-2 text-left font-display font-bold text-gray-500 uppercase tracking-wide">Summary</th>
              </tr>
            </thead>
            <tbody>
              {vulns.map((v) => (
                <tr key={v.id} className="border-t border-[#e5e7eb]">
                  <td className="px-3 py-2 font-mono text-[#464646]">{v.id}</td>
                  <td className={`px-3 py-2 font-semibold ${severityColor(v.severity)}`}>
                    {v.severity || 'N/A'}
                  </td>
                  <td className="px-3 py-2 text-gray-500">
                    {v.cvssScore > 0 ? v.cvssScore.toFixed(1) : 'N/A'}
                  </td>
                  <td className="px-3 py-2 text-gray-500">
                    {v.epssScore != null ? `${(v.epssScore * 100).toFixed(2)}%` : 'N/A'}
                  </td>
                  <td className="px-3 py-2">
                    {v.inKev ? (
                      <span className="inline-flex items-center rounded-full px-1.5 py-0.5 text-xs font-semibold bg-[#f2eeee] text-[#dc2626]">
                        KEV
                      </span>
                    ) : (
                      <span className="text-gray-300">No</span>
                    )}
                  </td>
                  <td className="px-3 py-2 font-mono text-gray-500">
                    {v.fixedVersion || <span className="text-gray-300">N/A</span>}
                  </td>
                  <td className="px-3 py-2 text-gray-500 max-w-[200px] truncate" title={v.summary}>
                    {v.summary || <span className="text-gray-300">No description</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </td>
    </tr>
  )
}

const PAGE_SIZE = 25

type SortField = 'name' | 'riskScore' | 'componentType' | 'supplier'
type SortDirection = 'asc' | 'desc'

function VulnCountBadge({ count }: { count: number }) {
  if (count === 0) {
    return <span className="text-sm text-gray-400 font-sans">0</span>
  }
  return (
    <span className="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold bg-[#f2eeee] text-[#dc2626]">
      {count}
    </span>
  )
}

function MissingFieldsIcon({ fields }: { fields: string[] }) {
  if (!fields || fields.length === 0) return null
  return (
    <Tooltip.Provider delayDuration={200}>
      <Tooltip.Root>
        <Tooltip.Trigger asChild>
          <button
            type="button"
            className="inline-flex items-center ml-1 text-[#f59e0b] focus:outline-none"
            aria-label={`Missing fields: ${fields.join(', ')}`}
          >
            <AlertTriangle size={13} strokeWidth={2} />
          </button>
        </Tooltip.Trigger>
        <Tooltip.Portal>
          <Tooltip.Content
            className="z-50 rounded-lg bg-[#464646] px-3 py-2 text-xs text-white shadow-lg max-w-xs"
            sideOffset={4}
          >
            <p className="font-semibold mb-1">Missing fields:</p>
            <ul className="space-y-0.5">
              {fields.map((f) => (
                <li key={f}>{f}</li>
              ))}
            </ul>
            <Tooltip.Arrow className="fill-[#464646]" />
          </Tooltip.Content>
        </Tooltip.Portal>
      </Tooltip.Root>
    </Tooltip.Provider>
  )
}

function SortIcon({
  field,
  currentField,
  direction,
}: {
  field: SortField
  currentField: SortField
  direction: SortDirection
}) {
  if (field !== currentField) {
    return <ChevronUp size={12} className="text-gray-300" />
  }
  return direction === 'asc' ? (
    <ChevronUp size={12} className="text-[#1c9770]" />
  ) : (
    <ChevronDown size={12} className="text-[#1c9770]" />
  )
}

export function ComponentTable({ components }: ComponentTableProps) {
  const [sortField, setSortField] = useState<SortField>('riskScore')
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc')
  const [page, setPage] = useState(1)
  const [expandedId, setExpandedId] = useState<string | null>(null)

  const handleSort = (field: SortField) => {
    if (field === sortField) {
      setSortDirection((d) => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortField(field)
      setSortDirection('desc')
    }
    setPage(1)
  }

  const sorted = useMemo(() => {
    const copy = [...components]
    copy.sort((a, b) => {
      let cmp = 0
      switch (sortField) {
        case 'riskScore':
          cmp = a.riskScore - b.riskScore
          break
        case 'name':
          cmp = a.name.localeCompare(b.name)
          break
        case 'componentType':
          cmp = (a.componentType ?? '').localeCompare(b.componentType ?? '')
          break
        case 'supplier':
          cmp = (a.supplier ?? '').localeCompare(b.supplier ?? '')
          break
      }
      return sortDirection === 'asc' ? cmp : -cmp
    })
    return copy
  }, [components, sortField, sortDirection])

  const totalPages = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE))
  const pageItems = sorted.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

  const thClass =
    'px-4 py-3 text-left text-xs font-display font-bold text-gray-500 uppercase tracking-wide whitespace-nowrap'
  const tdClass = 'px-4 py-3 text-sm font-sans text-[#464646]'

  return (
    <div className="flex flex-col gap-0">
      <div className="overflow-x-auto rounded-lg border border-[#e5e7eb]">
        <table className="min-w-full text-sm">
          <thead className="bg-gray-50 sticky top-0 z-10">
            <tr>
              <th className={thClass}>
                <button
                  onClick={() => handleSort('name')}
                  className="flex items-center gap-1 hover:text-[#464646] transition-colors"
                >
                  Name
                  <SortIcon field="name" currentField={sortField} direction={sortDirection} />
                </button>
              </th>
              <th className={thClass}>Version</th>
              <th className={thClass}>
                <button
                  onClick={() => handleSort('componentType')}
                  className="flex items-center gap-1 hover:text-[#464646] transition-colors"
                >
                  Type
                  <SortIcon field="componentType" currentField={sortField} direction={sortDirection} />
                </button>
              </th>
              <th className={thClass}>
                <button
                  onClick={() => handleSort('supplier')}
                  className="flex items-center gap-1 hover:text-[#464646] transition-colors"
                >
                  Supplier
                  <SortIcon field="supplier" currentField={sortField} direction={sortDirection} />
                </button>
              </th>
              <th className={thClass}>Licenses</th>
              <th className={thClass}>
                <button
                  onClick={() => handleSort('riskScore')}
                  className="flex items-center gap-1 hover:text-[#464646] transition-colors"
                >
                  Risk
                  <SortIcon field="riskScore" currentField={sortField} direction={sortDirection} />
                </button>
              </th>
              <th className={thClass}>Vulns</th>
            </tr>
          </thead>
          <tbody>
            {pageItems.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-4 py-10 text-center text-gray-400 font-sans">
                  No components found.
                </td>
              </tr>
            ) : (
              pageItems.flatMap((comp, idx) => {
                const isExpanded = expandedId === comp.id
                const hasVulns = (comp.vulnerabilities?.length ?? 0) > 0
                const rows = [
                  <tr
                    key={comp.id}
                    onClick={() => hasVulns && setExpandedId(isExpanded ? null : comp.id)}
                    className={cn(
                      'border-t border-[#e5e7eb] transition-colors',
                      hasVulns ? 'cursor-pointer hover:bg-[#f7fef9]' : 'hover:bg-gray-50',
                      idx % 2 === 1 ? 'bg-gray-50/50' : 'bg-white',
                      isExpanded && 'bg-[#f7fef9]',
                    )}
                  >
                    <td className={cn(tdClass, 'font-medium max-w-[200px]')}>
                      <div className="flex items-center gap-1 truncate">
                        {hasVulns && (
                          <ChevronRight
                            size={13}
                            className={cn(
                              'shrink-0 text-gray-400 transition-transform',
                              isExpanded && 'rotate-90',
                            )}
                          />
                        )}
                        <span className="truncate" title={comp.name}>
                          {comp.name}
                        </span>
                        <MissingFieldsIcon fields={comp.missingFields ?? []} />
                      </div>
                    </td>
                    <td className={cn(tdClass, 'font-mono text-xs text-gray-500')}>
                      {comp.version || <span className="text-gray-300">N/A</span>}
                    </td>
                    <td className={tdClass}>
                      {comp.componentType ? (
                        <span className="rounded bg-gray-100 px-2 py-0.5 text-xs text-gray-600 font-sans">
                          {comp.componentType}
                        </span>
                      ) : (
                        <span className="text-gray-300">N/A</span>
                      )}
                    </td>
                    <td className={cn(tdClass, 'max-w-[140px]')}>
                      <span className="truncate block" title={comp.supplier ?? ''}>
                        {comp.supplier || <span className="text-gray-300">N/A</span>}
                      </span>
                    </td>
                    <td className={cn(tdClass, 'max-w-[160px]')}>
                      {comp.licenses && comp.licenses.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {comp.licenses.slice(0, 2).map((lic) => (
                            <span
                              key={lic}
                              className="rounded bg-[#bef3e2] px-1.5 py-0.5 text-xs text-[#1c9770] font-sans"
                            >
                              {lic}
                            </span>
                          ))}
                          {comp.licenses.length > 2 && (
                            <span className="text-xs text-gray-400">
                              +{comp.licenses.length - 2}
                            </span>
                          )}
                        </div>
                      ) : (
                        <span className="text-gray-300 text-xs">None</span>
                      )}
                    </td>
                    <td className={tdClass}>
                      <div className="flex items-center gap-1.5">
                        <RiskBadge level={comp.riskLevel} />
                        <span className="text-xs text-gray-400">
                          {comp.riskScore.toFixed(1)}
                        </span>
                      </div>
                    </td>
                    <td className={tdClass}>
                      <VulnCountBadge count={comp.vulnerabilities?.length ?? 0} />
                    </td>
                  </tr>,
                ]
                if (isExpanded && hasVulns) {
                  rows.push(
                    <VulnExpandedRow
                      key={`${comp.id}-vulns`}
                      vulns={comp.vulnerabilities}
                      colSpan={7}
                    />
                  )
                }
                return rows
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Hint for expandable rows */}
      {components.some((c) => (c.vulnerabilities?.length ?? 0) > 0) && (
        <p className="px-1 pt-2 text-xs text-gray-400 font-sans">
          Click a row with vulnerabilities to expand CVE details.
        </p>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between px-1 py-3">
          <p className="text-sm text-gray-400 font-sans">
            Showing {(page - 1) * PAGE_SIZE + 1}
            {' - '}
            {Math.min(page * PAGE_SIZE, sorted.length)} of {sorted.length} components
          </p>
          <div className="flex items-center gap-1">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              className="rounded-lg border border-[#e5e7eb] px-3 py-1.5 text-sm font-display font-bold text-[#464646] disabled:opacity-40 hover:bg-gray-50 transition-colors"
            >
              Previous
            </button>
            {Array.from({ length: Math.min(totalPages, 7) }, (_, i) => {
              const pageNum =
                totalPages <= 7
                  ? i + 1
                  : page <= 4
                  ? i + 1
                  : page >= totalPages - 3
                  ? totalPages - 6 + i
                  : page - 3 + i
              return (
                <button
                  key={pageNum}
                  onClick={() => setPage(pageNum)}
                  className={cn(
                    'rounded-lg px-3 py-1.5 text-sm font-display font-bold transition-colors',
                    pageNum === page
                      ? 'bg-[#1c9770] text-white'
                      : 'border border-[#e5e7eb] text-[#464646] hover:bg-gray-50',
                  )}
                >
                  {pageNum}
                </button>
              )
            })}
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              className="rounded-lg border border-[#e5e7eb] px-3 py-1.5 text-sm font-display font-bold text-[#464646] disabled:opacity-40 hover:bg-gray-50 transition-colors"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
