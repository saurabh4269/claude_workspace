import React from 'react'
import { cn } from '@/lib/utils'

interface RiskBadgeProps {
  level: string
  className?: string
}

function getRiskStyles(level: string): { bg: string; text: string } {
  switch (level?.toUpperCase()) {
    case 'LOW':
      return { bg: 'bg-green-50', text: 'text-[#93cb52]' }
    case 'MEDIUM':
      return { bg: 'bg-amber-50', text: 'text-[#f59e0b]' }
    case 'HIGH':
      return { bg: 'bg-orange-50', text: 'text-[#f97316]' }
    case 'CRITICAL':
      return { bg: 'bg-[#f2eeee]', text: 'text-[#dc2626]' }
    default:
      return { bg: 'bg-gray-100', text: 'text-gray-500' }
  }
}

export function RiskBadge({ level, className }: RiskBadgeProps) {
  const { bg, text } = getRiskStyles(level)
  const displayLabel = level?.toUpperCase() ?? 'UNKNOWN'

  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-display font-bold uppercase tracking-wide',
        bg,
        text,
        className,
      )}
    >
      {displayLabel}
    </span>
  )
}
