import React from 'react'
import { cn } from '@/lib/utils'

interface RiskBadgeProps {
  level: string
  className?: string
}

export function RiskBadge({ level, className }: RiskBadgeProps) {
  const color = {
    LOW: 'text-[#93cb52]',
    MEDIUM: 'text-[#f59e0b]',
    HIGH: 'text-[#f97316]',
    CRITICAL: 'text-[#dc2626]',
  }[level?.toUpperCase()] ?? 'text-gray-400'

  return (
    <span className={cn(`text-sm font-display font-bold uppercase ${color}`, className)}>
      {level?.toUpperCase() ?? 'UNKNOWN'}
    </span>
  )
}
