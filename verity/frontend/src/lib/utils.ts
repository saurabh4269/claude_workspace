import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs))
}

export function formatDate(iso: string): string {
  const date = new Date(iso)
  return date.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  })
}

export function riskColor(level: string): string {
  switch (level?.toUpperCase()) {
    case 'LOW':
      return 'text-[#93cb52]'
    case 'MEDIUM':
      return 'text-[#f59e0b]'
    case 'HIGH':
      return 'text-[#f97316]'
    case 'CRITICAL':
      return 'text-[#dc2626]'
    default:
      return 'text-gray-500'
  }
}

export function riskBgColor(level: string): string {
  switch (level?.toUpperCase()) {
    case 'LOW':
      return 'bg-green-50'
    case 'MEDIUM':
      return 'bg-amber-50'
    case 'HIGH':
      return 'bg-orange-50'
    case 'CRITICAL':
      return 'bg-red-50'
    default:
      return 'bg-gray-50'
  }
}

export function riskBorderColor(level: string): string {
  switch (level?.toUpperCase()) {
    case 'LOW':
      return 'border-[#93cb52]'
    case 'MEDIUM':
      return 'border-[#f59e0b]'
    case 'HIGH':
      return 'border-[#f97316]'
    case 'CRITICAL':
      return 'border-[#dc2626]'
    default:
      return 'border-gray-300'
  }
}

export function formatScore(score: number): string {
  return score.toFixed(1)
}
