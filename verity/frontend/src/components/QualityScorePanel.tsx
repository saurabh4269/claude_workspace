import React from 'react'
import { CheckCircle, XCircle, Minus } from 'lucide-react'
import type { QualityScore, CategoryResult } from '@/lib/api'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card'

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

function CategoryRow({ cat }: { cat: CategoryResult }) {
  const pct = Math.min((cat.score / 10) * 100, 100)
  return (
    <div className="py-3 border-b border-[#e5e7eb] last:border-0">
      <div className="flex items-center justify-between mb-1">
        <span className="text-sm font-sans font-medium text-[#464646]">{cat.name}</span>
        <span className="text-sm font-display font-bold text-[#464646]">
          {cat.score.toFixed(1)} / 10
        </span>
      </div>
      <div className="w-full h-2 bg-gray-100 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all ${scoreBarColor(cat.score)}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <div className="mt-1.5 space-y-0.5">
        {cat.features.filter((f) => f.applicable).map((f) => (
          <div key={f.key} className="flex items-start gap-2 text-xs text-gray-400 font-sans">
            {f.score >= 8 ? (
              <CheckCircle size={12} className="text-[#93cb52] mt-0.5 shrink-0" />
            ) : f.score === 0 ? (
              <XCircle size={12} className="text-[#dc2626] mt-0.5 shrink-0" />
            ) : (
              <Minus size={12} className="text-[#f59e0b] mt-0.5 shrink-0" />
            )}
            <span>{f.detail}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

interface Props {
  quality: QualityScore
}

export function QualityScorePanel({ quality }: Props) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Quality Score</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex items-center gap-6 mb-6">
          <div className="flex flex-col items-center">
            <span className={`text-6xl font-display font-bold ${gradeColor(quality.grade)}`}>
              {quality.grade}
            </span>
            <span className="text-xs text-gray-400 font-sans mt-1">Grade</span>
          </div>
          <div className="flex flex-col">
            <span className="text-3xl font-display font-bold text-[#464646]">
              {quality.overallScore.toFixed(1)}
              <span className="text-lg text-gray-400 font-sans"> / 10</span>
            </span>
            <span className="text-xs text-gray-400 font-sans mt-1">Overall Score</span>
          </div>
        </div>
        <div>
          {quality.categories.map((cat) => (
            <CategoryRow key={cat.name} cat={cat} />
          ))}
        </div>
      </CardContent>
    </Card>
  )
}
