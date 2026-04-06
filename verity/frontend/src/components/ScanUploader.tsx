import React, { useCallback, useState } from 'react'
import { Upload } from 'lucide-react'
import { cn } from '@/lib/utils'
import { Spinner } from '@/components/ui/Spinner'

interface ScanUploaderProps {
  onFileSelected: (file: File) => void
  loading: boolean
}

const ACCEPTED_TYPES = ['.json', '.xml', '.spdx', '.tv']
const ACCEPTED_MIME = [
  'application/json',
  'application/xml',
  'text/xml',
  'text/plain',
]

function isValidFile(file: File): boolean {
  const name = file.name.toLowerCase()
  return ACCEPTED_TYPES.some((ext) => name.endsWith(ext))
}

export function ScanUploader({ onFileSelected, loading }: ScanUploaderProps) {
  const [isDragging, setIsDragging] = useState(false)
  const [dragError, setDragError] = useState<string | null>(null)

  const handleFile = useCallback(
    (file: File) => {
      setDragError(null)
      if (!isValidFile(file)) {
        setDragError(
          'Unsupported file type. Please upload a CycloneDX JSON/XML, SPDX JSON, or SPDX tag-value file.',
        )
        return
      }
      onFileSelected(file)
    },
    [onFileSelected],
  )

  const handleDragOver = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(true)
  }, [])

  const handleDragLeave = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)
  }, [])

  const handleDrop = useCallback(
    (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault()
      e.stopPropagation()
      setIsDragging(false)
      const file = e.dataTransfer.files?.[0]
      if (file) {
        handleFile(file)
      }
    },
    [handleFile],
  )

  const handleInputChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0]
      if (file) {
        handleFile(file)
      }
      // reset so same file can be re-selected
      e.target.value = ''
    },
    [handleFile],
  )

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center gap-4 rounded-2xl border-2 border-dashed border-[#bef3e2] bg-[#f7fef9] px-10 py-16">
        <Spinner size={36} />
        <p className="font-display font-bold text-lg text-[#1c9770]">
          Analyzing...
        </p>
        <p className="text-sm text-gray-400 font-sans">
          This may take a few moments
        </p>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-3">
      <label htmlFor="sbom-file-input" className="cursor-pointer">
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          className={cn(
            'flex flex-col items-center justify-center gap-4 rounded-2xl border-2 border-dashed px-10 py-16 transition-colors',
            isDragging
              ? 'border-[#1c9770] bg-[#bef3e2]/30'
              : 'border-gray-200 bg-gray-50 hover:border-[#1c9770] hover:bg-[#bef3e2]/10',
          )}
        >
          <div
            className={cn(
              'flex h-14 w-14 items-center justify-center rounded-full transition-colors',
              isDragging ? 'bg-[#bef3e2]' : 'bg-white border border-gray-200',
            )}
          >
            <Upload
              size={24}
              className={cn(
                'transition-colors',
                isDragging ? 'text-[#1c9770]' : 'text-gray-400',
              )}
            />
          </div>
          <div className="text-center">
            <p className="font-display font-bold text-xl text-[#464646]">
              Drop your SBOM here
            </p>
            <p className="mt-1.5 text-sm text-gray-400 font-sans">
              or{' '}
              <span className="text-[#1c9770] font-semibold">browse files</span>
            </p>
          </div>
          <p className="text-xs text-gray-400 font-sans text-center max-w-xs">
            Supports CycloneDX JSON, CycloneDX XML, SPDX JSON, SPDX tag-value
          </p>
        </div>
      </label>

      <input
        id="sbom-file-input"
        type="file"
        accept=".json,.xml,.spdx,.tv"
        className="sr-only"
        onChange={handleInputChange}
        disabled={loading}
      />

      {dragError && (
        <p className="rounded-lg bg-[#f2eeee] px-4 py-2.5 text-sm text-[#dc2626] font-sans">
          {dragError}
        </p>
      )}
    </div>
  )
}
