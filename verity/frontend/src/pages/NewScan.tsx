import React, { useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import { FileText, X } from 'lucide-react'
import * as Switch from '@radix-ui/react-switch'
import * as Select from '@radix-ui/react-select'
import { ChevronDown, Check } from 'lucide-react'
import { scans, workspaces, type ScanOptions } from '@/lib/api'
import { ScanUploader } from '@/components/ScanUploader'
import { Button } from '@/components/ui/Button'
import { Spinner } from '@/components/ui/Spinner'
import { cn } from '@/lib/utils'

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

interface ToggleOptionProps {
  id: string
  label: string
  description: string
  checked: boolean
  onCheckedChange: (v: boolean) => void
}

function ToggleOption({ id, label, description, checked, onCheckedChange }: ToggleOptionProps) {
  return (
    <div className="flex items-start justify-between gap-4 py-4">
      <div className="flex-1">
        <label
          htmlFor={id}
          className="text-sm font-display font-bold text-[#464646] cursor-pointer"
        >
          {label}
        </label>
        <p className="text-xs text-gray-400 font-sans mt-0.5">{description}</p>
      </div>
      <Switch.Root
        id={id}
        checked={checked}
        onCheckedChange={onCheckedChange}
        className={cn(
          'relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#1c9770] focus-visible:ring-offset-2',
          checked ? 'bg-[#1c9770]' : 'bg-gray-200',
        )}
      >
        <Switch.Thumb
          className={cn(
            'pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow-lg ring-0 transition-transform',
            checked ? 'translate-x-5' : 'translate-x-0',
          )}
        />
      </Switch.Root>
    </div>
  )
}

export default function NewScan() {
  const navigate = useNavigate()
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [vulnCheck, setVulnCheck] = useState(
    () => localStorage.getItem('pref_vuln_check') !== 'false'
  )
  const [saveToHistory, setSaveToHistory] = useState(
    () => localStorage.getItem('pref_save_history') !== 'false'
  )
  const [workspaceId, setWorkspaceId] = useState<string>('none')
  const [profile, setProfile] = useState<string>('none')
  const [scanError, setScanError] = useState<string | null>(null)

  const { data: workspaceList } = useQuery({
    queryKey: ['workspaces'],
    queryFn: () => workspaces.list(),
    retry: false,
  })

  const uploadMutation = useMutation({
    mutationFn: ({ file, opts }: { file: File; opts: ScanOptions }) =>
      scans.upload(file, opts),
    onSuccess: (data) => {
      navigate(`/scan/${data.id}`)
    },
    onError: (err: unknown) => {
      // Extract meaningful message from Axios error responses
      const axiosErr = err as { response?: { data?: { detail?: string | { msg: string }[] } } }
      const detail = axiosErr?.response?.data?.detail
      let message: string
      if (typeof detail === 'string') {
        message = detail
      } else if (Array.isArray(detail) && detail.length > 0) {
        message = typeof detail[0] === 'string' ? detail[0] : (detail[0] as { msg: string }).msg
      } else if (err instanceof Error) {
        message = err.message
      } else {
        message = 'An unexpected error occurred.'
      }
      setScanError(message)
    },
  })

  const handleFileSelected = useCallback((file: File) => {
    setSelectedFile(file)
    setScanError(null)
  }, [])

  const handleClearFile = () => {
    setSelectedFile(null)
    setScanError(null)
  }

  const handleRunScan = () => {
    if (!selectedFile) return
    setScanError(null)
    const opts: ScanOptions = {
      vulnCheck,
      saveToHistory,
      runCompliance: true,
      workspaceId: workspaceId !== 'none' ? workspaceId : undefined,
      profile: profile !== 'none' ? profile : undefined,
    }
    uploadMutation.mutate({ file: selectedFile, opts })
  }

  const isScanning = uploadMutation.isPending

  return (
    <div className="p-8 max-w-2xl mx-auto">
      {/* Page header */}
      <div className="mb-8">
        <h1 className="font-display font-bold text-3xl text-[#464646]">New Scan</h1>
        <p className="mt-2 text-sm font-sans text-gray-400">
          Upload an SBOM file to validate and assess risk.
        </p>
      </div>

      {/* Uploader */}
      <ScanUploader onFileSelected={handleFileSelected} loading={isScanning} />

      {/* Selected file info */}
      {selectedFile && !isScanning && (
        <div className="mt-4 flex items-center gap-3 rounded-xl border border-[#bef3e2] bg-[#f7fef9] px-4 py-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-[#bef3e2]">
            <FileText size={16} className="text-[#1c9770]" />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-display font-bold text-[#464646] truncate">
              {selectedFile.name}
            </p>
            <p className="text-xs text-gray-400 font-sans">{formatBytes(selectedFile.size)}</p>
          </div>
          <button
            type="button"
            onClick={handleClearFile}
            className="text-gray-400 hover:text-[#464646] transition-colors"
            aria-label="Remove file"
          >
            <X size={16} />
          </button>
        </div>
      )}

      {/* Options panel */}
      {!isScanning && (
        <div className="mt-6 rounded-xl border border-[#e5e7eb] bg-white px-6 divide-y divide-[#e5e7eb]">
          <ToggleOption
            id="vuln-check"
            label="Check vulnerabilities"
            description="Queries OSV.dev for known CVEs affecting your components"
            checked={vulnCheck}
            onCheckedChange={setVulnCheck}
          />
          <ToggleOption
            id="save-history"
            label="Save to history"
            description="Store this scan for future reference and trend analysis"
            checked={saveToHistory}
            onCheckedChange={setSaveToHistory}
          />

          {/* Workspace selector */}
          {workspaceList && workspaceList.length > 0 && (
            <div className="flex items-start justify-between gap-4 py-4">
              <div className="flex-1">
                <p className="text-sm font-display font-bold text-[#464646]">Workspace</p>
                <p className="text-xs text-gray-400 font-sans mt-0.5">
                  Associate this scan with a workspace (optional)
                </p>
              </div>
              <Select.Root value={workspaceId} onValueChange={setWorkspaceId}>
                <Select.Trigger
                  className="flex h-9 min-w-[160px] items-center justify-between rounded-lg border border-gray-200 bg-white px-3 text-sm font-sans text-[#464646] focus:outline-none focus:ring-2 focus:ring-[#1c9770] data-[placeholder]:text-gray-400"
                  aria-label="Workspace"
                >
                  <Select.Value placeholder="None" />
                  <Select.Icon>
                    <ChevronDown size={14} className="text-gray-400" />
                  </Select.Icon>
                </Select.Trigger>
                <Select.Portal>
                  <Select.Content className="z-50 overflow-hidden rounded-lg border border-[#e5e7eb] bg-white shadow-lg">
                    <Select.Viewport className="p-1">
                      <Select.Item
                        value="none"
                        className="flex cursor-pointer items-center rounded-md px-3 py-2 text-sm font-sans text-gray-400 hover:bg-gray-50 focus:outline-none focus:bg-gray-50"
                      >
                        <Select.ItemText>None</Select.ItemText>
                      </Select.Item>
                      {workspaceList.map((ws) => (
                        <Select.Item
                          key={ws.id}
                          value={ws.id}
                          className="flex cursor-pointer items-center rounded-md px-3 py-2 text-sm font-sans text-[#464646] hover:bg-gray-50 focus:outline-none focus:bg-gray-50"
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

          {/* Compliance profile selector */}
          <div className="flex items-start justify-between gap-4 py-4">
            <div className="flex-1">
              <p className="text-sm font-display font-bold text-[#464646]">Compliance Profile Score</p>
              <p className="text-xs text-gray-400 font-sans mt-0.5">
                Score the SBOM against a specific compliance standard (optional)
              </p>
            </div>
            <Select.Root value={profile} onValueChange={setProfile}>
              <Select.Trigger
                className="flex h-9 min-w-[160px] items-center justify-between rounded-lg border border-gray-200 bg-white px-3 text-sm font-sans text-[#464646] focus:outline-none focus:ring-2 focus:ring-[#1c9770] data-[placeholder]:text-gray-400"
                aria-label="Profile"
              >
                <Select.Value placeholder="None" />
                <Select.Icon>
                  <ChevronDown size={14} className="text-gray-400" />
                </Select.Icon>
              </Select.Trigger>
              <Select.Portal>
                <Select.Content className="z-50 overflow-hidden rounded-lg border border-[#e5e7eb] bg-white shadow-lg">
                  <Select.Viewport className="p-1">
                    {[
                      { value: 'none', label: 'None' },
                      { value: 'ntia', label: 'NTIA Minimum Elements' },
                      { value: 'bsi', label: 'BSI TR-03183-2 v2.1' },
                      { value: 'fsct', label: 'FSCT v3' },
                      { value: 'oct', label: 'OpenChain Telco v1.1' },
                    ].map(({ value, label }) => (
                      <Select.Item
                        key={value}
                        value={value}
                        className="flex cursor-pointer items-center rounded-md px-3 py-2 text-sm font-sans text-[#464646] hover:bg-gray-50 focus:outline-none focus:bg-gray-50 data-[highlighted]:bg-gray-50"
                      >
                        <Select.ItemText>{label}</Select.ItemText>
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
        </div>
      )}

      {/* Scanning progress */}
      {isScanning && (
        <div className="mt-6 flex flex-col items-center gap-3 py-4">
          <div className="w-full rounded-full bg-gray-100 h-1.5 overflow-hidden">
            <div className="h-full bg-[#1c9770] rounded-full animate-pulse w-3/4" />
          </div>
          <p className="text-sm text-gray-400 font-sans">
            Analyzing SBOM... this may take a moment.
          </p>
        </div>
      )}

      {/* Error state */}
      {scanError && !isScanning && (
        <div className="mt-4 rounded-xl bg-[#f2eeee] px-5 py-4">
          <p className="text-sm font-sans text-[#dc2626] font-semibold mb-0.5">Scan failed</p>
          <p className="text-sm font-sans text-[#dc2626]">{scanError}</p>
        </div>
      )}

      {/* Run scan button */}
      {selectedFile && !isScanning && (
        <div className="mt-6">
          <Button
            size="lg"
            className="w-full"
            onClick={handleRunScan}
            disabled={isScanning}
          >
            {isScanning ? (
              <>
                <Spinner size={16} className="text-white" />
                Analyzing...
              </>
            ) : (
              'Run Scan'
            )}
          </Button>
        </div>
      )}
    </div>
  )
}
