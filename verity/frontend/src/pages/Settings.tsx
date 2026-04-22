import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'
import { Plus, Copy, Check, LogIn } from 'lucide-react'
import { auth, workspaces, siteSettings, type WorkspaceResponse } from '@/lib/api'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Spinner } from '@/components/ui/Spinner'

function SectionLabel({ title }: { title: string }) {
  return (
    <div className="mt-10 mb-4">
      <p className="text-xs font-display font-bold text-gray-400 uppercase tracking-widest">
        {title}
      </p>
    </div>
  )
}

function Toggle({
  checked,
  onChange,
  label,
  description,
  disabled,
}: {
  checked: boolean
  onChange: (v: boolean) => void
  label: string
  description: string
  disabled?: boolean
}) {
  return (
    <div className="flex items-center justify-between py-3 border-b border-gray-100 last:border-b-0">
      <div className="flex-1 min-w-0 pr-4">
        <p className="text-sm font-sans font-medium text-[#464646]">{label}</p>
        <p className="text-xs text-gray-400 font-sans mt-0.5">{description}</p>
      </div>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        onClick={() => !disabled && onChange(!checked)}
        disabled={disabled}
        className={`relative inline-flex h-5 w-9 flex-shrink-0 rounded-full border-2 border-transparent transition-colors focus:outline-none focus:ring-2 focus:ring-[#1c9770] focus:ring-offset-2 ${
          disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'
        } ${checked ? 'bg-[#1c9770]' : 'bg-gray-200'}`}
      >
        <span
          className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${
            checked ? 'translate-x-4' : 'translate-x-0'
          }`}
        />
      </button>
    </div>
  )
}

function InfoRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between py-3 border-b border-gray-100 last:border-b-0">
      <span className="text-sm font-sans text-gray-400">{label}</span>
      <div className="flex items-center gap-2">{value}</div>
    </div>
  )
}

function WorkspaceCard({
  workspace,
  onInvite,
}: {
  workspace: WorkspaceResponse
  onInvite: (id: string, email: string) => Promise<string>
}) {
  const [inviteEmail, setInviteEmail] = useState('')
  const [inviteLink, setInviteLink] = useState<string | null>(null)
  const [inviteLoading, setInviteLoading] = useState(false)
  const [inviteError, setInviteError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const handleInvite = async () => {
    if (!inviteEmail.trim()) return
    setInviteLoading(true)
    setInviteError(null)
    try {
      const link = await onInvite(workspace.id, inviteEmail.trim())
      setInviteLink(link)
      setInviteEmail('')
    } catch (err) {
      const axiosErr = err as { response?: { data?: { detail?: string } } }
      const detail = axiosErr?.response?.data?.detail
      setInviteError(detail || (err instanceof Error ? err.message : 'Failed to generate invite link.'))
    } finally {
      setInviteLoading(false)
    }
  }

  const handleCopy = () => {
    if (!inviteLink) return
    navigator.clipboard.writeText(inviteLink).catch(() => undefined)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="pb-5 border-b border-gray-100 last:border-b-0 space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <p className="font-display font-bold text-sm text-[#464646]">{workspace.name}</p>
          <p className="text-xs text-gray-400 font-sans mt-0.5">
            {workspace.memberCount} member{workspace.memberCount !== 1 ? 's' : ''}
          </p>
        </div>
        <span className="text-sm font-display font-bold text-[#1c9770]">Owner</span>
      </div>

      <div className="flex items-center gap-2">
        <Input
          placeholder="Email to invite..."
          value={inviteEmail}
          onChange={(e) => setInviteEmail(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleInvite()}
          className="flex-1"
        />
        <Button size="sm" onClick={handleInvite} disabled={inviteLoading || !inviteEmail.trim()}>
          {inviteLoading ? <Spinner size={14} className="text-white" /> : 'Invite'}
        </Button>
      </div>

      {inviteError && <p className="text-xs text-[#dc2626] font-sans">{inviteError}</p>}

      {inviteLink && (
        <div className="flex items-center gap-2 border-b border-gray-100 pb-3">
          <p className="flex-1 truncate font-mono text-xs text-[#6b7280]">{inviteLink}</p>
          <button
            onClick={handleCopy}
            className="text-[#1c9770] hover:text-[#177a5a] transition-colors shrink-0"
            aria-label="Copy link"
          >
            {copied ? <Check size={14} /> : <Copy size={14} />}
          </button>
        </div>
      )}
    </div>
  )
}

export default function Settings() {
  const queryClient = useQueryClient()
  const navigate = useNavigate()

  const [vulnCheck, setVulnCheck] = useState(
    () => localStorage.getItem('pref_vuln_check') !== 'false'
  )
  const [saveHistory, setSaveHistory] = useState(
    () => localStorage.getItem('pref_save_history') !== 'false'
  )

  const handleVulnCheck = (v: boolean) => {
    setVulnCheck(v)
    localStorage.setItem('pref_vuln_check', String(v))
  }
  const handleSaveHistory = (v: boolean) => {
    setSaveHistory(v)
    localStorage.setItem('pref_save_history', String(v))
  }

  const { data: platformSettings, isLoading: platformLoading } = useQuery({
    queryKey: ['site-settings'],
    queryFn: () => siteSettings.get(),
    retry: false,
  })

  const [authJustEnabled, setAuthJustEnabled] = useState(false)
  const [platformError, setPlatformError] = React.useState<string | null>(null)

  const platformMutation = useMutation({
    mutationFn: (patch: Parameters<typeof siteSettings.update>[0]) =>
      siteSettings.update(patch),
    onSuccess: (data, variables) => {
      setPlatformError(null)
      queryClient.setQueryData(['site-settings'], data)

      if ('auth_enabled' in variables) {
        if (data.authEnabled) {
          queryClient.clear()
          navigate('/login')
        } else {
          localStorage.removeItem('access_token')
          localStorage.removeItem('refresh_token')
          queryClient.invalidateQueries({ queryKey: ['me'] })
        }
      }
    },
    onError: (err: unknown) => {
      const axiosErr = err as { response?: { data?: { detail?: string } } }
      const detail = axiosErr?.response?.data?.detail
      setPlatformError(detail || 'Failed to update platform settings.')
    },
  })

  const handlePlatformToggle = (
    key: 'auth_enabled' | 'history_enabled' | 'vuln_check_enabled',
    value: boolean,
  ) => {
    if (key === 'auth_enabled' && value) setAuthJustEnabled(true)
    if (key === 'auth_enabled' && !value) setAuthJustEnabled(false)
    platformMutation.mutate({ [key]: value })
  }

  const { data: user } = useQuery({
    queryKey: ['me'],
    queryFn: () => auth.me(),
    retry: false,
  })
  const isAuthEnabled = Boolean(user)

  const [changingPassword, setChangingPassword] = useState(false)
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [passwordError, setPasswordError] = useState<string | null>(null)

  const passwordMutation = useMutation({
    mutationFn: () => auth.changePassword(currentPassword, newPassword),
    onSuccess: () => {
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
      setPasswordError(null)
      setTimeout(() => setChangingPassword(false), 1500)
    },
    onError: (err: unknown) => {
      const axiosErr = err as { response?: { data?: { detail?: string } } }
      const detail = axiosErr?.response?.data?.detail
      setPasswordError(detail || (err instanceof Error ? err.message : 'Failed to change password.'))
    },
  })

  const handleChangePassword = () => {
    setPasswordError(null)
    if (!currentPassword || !newPassword || !confirmPassword) {
      setPasswordError('All fields are required.')
      return
    }
    if (newPassword !== confirmPassword) {
      setPasswordError('New passwords do not match.')
      return
    }
    if (newPassword.length < 8) {
      setPasswordError('Password must be at least 8 characters.')
      return
    }
    passwordMutation.mutate()
  }

  const [newWorkspaceName, setNewWorkspaceName] = useState('')
  const [createError, setCreateError] = useState<string | null>(null)

  const { data: workspaceList, isLoading: wsLoading } = useQuery({
    queryKey: ['workspaces'],
    queryFn: () => workspaces.list(),
    retry: false,
  })

  const createWorkspaceMutation = useMutation({
    mutationFn: (name: string) => workspaces.create(name),
    onSuccess: () => {
      setNewWorkspaceName('')
      setCreateError(null)
      queryClient.invalidateQueries({ queryKey: ['workspaces'] })
    },
    onError: (err: unknown) => {
      const axiosErr = err as { response?: { data?: { detail?: string } } }
      const detail = axiosErr?.response?.data?.detail
      setCreateError(detail || (err instanceof Error ? err.message : 'Failed to create workspace.'))
    },
  })

  const handleInvite = async (workspaceId: string, email: string): Promise<string> => {
    const result = await workspaces.invite(workspaceId, email)
    return result.inviteLink
  }

  return (
    <div className="p-8 max-w-2xl mx-auto">
      <div className="mb-6">
        <h1 className="font-display font-bold text-2xl text-[#464646]">Settings</h1>
        <p className="mt-1 text-sm text-gray-400 font-sans">
          Scan preferences and platform configuration.
        </p>
      </div>

      {/* Per-scan defaults */}
      <SectionLabel title="Scan Defaults" />
      <div>
        <Toggle
          checked={vulnCheck}
          onChange={handleVulnCheck}
          label="Enable vulnerability check"
          description="Default for new scans. Queries OSV.dev for known CVEs."
        />
        <Toggle
          checked={saveHistory}
          onChange={handleSaveHistory}
          label="Save scans to history"
          description="Default for new scans. Persist results in the History tab."
        />
      </div>

      {/* Platform settings */}
      <SectionLabel title="Platform" />
      <div>
        {platformLoading ? (
          <div className="flex items-center gap-2 py-3">
            <Spinner size={16} />
            <span className="text-sm text-gray-400 font-sans">Loading…</span>
          </div>
        ) : (
          <>
            <Toggle
              checked={platformSettings?.authEnabled ?? false}
              onChange={(v) => handlePlatformToggle('auth_enabled', v)}
              label="Authentication"
              description="Require users to sign in. Disabling removes all login requirements."
              disabled={platformMutation.isPending}
            />
            <Toggle
              checked={platformSettings?.historyEnabled ?? true}
              onChange={(v) => handlePlatformToggle('history_enabled', v)}
              label="History"
              description="Allow scans to be saved to the History tab platform-wide."
              disabled={platformMutation.isPending}
            />
            <Toggle
              checked={platformSettings?.vulnCheckEnabled ?? true}
              onChange={(v) => handlePlatformToggle('vuln_check_enabled', v)}
              label="Vulnerability checking"
              description="Allow OSV.dev lookups platform-wide. Overrides per-scan setting."
              disabled={platformMutation.isPending}
            />

            {platformError && (
              <p className="text-xs text-[#dc2626] font-sans pt-3">{platformError}</p>
            )}

            {user && (
              <InfoRow
                label="Signed in as"
                value={<span className="text-sm font-sans font-medium text-[#464646]">{user.email}</span>}
              />
            )}
            {user && (
              <InfoRow
                label="Role"
                value={
                  <span className="text-sm font-display font-bold text-[#464646]">
                    {user.isAdmin ? 'Admin' : 'Member'}
                  </span>
                }
              />
            )}
            <InfoRow
              label="App version"
              value={<span className="text-sm font-sans text-gray-400">v0.1.0</span>}
            />
          </>
        )}
      </div>

      {authJustEnabled && (
        <p className="mt-4 text-sm font-sans text-[#1c9770]">
          <LogIn size={13} className="inline mr-1.5 mb-0.5" />
          Authentication enabled.{' '}
          <Link to="/login" className="underline font-semibold">
            Go to login page
          </Link>{' '}
          to create your first account.
        </p>
      )}

      {/* Change Password */}
      {isAuthEnabled && (
        <>
          <SectionLabel title="Account" />
          {!changingPassword ? (
            <button
              type="button"
              onClick={() => setChangingPassword(true)}
              className="text-sm font-sans text-[#1c9770] hover:underline"
            >
              Change password
            </button>
          ) : (
            <div className="space-y-3">
              <div>
                <label className="text-xs font-display font-bold text-gray-400 block mb-1">
                  Current password
                </label>
                <Input
                  type="password"
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  autoComplete="current-password"
                />
              </div>
              <div>
                <label className="text-xs font-display font-bold text-gray-400 block mb-1">
                  New password
                </label>
                <Input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  autoComplete="new-password"
                />
              </div>
              <div>
                <label className="text-xs font-display font-bold text-gray-400 block mb-1">
                  Confirm new password
                </label>
                <Input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  autoComplete="new-password"
                  onKeyDown={(e) => e.key === 'Enter' && handleChangePassword()}
                />
              </div>

              {passwordError && (
                <p className="text-xs text-[#dc2626] font-sans">{passwordError}</p>
              )}
              {passwordMutation.isSuccess && (
                <p className="text-xs text-[#93cb52] font-sans">Password updated successfully.</p>
              )}

              <div className="flex items-center gap-3">
                <Button
                  size="sm"
                  onClick={handleChangePassword}
                  disabled={passwordMutation.isPending}
                >
                  {passwordMutation.isPending ? <Spinner size={14} className="text-white" /> : null}
                  Update password
                </Button>
                <button
                  type="button"
                  onClick={() => {
                    setChangingPassword(false)
                    setCurrentPassword('')
                    setNewPassword('')
                    setConfirmPassword('')
                    setPasswordError(null)
                  }}
                  className="text-sm font-sans text-gray-400 hover:text-[#464646]"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </>
      )}

      {/* Workspaces */}
      {isAuthEnabled && (
        <>
          <SectionLabel title="Workspaces" />
          <div>
            {wsLoading ? (
              <div className="flex items-center gap-2 py-4">
                <Spinner size={16} />
                <span className="text-sm text-gray-400 font-sans">Loading workspaces...</span>
              </div>
            ) : !workspaceList || workspaceList.length === 0 ? (
              <p className="text-sm text-gray-400 font-sans py-2">No workspaces yet.</p>
            ) : (
              <div className="space-y-5">
                {workspaceList.map((ws) => (
                  <WorkspaceCard key={ws.id} workspace={ws} onInvite={handleInvite} />
                ))}
              </div>
            )}

            <div className="mt-6 pt-4 border-t border-gray-100">
              <p className="text-xs font-display font-bold text-gray-400 mb-2">
                Create new workspace
              </p>
              <div className="flex items-center gap-2">
                <Input
                  placeholder="Workspace name..."
                  value={newWorkspaceName}
                  onChange={(e) => setNewWorkspaceName(e.target.value)}
                  onKeyDown={(e) =>
                    e.key === 'Enter' &&
                    newWorkspaceName.trim() &&
                    createWorkspaceMutation.mutate(newWorkspaceName.trim())
                  }
                />
                <Button
                  size="sm"
                  onClick={() => {
                    if (newWorkspaceName.trim()) createWorkspaceMutation.mutate(newWorkspaceName.trim())
                  }}
                  disabled={createWorkspaceMutation.isPending || !newWorkspaceName.trim()}
                >
                  {createWorkspaceMutation.isPending ? (
                    <Spinner size={14} className="text-white" />
                  ) : (
                    <Plus size={14} />
                  )}
                  Create
                </Button>
              </div>
              {createError && (
                <p className="mt-2 text-xs text-[#dc2626] font-sans">{createError}</p>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  )
}
