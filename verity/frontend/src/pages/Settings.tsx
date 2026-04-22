import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'
import {
  Shield,
  ScanSearch,
  Key,
  Users,
  Plus,
  Copy,
  CheckCircle,
  XCircle,
  Info,
  LogIn,
} from 'lucide-react'
import { auth, workspaces, siteSettings, type WorkspaceResponse } from '@/lib/api'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Badge } from '@/components/ui/Badge'
import { Spinner } from '@/components/ui/Spinner'

function SectionDivider({ title, icon: Icon }: { title: string; icon: React.ElementType }) {
  return (
    <div className="flex items-center gap-2.5 mt-10 mb-4">
      <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-[#bef3e2]">
        <Icon size={14} className="text-[#1c9770]" />
      </div>
      <h2 className="font-display font-bold text-base text-[#1c9770] uppercase tracking-wide">
        {title}
      </h2>
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
    <div className="flex items-center justify-between py-3 border-b border-[#e5e7eb] last:border-b-0">
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

function InfoRow({ label, badge }: { label: string; badge: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between py-3 border-b border-[#e5e7eb] last:border-b-0">
      <span className="text-sm font-sans text-gray-500">{label}</span>
      <div className="flex items-center gap-2">{badge}</div>
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
    <div className="rounded-xl border border-[#e5e7eb] p-5 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <p className="font-display font-bold text-sm text-[#464646]">{workspace.name}</p>
          <p className="text-xs text-gray-400 font-sans mt-0.5">
            {workspace.memberCount} member{workspace.memberCount !== 1 ? 's' : ''}
          </p>
        </div>
        <Badge variant="info" className="text-xs">Owner</Badge>
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
        <div className="flex items-center gap-2 rounded-lg bg-[#bef3e2] px-3 py-2">
          <p className="flex-1 truncate font-mono text-xs text-[#1c9770]">{inviteLink}</p>
          <button
            onClick={handleCopy}
            className="text-[#1c9770] hover:text-[#177a5a] transition-colors"
            aria-label="Copy link"
          >
            {copied ? <CheckCircle size={14} /> : <Copy size={14} />}
          </button>
        </div>
      )}
    </div>
  )
}

export default function Settings() {
  const queryClient = useQueryClient()
  const navigate = useNavigate()

  // Per-scan defaults — stored in localStorage, read by NewScan on mount
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

  // Platform settings (server-side)
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
          // Wipe all cached data so Login.tsx fetches a fresh health response
          // instead of acting on stale auth_enabled=false data.
          queryClient.clear()
          navigate('/login')
        } else {
          // Auth turned off — clear stored credentials
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

  // Auth
  const { data: user } = useQuery({
    queryKey: ['me'],
    queryFn: () => auth.me(),
    retry: false,
  })
  const isAuthEnabled = Boolean(user)

  // Password change
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

  // Workspaces
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
    <div className="p-8 max-w-2xl mx-auto space-y-2">
      <div className="mb-6">
        <h1 className="font-display font-bold text-2xl text-[#464646]">Settings</h1>
        <p className="mt-1 text-sm text-gray-400 font-sans">
          Scan preferences and platform configuration.
        </p>
      </div>

      {/* Per-scan defaults */}
      <SectionDivider title="Scan Defaults" icon={ScanSearch} />
      <Card>
        <CardContent className="pt-6">
          <Toggle
            checked={vulnCheck}
            onChange={handleVulnCheck}
            label="Enable vulnerability check"
            description="Default for new scans — queries OSV.dev for known CVEs."
          />
          <Toggle
            checked={saveHistory}
            onChange={handleSaveHistory}
            label="Save scans to history"
            description="Default for new scans — persist results in the History tab."
          />
        </CardContent>
      </Card>

      {/* Platform settings */}
      <SectionDivider title="Platform" icon={Shield} />
      <Card>
        <CardContent className="pt-6">
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

              {/* Platform mutation error */}
              {platformError && (
                <div className="mt-2 rounded-lg bg-[#f2eeee] px-4 py-2">
                  <p className="text-xs text-[#dc2626] font-sans">{platformError}</p>
                </div>
              )}

              {/* Account info rows */}
              {user && (
                <InfoRow
                  label="Signed in as"
                  badge={<span className="text-sm font-sans font-medium text-[#464646]">{user.email}</span>}
                />
              )}
              {user && (
                <InfoRow
                  label="Role"
                  badge={user.isAdmin ? <Badge variant="error">Admin</Badge> : <Badge variant="default">Member</Badge>}
                />
              )}
              <InfoRow
                label="App version"
                badge={<span className="text-sm font-sans font-medium text-[#464646]">v0.1.0</span>}
              />
            </>
          )}
        </CardContent>
      </Card>

      {/* Auth just-enabled callout */}
      {authJustEnabled && (
        <div className="flex items-start gap-3 rounded-xl bg-[#f7fef9] border border-[#bef3e2] px-4 py-3">
          <LogIn size={16} className="text-[#1c9770] mt-0.5 flex-shrink-0" />
          <div className="flex-1">
            <p className="text-sm font-sans font-medium text-[#1c9770]">Authentication is now enabled.</p>
            <p className="text-xs text-gray-500 font-sans mt-0.5">
              Go to{' '}
              <Link to="/login" className="text-[#1c9770] underline font-semibold">
                the login page
              </Link>{' '}
              to create your first account.
            </p>
          </div>
        </div>
      )}

      {/* Auth-disabled info note */}
      {!authJustEnabled && (
        <div className="flex items-start gap-2 rounded-xl bg-gray-50 border border-[#e5e7eb] px-4 py-3">
          <Info size={14} className="text-gray-400 mt-0.5 flex-shrink-0" />
          <p className="text-xs text-gray-400 font-sans">
            Platform settings take effect immediately and persist across restarts.
            They can also be set via environment variables (
            <code className="font-mono bg-gray-100 px-1 py-0.5 rounded text-xs">AUTH_ENABLED</code>,{' '}
            <code className="font-mono bg-gray-100 px-1 py-0.5 rounded text-xs">HISTORY_ENABLED</code>,{' '}
            <code className="font-mono bg-gray-100 px-1 py-0.5 rounded text-xs">VULN_CHECK_ENABLED</code>).
          </p>
        </div>
      )}

      {/* Change Password — only when auth is enabled and user is logged in */}
      {isAuthEnabled && (
        <>
          <SectionDivider title="Change Password" icon={Key} />
          <Card>
            <CardContent className="pt-6 space-y-3">
              <div>
                <label className="text-xs font-display font-bold text-gray-500 block mb-1">
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
                <label className="text-xs font-display font-bold text-gray-500 block mb-1">
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
                <label className="text-xs font-display font-bold text-gray-500 block mb-1">
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

              <Button
                size="sm"
                onClick={handleChangePassword}
                disabled={passwordMutation.isPending}
              >
                {passwordMutation.isPending ? <Spinner size={14} className="text-white" /> : null}
                Update Password
              </Button>
            </CardContent>
          </Card>
        </>
      )}

      {/* Workspaces — only when auth is enabled and user is logged in */}
      {isAuthEnabled && (
        <>
          <SectionDivider title="Workspaces" icon={Users} />
          <Card>
            <CardContent className="pt-6">
              {wsLoading ? (
                <div className="flex items-center gap-2 py-4">
                  <Spinner size={16} />
                  <span className="text-sm text-gray-400 font-sans">Loading workspaces...</span>
                </div>
              ) : !workspaceList || workspaceList.length === 0 ? (
                <p className="text-sm text-gray-400 font-sans py-2">No workspaces yet.</p>
              ) : (
                <div className="space-y-3">
                  {workspaceList.map((ws) => (
                    <WorkspaceCard key={ws.id} workspace={ws} onInvite={handleInvite} />
                  ))}
                </div>
              )}

              <div className="mt-4 pt-4 border-t border-[#e5e7eb]">
                <p className="text-xs font-display font-bold text-gray-500 mb-2">
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
            </CardContent>
          </Card>
        </>
      )}
    </div>
  )
}
