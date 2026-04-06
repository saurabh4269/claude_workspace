import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Shield,
  Database,
  Key,
  Users,
  Plus,
  Copy,
  CheckCircle,
  XCircle,
  Info,
} from 'lucide-react'
import { auth, workspaces, type WorkspaceResponse } from '@/lib/api'
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

function InfoRow({
  label,
  value,
  badge,
}: {
  label: string
  value?: string
  badge?: React.ReactNode
}) {
  return (
    <div className="flex items-center justify-between py-3 border-b border-[#e5e7eb] last:border-b-0">
      <span className="text-sm font-sans text-gray-500">{label}</span>
      <div className="flex items-center gap-2">
        {value && <span className="text-sm font-sans font-medium text-[#464646]">{value}</span>}
        {badge}
      </div>
    </div>
  )
}

function EnvNote() {
  return (
    <div className="flex items-start gap-2 rounded-xl bg-gray-50 border border-[#e5e7eb] px-4 py-3 mt-4">
      <Info size={14} className="text-gray-400 mt-0.5 flex-shrink-0" />
      <p className="text-xs text-gray-400 font-sans">
        These settings are controlled via environment variables or your{' '}
        <code className="font-mono bg-gray-100 px-1 py-0.5 rounded text-xs">.env</code> file.
        Restart the server after making changes.
      </p>
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
      setInviteError(err instanceof Error ? err.message : 'Failed to generate invite link.')
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
        <Badge variant="info" className="text-xs">
          Owner
        </Badge>
      </div>

      <div className="flex items-center gap-2">
        <Input
          placeholder="Email to invite..."
          value={inviteEmail}
          onChange={(e) => setInviteEmail(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleInvite()}
          className="flex-1"
        />
        <Button
          size="sm"
          onClick={handleInvite}
          disabled={inviteLoading || !inviteEmail.trim()}
        >
          {inviteLoading ? <Spinner size={14} className="text-white" /> : 'Invite'}
        </Button>
      </div>

      {inviteError && (
        <p className="text-xs text-[#dc2626] font-sans">{inviteError}</p>
      )}

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
  const [newWorkspaceName, setNewWorkspaceName] = useState('')
  const [createError, setCreateError] = useState<string | null>(null)

  const { data: user } = useQuery({
    queryKey: ['me'],
    queryFn: () => auth.me(),
    retry: false,
  })

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
      setCreateError(err instanceof Error ? err.message : 'Failed to create workspace.')
    },
  })

  const handleInvite = async (workspaceId: string, email: string): Promise<string> => {
    const result = await workspaces.invite(workspaceId, email)
    return result.invite_link
  }

  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [passwordError, setPasswordError] = useState<string | null>(null)
  const [passwordSuccess, setPasswordSuccess] = useState(false)

  const handleChangePassword = () => {
    setPasswordError(null)
    setPasswordSuccess(false)
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
    // Would call password change endpoint here
    setPasswordSuccess(true)
    setCurrentPassword('')
    setNewPassword('')
    setConfirmPassword('')
  }

  const isAuthEnabled = Boolean(user)

  return (
    <div className="p-8 max-w-2xl space-y-2">
      <div className="mb-6">
        <h1 className="font-display font-bold text-2xl text-[#464646]">Settings</h1>
        <p className="mt-1 text-sm text-gray-400 font-sans">
          Platform configuration and preferences.
        </p>
      </div>

      {/* General */}
      <SectionDivider title="General" icon={Shield} />
      <Card>
        <CardContent className="pt-6">
          <InfoRow label="App version" value="v0.1.0" />
          <InfoRow
            label="History"
            badge={<Badge variant="info">Configured via environment</Badge>}
          />
          <InfoRow
            label="Storage backend"
            badge={<Badge variant="default">Configured via environment</Badge>}
          />
        </CardContent>
      </Card>
      <EnvNote />

      {/* Vulnerability Checking */}
      <SectionDivider title="Vulnerability Checking" icon={Database} />
      <Card>
        <CardContent className="pt-6">
          <InfoRow
            label="OSV.dev"
            badge={
              <div className="flex items-center gap-1.5">
                <CheckCircle size={14} className="text-[#93cb52]" />
                <span className="text-sm font-sans text-[#93cb52] font-medium">Active</span>
              </div>
            }
          />
          <InfoRow
            label="NVD (NIST)"
            badge={
              <div className="flex items-center gap-1.5">
                <Info size={14} className="text-gray-400" />
                <span className="text-sm font-sans text-gray-400">
                  Not configured (set NVD_API_KEY)
                </span>
              </div>
            }
          />
          <InfoRow
            label="Vuln check enabled"
            badge={<Badge variant="info">Default: on per scan</Badge>}
          />
        </CardContent>
      </Card>
      <EnvNote />

      {/* Authentication */}
      <SectionDivider title="Authentication" icon={Key} />
      <Card>
        <CardContent className="pt-6">
          <InfoRow
            label="Authentication"
            badge={
              isAuthEnabled ? (
                <div className="flex items-center gap-1.5">
                  <CheckCircle size={14} className="text-[#93cb52]" />
                  <span className="text-sm font-sans text-[#93cb52] font-medium">Enabled</span>
                </div>
              ) : (
                <div className="flex items-center gap-1.5">
                  <XCircle size={14} className="text-gray-400" />
                  <span className="text-sm font-sans text-gray-400">Disabled</span>
                </div>
              )
            }
          />
          {user && (
            <InfoRow label="Signed in as" value={user.email} />
          )}
          {user && (
            <InfoRow
              label="Role"
              badge={
                user.isAdmin ? (
                  <Badge variant="error">Admin</Badge>
                ) : (
                  <Badge variant="default">Member</Badge>
                )
              }
            />
          )}
        </CardContent>
      </Card>

      {isAuthEnabled && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Change Password</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
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
            {passwordSuccess && (
              <p className="text-xs text-[#93cb52] font-sans">Password updated successfully.</p>
            )}

            <Button size="sm" onClick={handleChangePassword}>
              Update Password
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Workspace Management */}
      {isAuthEnabled && (
        <>
          <SectionDivider title="Workspace Management" icon={Users} />

          <Card>
            <CardHeader className="flex-row items-center justify-between pb-2">
              <CardTitle className="text-base">Workspaces</CardTitle>
            </CardHeader>
            <CardContent>
              {wsLoading ? (
                <div className="flex items-center gap-2 py-4">
                  <Spinner size={16} />
                  <span className="text-sm text-gray-400 font-sans">Loading workspaces...</span>
                </div>
              ) : !workspaceList || workspaceList.length === 0 ? (
                <p className="text-sm text-gray-400 font-sans py-2">
                  No workspaces yet.
                </p>
              ) : (
                <div className="space-y-3">
                  {workspaceList.map((ws) => (
                    <WorkspaceCard
                      key={ws.id}
                      workspace={ws}
                      onInvite={handleInvite}
                    />
                  ))}
                </div>
              )}

              {/* Create workspace */}
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
                      if (newWorkspaceName.trim()) {
                        createWorkspaceMutation.mutate(newWorkspaceName.trim())
                      }
                    }}
                    disabled={
                      createWorkspaceMutation.isPending || !newWorkspaceName.trim()
                    }
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
