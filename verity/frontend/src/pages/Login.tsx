import React, { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield } from 'lucide-react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { auth, health } from '@/lib/api'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Spinner } from '@/components/ui/Spinner'

export default function Login() {
  const navigate = useNavigate()
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [formError, setFormError] = useState<string | null>(null)

  const { data: healthData, isLoading: healthLoading, isFetching: healthFetching } = useQuery({
    queryKey: ['health'],
    queryFn: health.get,
    retry: false,
  })

  const loginMutation = useMutation({
    mutationFn: ({ email, password }: { email: string; password: string }) =>
      auth.login(email, password),
    onSuccess: (data) => {
      localStorage.setItem('access_token', data.accessToken)
      localStorage.setItem('refresh_token', data.refreshToken)
      localStorage.setItem('user_email', email)
      navigate('/')
    },
    onError: (err: unknown) => {
      const axiosErr = err as { response?: { data?: { detail?: string } } }
      const detail = axiosErr?.response?.data?.detail
      setFormError(detail || 'Invalid email or password.')
    },
  })

  const registerMutation = useMutation({
    mutationFn: ({ email, password }: { email: string; password: string }) =>
      auth.register(email, password),
    onSuccess: () => {
      setMode('login')
      setFormError(null)
      setPassword('')
    },
    onError: (err: unknown) => {
      const axiosErr = err as { response?: { data?: { detail?: string } } }
      const detail = axiosErr?.response?.data?.detail
      setFormError(detail || 'Registration failed. Please try again.')
    },
  })

  useEffect(() => {
    if (localStorage.getItem('access_token')) {
      navigate('/', { replace: true })
      return
    }
    if (healthData && !healthData.authEnabled) {
      navigate('/', { replace: true })
    }
  }, [healthData, navigate])

  const isLoading = loginMutation.isPending || registerMutation.isPending

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setFormError(null)
    if (!email.trim()) { setFormError('Email is required.'); return }
    if (!password) { setFormError('Password is required.'); return }
    if (mode === 'login') {
      loginMutation.mutate({ email: email.trim(), password })
    } else {
      if (password.length < 8) { setFormError('Password must be at least 8 characters.'); return }
      registerMutation.mutate({ email: email.trim(), password })
    }
  }

  // Show spinner only during the initial health check, not background refetches
  if (healthLoading || (healthData && !healthData.authEnabled)) {
    return (
      <div className="min-h-screen bg-white flex items-center justify-center">
        <Spinner size={28} />
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-white flex items-center justify-center px-4">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="flex flex-col items-center mb-10">
          <div className="flex items-center gap-2.5 mb-2">
            <Shield size={28} className="text-[#1c9770]" strokeWidth={2.5} />
            <span className="font-display font-bold text-3xl text-[#1c9770]">Verity</span>
          </div>
          <p className="text-sm text-gray-400 font-sans">
            SBOM validation and risk assessment
          </p>
        </div>

        {/* Card */}
        <div className="rounded-2xl border border-[#e5e7eb] bg-white shadow-sm p-8">
          <h2 className="font-display font-bold text-xl text-[#464646] mb-6 text-center">
            {mode === 'login' ? 'Sign in' : 'Create account'}
          </h2>

          <form onSubmit={handleSubmit} className="space-y-4" noValidate>
            <div>
              <label htmlFor="email" className="block text-xs font-display font-bold text-gray-500 mb-1">
                Email
              </label>
              <Input
                id="email"
                type="email"
                autoComplete="email"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled={isLoading}
                required
              />
            </div>

            <div>
              <label htmlFor="password" className="block text-xs font-display font-bold text-gray-500 mb-1">
                Password
              </label>
              <Input
                id="password"
                type="password"
                autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                placeholder={mode === 'login' ? 'Your password' : 'Min. 8 characters'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={isLoading}
                required
              />
            </div>

            {formError && (
              <div className="rounded-lg bg-[#f2eeee] px-4 py-3">
                <p className="text-sm text-[#dc2626] font-sans">{formError}</p>
              </div>
            )}

            {registerMutation.isSuccess && mode === 'login' && (
              <div className="rounded-lg bg-green-50 px-4 py-3">
                <p className="text-sm text-[#93cb52] font-sans">Account created. Please sign in.</p>
              </div>
            )}

            <Button type="submit" size="lg" className="w-full mt-2" disabled={isLoading}>
              {isLoading ? (
                <>
                  <Spinner size={16} className="text-white" />
                  {mode === 'login' ? 'Signing in...' : 'Creating account...'}
                </>
              ) : mode === 'login' ? 'Sign In' : 'Create Account'}
            </Button>
          </form>
        </div>

        {/* Toggle mode */}
        <p className="text-center text-sm text-gray-400 font-sans mt-6">
          {mode === 'login' ? (
            <>
              Don't have an account?{' '}
              <button
                type="button"
                onClick={() => { setMode('register'); setFormError(null) }}
                className="text-[#1c9770] font-semibold hover:underline"
              >
                Sign up
              </button>
            </>
          ) : (
            <>
              Already have an account?{' '}
              <button
                type="button"
                onClick={() => { setMode('login'); setFormError(null) }}
                className="text-[#1c9770] font-semibold hover:underline"
              >
                Sign in
              </button>
            </>
          )}
        </p>

        {/* Back link — escape hatch if user lands here unintentionally */}
        <p className="text-center text-xs text-gray-400 font-sans mt-4">
          <button
            type="button"
            onClick={() => navigate('/')}
            className="hover:underline"
          >
            ← Back to Dashboard
          </button>
        </p>
      </div>
    </div>
  )
}
