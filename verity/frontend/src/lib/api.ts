import axios from 'axios'

// ---------------------------------------------------------------------------
// TypeScript interfaces
// ---------------------------------------------------------------------------

export interface ScanOptions {
  vulnCheck: boolean
  saveToHistory: boolean
  workspaceId?: string
}

export interface ScanListParams {
  page?: number
  perPage?: number
  riskLevel?: string
  workspaceId?: string
}

export interface Vulnerability {
  id: string
  summary: string
  severity: string
  cvssScore: number
  fixedVersion: string
  published: string
}

export interface Component {
  id: string
  name: string
  version: string
  purl: string
  cpe: string
  supplier: string
  licenses: string[]
  componentType: string
  riskLevel: string
  riskScore: number
  missingFields: string[]
  vulnerabilities: Vulnerability[]
}

export interface ValidationIssue {
  severity: string
  code: string
  message: string
  componentName: string
}

export interface ScanSummary {
  id: string
  filename: string
  sbomFormat: string
  formatVersion: string
  createdAt: string
  riskLevel: string
  riskScore: number
  totalComponents: number
  vulnerableComponents: number
  invalidComponents: number
  ntiaCompliant: boolean
  vulnCheckEnabled: boolean
  summary: string
}

export interface ScanDetail extends ScanSummary {
  components: Component[]
  validationIssues: ValidationIssue[]
}

export interface ScanListResponse {
  items: ScanSummary[]
  total: number
  page: number
  perPage: number
}

export interface TokenResponse {
  accessToken: string
  refreshToken: string
  tokenType: string
}

export interface UserResponse {
  id: string
  email: string
  isAdmin: boolean
  createdAt: string
}

export interface WorkspaceResponse {
  id: string
  name: string
  ownerId: string
  createdAt: string
  memberCount: number
}

// ---------------------------------------------------------------------------
// Axios instance
// ---------------------------------------------------------------------------

const apiClient = axios.create({
  baseURL: '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor: attach token if present
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Response interceptor: handle 401
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('access_token')
      localStorage.removeItem('refresh_token')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  },
)

// ---------------------------------------------------------------------------
// API functions
// ---------------------------------------------------------------------------

export const scans = {
  upload: async (file: File, opts: ScanOptions): Promise<ScanDetail> => {
    const formData = new FormData()
    formData.append('file', file)
    formData.append('vuln_check', String(opts.vulnCheck))
    formData.append('save_to_history', String(opts.saveToHistory))
    if (opts.workspaceId) {
      formData.append('workspace_id', opts.workspaceId)
    }
    const { data } = await apiClient.post<ScanDetail>('/scans/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return data
  },

  list: async (params: ScanListParams): Promise<ScanListResponse> => {
    const { data } = await apiClient.get<ScanListResponse>('/scans', {
      params: {
        page: params.page,
        per_page: params.perPage,
        risk_level: params.riskLevel,
        workspace_id: params.workspaceId,
      },
    })
    return data
  },

  get: async (id: string): Promise<ScanDetail> => {
    const { data } = await apiClient.get<ScanDetail>(`/scans/${id}`)
    return data
  },

  delete: async (id: string): Promise<void> => {
    await apiClient.delete(`/scans/${id}`)
  },

  exportJson: async (id: string): Promise<Blob> => {
    const { data } = await apiClient.get(`/scans/${id}/export/json`, {
      responseType: 'blob',
    })
    return data
  },

  exportPdf: async (id: string): Promise<Blob> => {
    const { data } = await apiClient.get(`/scans/${id}/export/pdf`, {
      responseType: 'blob',
    })
    return data
  },
}

export const auth = {
  login: async (email: string, password: string): Promise<TokenResponse> => {
    const formData = new URLSearchParams()
    formData.append('username', email)
    formData.append('password', password)
    const { data } = await apiClient.post<TokenResponse>('/auth/token', formData, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    })
    return data
  },

  register: async (email: string, password: string): Promise<UserResponse> => {
    const { data } = await apiClient.post<UserResponse>('/auth/register', {
      email,
      password,
    })
    return data
  },

  me: async (): Promise<UserResponse> => {
    const { data } = await apiClient.get<UserResponse>('/auth/me')
    return data
  },
}

export const workspaces = {
  list: async (): Promise<WorkspaceResponse[]> => {
    const { data } = await apiClient.get<WorkspaceResponse[]>('/workspaces')
    return data
  },

  create: async (name: string): Promise<WorkspaceResponse> => {
    const { data } = await apiClient.post<WorkspaceResponse>('/workspaces', { name })
    return data
  },

  invite: async (
    workspaceId: string,
    email: string,
  ): Promise<{ invite_link: string }> => {
    const { data } = await apiClient.post<{ invite_link: string }>(
      `/workspaces/${workspaceId}/invite`,
      { email },
    )
    return data
  },
}

export default apiClient
