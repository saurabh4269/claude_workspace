import axios from 'axios'

// ---------------------------------------------------------------------------
// TypeScript interfaces
// ---------------------------------------------------------------------------

export interface ScanOptions {
  vulnCheck: boolean
  saveToHistory: boolean
  workspaceId?: string
  runCompliance?: boolean
  profile?: string
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
  fixedVersion?: string
  published?: string
  epssScore?: number
  epssPercentile?: number
  inKev: boolean
}

export interface Component {
  id: string
  name: string
  version?: string
  purl?: string
  cpe?: string
  supplier?: string
  licenses: string[]
  componentType?: string
  riskLevel: string
  riskScore: number
  missingFields: string[]
  vulnerabilities: Vulnerability[]
}

export interface ValidationIssue {
  severity: string
  code: string
  message: string
  componentName?: string
}

// Quality scoring
export interface FeatureResult {
  key: string
  score: number
  applicable: boolean
  weight: number
  detail: string
}

export interface CategoryResult {
  name: string
  weight: number
  score: number
  weightedScore: number
  features: FeatureResult[]
}

export interface QualityScore {
  overallScore: number
  grade: string
  categories: CategoryResult[]
}

// Compliance
export interface ComplianceRecord {
  checkKey: string
  tier: string
  score: number
  applicable: boolean
  subjectId: string
  foundValue: string
  expected: string
  detail: string
}

export interface NTIAElement {
  elementName: string
  compliant: boolean
  score: number
  failingComponents: string[]
  detail: string
}

export interface NTIAResult {
  standard: string
  overallCompliant: boolean
  overallScore: number
  elements: NTIAElement[]
}

export interface BSIResult {
  standard: string
  overallScore: number
  compliant: boolean
  requiredPassed: number
  requiredTotal: number
  additionalPassed: number
  additionalTotal: number
  records: ComplianceRecord[]
}

export interface FSCTResult {
  standard: string
  overallScore: number
  rawScore?: number
  records: ComplianceRecord[]
}

export interface OCTResult {
  standard: string
  overallScore: number
  spdxOnlyFail: boolean
  records: ComplianceRecord[]
}

export interface ComplianceSummary {
  ntia?: NTIAResult
  bsiV21?: BSIResult
  fsct?: FSCTResult
  oct?: OCTResult
}

// Dependency graph
export interface DependencyGraph {
  nodes: string[]
  edges: string[][]
  primaryComponentRef?: string
  orphans: string[]
  isComplete: boolean
  maxDepth: number
}

// Policy
export interface PolicyRuleOutcome {
  ruleId: string
  description: string
  action: string
  triggered: boolean
  detail: string
}

export interface PolicyResult {
  overall: string
  outcomes: PolicyRuleOutcome[]
}

export interface ScanSummary {
  id: string
  filename: string
  sbomFormat: string
  formatVersion?: string
  createdAt: string
  riskLevel: string
  riskScore: number
  totalComponents: number
  vulnerableComponents: number
  invalidComponents: number
  ntiaCompliant: boolean
  vulnCheckEnabled: boolean
  summary: Record<string, unknown>
  qualityScore?: number
  qualityGrade?: string
}

export interface ProfileFeature {
  key: string
  score?: number | null
  applicable: boolean
  weight: number
  detail: string
}

export interface ProfileScore {
  profileName: string
  profileScore: number
  grade: string
  features: ProfileFeature[]
}

export interface ScanDetail extends ScanSummary {
  components: Component[]
  validationIssues: ValidationIssue[]
  quality?: QualityScore
  compliance?: ComplianceSummary
  dependencyGraph?: DependencyGraph
  policyResult?: PolicyResult
  profileScore?: ProfileScore
}

export interface ScanListResponse {
  items: ScanSummary[]
  total: number
  page: number
  perPage: number
}

// Diff
export interface ScanDiff {
  scanIdA: string
  scanIdB: string
  filenameA: string
  filenameB: string
  scoreDelta: number
  added: Record<string, unknown>[]
  removed: Record<string, unknown>[]
  versionChanged: Record<string, unknown>[]
  newVulnerabilities: Record<string, unknown>[]
  resolvedVulnerabilities: Record<string, unknown>[]
}

// Component search
export interface ComponentSearchResult {
  componentId: string
  scanId: string
  scanFilename: string
  scanDate: string
  name: string
  version?: string
  purl?: string
  riskLevel: string
  riskScore: number
  vulnCount: number
}

export interface ComponentSearchResponse {
  query: string
  results: ComponentSearchResult[]
  total: number
}

// Analytics
export interface WorkspaceAnalytics {
  workspaceId: string
  totalScans: number
  avgQualityScore?: number
  avgRiskScore: number
  ntiaPassRate: number
  riskDistribution: Record<string, number>
  scoreTrend: { date: string; riskScore: number; qualityScore?: number }[]
  topVulnerabilities: { id: string; count: number }[]
}

// Policy YAML
export interface PolicyConfig {
  id: string
  workspaceId: string
  name: string
  policyYaml: string
  updatedAt: string
}

// Auth
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

export interface SiteSettings {
  authEnabled: boolean
  historyEnabled: boolean
  vulnCheckEnabled: boolean
}

// ---------------------------------------------------------------------------
// Axios instance
// ---------------------------------------------------------------------------

const apiClient = axios.create({
  baseURL: '/api/v1',
  headers: { 'Content-Type': 'application/json' },
})

function snakeToCamel(str: string): string {
  return str.replace(/_([a-z])/g, (_, l) => l.toUpperCase())
}

function transformKeys(obj: unknown): unknown {
  if (Array.isArray(obj)) return obj.map(transformKeys)
  if (obj !== null && typeof obj === 'object') {
    return Object.fromEntries(
      Object.entries(obj as Record<string, unknown>).map(([k, v]) => [
        snakeToCamel(k),
        transformKeys(v),
      ])
    )
  }
  return obj
}

apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

apiClient.interceptors.response.use(
  (response) => {
    if (response.config.responseType !== 'blob') {
      response.data = transformKeys(response.data)
    }
    return response
  },
  (error) => {
    const isAuthEndpoint = error.config?.url?.includes('/auth/login') ||
      error.config?.url?.includes('/auth/register')
    if (error.response?.status === 401 && !isAuthEndpoint) {
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
    formData.append('run_compliance', String(opts.runCompliance ?? true))
    if (opts.workspaceId) formData.append('workspace_id', opts.workspaceId)
    if (opts.profile) formData.append('profile', opts.profile)
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

  compliance: async (id: string): Promise<ComplianceSummary> => {
    const { data } = await apiClient.get<ComplianceSummary>(`/scans/${id}/compliance`)
    return data
  },

  diff: async (scanIdA: string, scanIdB: string): Promise<ScanDiff> => {
    const { data } = await apiClient.post<ScanDiff>('/scans/diff', {
      scan_id_a: scanIdA,
      scan_id_b: scanIdB,
    })
    return data
  },

  delete: async (id: string): Promise<void> => {
    await apiClient.delete(`/scans/${id}`)
  },

  exportJson: async (id: string): Promise<Blob> => {
    const { data } = await apiClient.get(`/scans/${id}/export/json`, { responseType: 'blob' })
    return data
  },

  exportPdf: async (id: string): Promise<Blob> => {
    const { data } = await apiClient.get(`/scans/${id}/export/pdf`, { responseType: 'blob' })
    return data
  },
}

export const components = {
  search: async (q: string, limit = 50): Promise<ComponentSearchResponse> => {
    const { data } = await apiClient.get<ComponentSearchResponse>('/components/search', {
      params: { q, limit },
    })
    return data
  },
}

export const auth = {
  login: async (email: string, password: string): Promise<TokenResponse> => {
    const { data } = await apiClient.post<TokenResponse>('/auth/login', { email, password })
    return data
  },

  register: async (email: string, password: string): Promise<UserResponse> => {
    const { data } = await apiClient.post<UserResponse>('/auth/register', { email, password })
    return data
  },

  me: async (): Promise<UserResponse> => {
    const { data } = await apiClient.get<UserResponse>('/auth/me')
    return data
  },

  changePassword: async (currentPassword: string, newPassword: string): Promise<void> => {
    await apiClient.post('/auth/change-password', {
      current_password: currentPassword,
      new_password: newPassword,
    })
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

  invite: async (workspaceId: string, email: string): Promise<{ inviteLink: string }> => {
    const { data } = await apiClient.post<{ inviteLink: string }>(
      `/workspaces/${workspaceId}/invite`,
      { email },
    )
    return data
  },

  analytics: async (workspaceId: string): Promise<WorkspaceAnalytics> => {
    const { data } = await apiClient.get<WorkspaceAnalytics>(`/workspaces/${workspaceId}/analytics`)
    return data
  },

  getPolicy: async (workspaceId: string): Promise<PolicyConfig> => {
    const { data } = await apiClient.get<PolicyConfig>(`/workspaces/${workspaceId}/policy`)
    return data
  },

  upsertPolicy: async (workspaceId: string, name: string, policyYaml: string): Promise<PolicyConfig> => {
    const { data } = await apiClient.put<PolicyConfig>(`/workspaces/${workspaceId}/policy`, {
      name,
      policy_yaml: policyYaml,
    })
    return data
  },

  deletePolicy: async (workspaceId: string): Promise<void> => {
    await apiClient.delete(`/workspaces/${workspaceId}/policy`)
  },
}

export const siteSettings = {
  get: async (): Promise<SiteSettings> => {
    const { data } = await apiClient.get<SiteSettings>('/settings')
    return data
  },

  update: async (
    patch: Partial<{ auth_enabled: boolean; history_enabled: boolean; vuln_check_enabled: boolean }>
  ): Promise<SiteSettings> => {
    const { data } = await apiClient.patch<SiteSettings>('/settings', patch)
    return data
  },
}

export const health = {
  get: async (): Promise<{ status: string; version: string; authEnabled: boolean }> => {
    const { data } = await apiClient.get('health')
    return data
  },
}

export default apiClient
