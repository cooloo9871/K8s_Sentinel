import axios from 'axios'
import type { PolicyRecord, CreatePolicyPayload, Mode } from './types'

const api = axios.create({ baseURL: '/api', withCredentials: true })

api.interceptors.response.use(
  (res) => res,
  (err) => Promise.reject(err)
)

export const policyApi = {
  list: (): Promise<PolicyRecord[]> =>
    api.get('/policies').then((r) => r.data),

  get: (name: string, namespace?: string): Promise<PolicyRecord> =>
    api.get(`/policies/${name}`, { params: { namespace } }).then((r) => r.data),

  create: (payload: CreatePolicyPayload): Promise<void> =>
    api.post('/policies', payload),

  update: (name: string, payload: CreatePolicyPayload): Promise<void> =>
    api.put(`/policies/${name}`, payload),

  delete: (name: string, namespace?: string): Promise<void> =>
    api.delete(`/policies/${name}`, { params: { namespace } }),

  setMode: (name: string, namespace: string | undefined, mode: 'Monitoring' | 'Protect'): Promise<void> =>
    api.put(`/policies/${name}/mode`, { mode }, { params: { namespace } }),

  preview: (form: CreatePolicyPayload): Promise<string> =>
    api.post('/policies/preview', form).then((r) => r.data.yaml),
}

export const modeApi = {
  get: (): Promise<Mode> => api.get('/mode').then((r) => r.data.mode),
  set: (mode: 'Monitoring' | 'Protect'): Promise<void> =>
    api.put('/mode', { mode }),
}

export const namespaceApi = {
  list: (): Promise<string[]> => api.get('/namespaces').then((r) => r.data),
}

export const podApi = {
  labels: (namespace: string, pod: string): Promise<{ labels: Record<string, string> }> =>
    api.get(`/pods/${namespace}/${pod}/labels`).then((r) => r.data),
}

export interface CustomTemplatePayload {
  id: string
  name: string
  description?: string
  tags?: string[]
  yaml: string
}

export interface AuthUser {
  username: string
  role: 'admin' | 'viewer'
}

export const authApi = {
  login: (username: string, password: string): Promise<AuthUser> =>
    api.post('/auth/login', { username, password }).then((r) => r.data),
  logout: (): Promise<void> =>
    api.post('/auth/logout'),
  me: (): Promise<AuthUser> =>
    api.get('/auth/me').then((r) => r.data),
}

export interface UserRecord {
  username: string
  role: 'admin' | 'viewer'
  createdAt: string
}

export const userApi = {
  list: (): Promise<UserRecord[]> =>
    api.get('/users').then((r) => r.data),
  create: (username: string, password: string, role: 'admin' | 'viewer'): Promise<void> =>
    api.post('/users', { username, password, role }),
  delete: (username: string): Promise<void> =>
    api.delete(`/users/${username}`),
  changePassword: (username: string, password: string): Promise<void> =>
    api.put(`/users/${username}/password`, { password }),
}

export interface AlertRule {
  id: string
  name: string
  webhookURL: string
  eventTypes: string[]   // ["security","admission"], empty = all
  severities: string[]   // ["warning","critical"], empty = all
  namespaces: string[]   // empty = all
  policies: string[]     // empty = all
  cooldownMin: number    // 0 = no cooldown
  enabled: boolean
}

export interface RsyslogConfig {
  id: string
  name: string
  host: string
  port: number
  protocol: 'udp' | 'tcp'
  facility: number        // 16=local0 … 23=local7
  eventTypes: string[]   // ["security","admission"], empty = all
  severities: string[]   // ["warning","critical"], empty = all
  namespaces: string[]
  policies: string[]
  enabled: boolean
}

export const rsyslogApi = {
  list: (): Promise<RsyslogConfig[]> =>
    api.get('/rsyslog').then((r) => r.data ?? []),
  create: (cfg: Omit<RsyslogConfig, 'id'>): Promise<RsyslogConfig> =>
    api.post('/rsyslog', cfg).then((r) => r.data),
  update: (id: string, cfg: RsyslogConfig): Promise<RsyslogConfig> =>
    api.put(`/rsyslog/${id}`, cfg).then((r) => r.data),
  delete: (id: string): Promise<void> =>
    api.delete(`/rsyslog/${id}`),
  test: (cfg: Partial<RsyslogConfig>): Promise<{ message: string }> =>
    api.post('/rsyslog/test', cfg, { timeout: 6000 }).then((r) => r.data),
}

export const alertsApi = {
  list: (): Promise<AlertRule[]> =>
    api.get('/alerts').then((r) => r.data ?? []),
  create: (rule: Omit<AlertRule, 'id'>): Promise<AlertRule> =>
    api.post('/alerts', rule).then((r) => r.data),
  update: (id: string, rule: AlertRule): Promise<AlertRule> =>
    api.put(`/alerts/${id}`, rule).then((r) => r.data),
  delete: (id: string): Promise<void> =>
    api.delete(`/alerts/${id}`),
  test: (webhookURL: string): Promise<void> =>
    api.post('/alerts/test', { webhookURL }),
}

export interface VAPRecord {
  name: string
  namespace: string
  failurePolicy: string
  validationCount: number
  createdBy: string
  createdAt: string
  rawYaml: string
}

export interface VAPBindingRecord {
  name: string
  namespace: string
  policyName: string
  validationActions: string[]
  createdBy: string
  createdAt: string
  rawYaml: string
}

export interface AdmissionEvent {
  id: string
  time: string
  count: number
  namespace: string
  // from K8s Events watcher
  involvedKind: string
  involvedName: string
  // from webhook (direct creates)
  resource: string
  name: string
  operation: string
  username: string
  // common
  policyName: string
  bindingName: string
  message: string
  severity: 'critical' | 'warning'
  source: 'audit' | 'k8s-event'
  rawMessage?: string
}

export const admissionApi = {
  list: (): Promise<AdmissionEvent[]> =>
    api.get('/admission-events').then((r) => r.data ?? []),
}


export interface AdmissionRule {
  id: string
  name: string
  description?: string
  enabled: boolean
  createdAt: string
  spec: {
    matchConstraints: {
      resourceRules: Array<{
        apiGroups: string[]
        apiVersions: string[]
        operations: string[]
        resources: string[]
      }>
    }
    validations: Array<{ expression: string; message: string }>
  }
}

export const admissionRulesApi = {
  list: (): Promise<AdmissionRule[]> =>
    api.get('/admission-rules').then((r) => r.data ?? []),
  create: (payload: object): Promise<AdmissionRule> =>
    api.post('/admission-rules', payload).then((r) => r.data),
  update: (id: string, payload: object): Promise<AdmissionRule> =>
    api.put(`/admission-rules/${id}`, payload).then((r) => r.data),
  toggle: (id: string, enabled: boolean): Promise<void> =>
    api.patch(`/admission-rules/${id}/toggle?enabled=${enabled}`),
  delete: (id: string): Promise<void> =>
    api.delete(`/admission-rules/${id}`),
}

export const vapApi = {
  listPolicies: (): Promise<VAPRecord[]> =>
    api.get('/vap').then((r) => r.data),
  getPolicy: (name: string): Promise<VAPRecord> =>
    api.get(`/vap/${name}`).then((r) => r.data),
  applyPolicy: (rawYaml: string): Promise<void> =>
    api.post('/vap', { rawYaml }),
  updatePolicy: (name: string, rawYaml: string): Promise<void> =>
    api.put(`/vap/${name}`, { rawYaml }),
  deletePolicy: (name: string): Promise<void> =>
    api.delete(`/vap/${name}`),
  listBindings: (): Promise<VAPBindingRecord[]> =>
    api.get('/vap-bindings').then((r) => r.data),
  getBinding: (name: string): Promise<VAPBindingRecord> =>
    api.get(`/vap-bindings/${name}`).then((r) => r.data),
  applyBinding: (rawYaml: string): Promise<void> =>
    api.post('/vap-bindings', { rawYaml }),
  updateBinding: (name: string, rawYaml: string): Promise<void> =>
    api.put(`/vap-bindings/${name}`, { rawYaml }),
  deleteBinding: (name: string): Promise<void> =>
    api.delete(`/vap-bindings/${name}`),
}

export const clusterApi = {
  cidr: (): Promise<{ podCIDRs: string[]; serviceCIDRs: string[]; nodeIPs: string[] }> =>
    api.get('/cluster/cidr').then((r) => r.data),
}

export const settingsApi = {
  getSessionTTL: (): Promise<{ sessionTTL: number }> =>
    api.get('/settings/session-ttl').then((r) => r.data),
  setSessionTTL: (seconds: number): Promise<void> =>
    api.put('/settings/session-ttl', { sessionTTL: seconds }),
}

export interface SecurityRetention {
  maxWarnings: number
  maxCriticals: number
  ttlDays: number
}

export const securityRetentionApi = {
  get: (): Promise<SecurityRetention> =>
    api.get('/security-events/retention').then((r) => r.data),
  set: (cfg: SecurityRetention): Promise<SecurityRetention> =>
    api.put('/security-events/retention', cfg).then((r) => r.data),
}

export interface AdmissionRetention {
  maxEvents: number
}

export const admissionRetentionApi = {
  get: (): Promise<AdmissionRetention> =>
    api.get('/admission-events/retention').then((r) => r.data),
  set: (cfg: AdmissionRetention): Promise<AdmissionRetention> =>
    api.put('/admission-events/retention', cfg).then((r) => r.data),
}

export const templateApi = {
  list: (): Promise<{ templates: CustomTemplatePayload[] }> =>
    api.get('/templates').then((r) => r.data),
  create: (t: CustomTemplatePayload): Promise<CustomTemplatePayload> =>
    api.post('/templates', t).then((r) => r.data),
  update: (id: string, t: CustomTemplatePayload): Promise<CustomTemplatePayload> =>
    api.put(`/templates/${id}`, t).then((r) => r.data),
  delete: (id: string): Promise<void> =>
    api.delete(`/templates/${id}`),
}

