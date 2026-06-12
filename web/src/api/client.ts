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
  role: 'admin' | 'user'
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
  role: 'admin' | 'user'
  createdAt: string
}

export const userApi = {
  list: (): Promise<UserRecord[]> =>
    api.get('/users').then((r) => r.data),
  create: (username: string, password: string, role: 'admin' | 'user'): Promise<void> =>
    api.post('/users', { username, password, role }),
  delete: (username: string): Promise<void> =>
    api.delete(`/users/${username}`),
  changePassword: (username: string, password: string): Promise<void> =>
    api.put(`/users/${username}/password`, { password }),
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

