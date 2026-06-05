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

