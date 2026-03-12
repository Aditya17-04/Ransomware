import axios from 'axios'

const API = axios.create({ baseURL: '/api', timeout: 5000 })

export const getStatus    = () => API.get('/status').then(r => r.data)
export const getTelemetry = () => API.get('/telemetry').then(r => r.data)
export const getThreat    = () => API.get('/threat').then(r => r.data)
export const getAlerts    = () => API.get('/alerts').then(r => r.data)
export const getConfig    = () => API.get('/config').then(r => r.data)
export const getModel     = () => API.get('/model').then(r => r.data)
