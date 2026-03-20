const API_BASE = import.meta.env.DEV ? '/api' : (import.meta.env.VITE_API_BASE || '/api')

const STORAGE_KEY = 'security_orchestrator_api_key'

export function getStoredApiKey() {
  try {
    return sessionStorage.getItem(STORAGE_KEY) || ''
  } catch {
    return ''
  }
}

export function setStoredApiKey(value) {
  try {
    if (value && value.trim()) {
      sessionStorage.setItem(STORAGE_KEY, value.trim())
    } else {
      sessionStorage.removeItem(STORAGE_KEY)
    }
  } catch {}
}

export function clearStoredApiKey() {
  try {
    sessionStorage.removeItem(STORAGE_KEY)
  } catch {}
}

export async function runAudit(target, apiKey) {
  const res = await fetch(`${API_BASE}/v1/audit`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': apiKey || getStoredApiKey() || '',
    },
    body: JSON.stringify({ target: target.trim() }),
  })

  const text = await res.text()
  let json = null
  try { json = text ? JSON.parse(text) : null } catch {}

  if (res.status === 401) {
    throw new Error(json?.error || text || 'Missing or invalid API key. Add it in Settings.')
  }
  if (res.status === 429) {
    throw new Error(json?.error || 'Too many requests. Try again in a minute.')
  }
  if (!res.ok) {
    const msg = json?.error || json?.report?.remediationSteps || text || `Request failed: ${res.status}`
    throw new Error(msg)
  }

  return json
}
