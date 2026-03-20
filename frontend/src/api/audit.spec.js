import { describe, it, expect, vi, beforeEach } from 'vitest'
import { getStoredApiKey, setStoredApiKey, clearStoredApiKey, runAudit } from './audit.js'

describe('audit API', () => {
  const STORAGE_KEY = 'security_orchestrator_api_key'

  beforeEach(() => {
    vi.stubGlobal('sessionStorage', {
      getItem: vi.fn(),
      setItem: vi.fn(),
      removeItem: vi.fn(),
    })
    vi.stubGlobal('fetch', vi.fn())
  })

  describe('getStoredApiKey', () => {
    it('returns empty string when storage is empty', () => {
      sessionStorage.getItem.mockReturnValue(null)
      expect(getStoredApiKey()).toBe('')
    })
    it('returns stored value', () => {
      sessionStorage.getItem.mockReturnValue('sk-abc')
      expect(getStoredApiKey()).toBe('sk-abc')
    })
    it('returns empty string when getItem throws', () => {
      sessionStorage.getItem.mockImplementation(() => { throw new Error() })
      expect(getStoredApiKey()).toBe('')
    })
  })

  describe('setStoredApiKey', () => {
    it('sets key when value is non-empty', () => {
      setStoredApiKey('sk-xyz')
      expect(sessionStorage.setItem).toHaveBeenCalledWith(STORAGE_KEY, 'sk-xyz')
    })
    it('removes key when value is empty', () => {
      setStoredApiKey('')
      expect(sessionStorage.removeItem).toHaveBeenCalledWith(STORAGE_KEY)
    })
    it('removes key when value is blank', () => {
      setStoredApiKey('   ')
      expect(sessionStorage.removeItem).toHaveBeenCalledWith(STORAGE_KEY)
    })
  })

  describe('clearStoredApiKey', () => {
    it('removes key', () => {
      clearStoredApiKey()
      expect(sessionStorage.removeItem).toHaveBeenCalledWith(STORAGE_KEY)
    })
  })

  describe('runAudit', () => {
    it('throws on 401 with message', async () => {
      fetch.mockResolvedValue({
        status: 401,
        text: () => Promise.resolve(JSON.stringify({ error: 'Missing or invalid API key.', code: 'MISSING_API_KEY' })),
      })
      await expect(runAudit('https://github.com/a/b', '')).rejects.toThrow(/API key|Missing/)
    })
    it('throws on 429 with rate limit message', async () => {
      fetch.mockResolvedValue({
        status: 429,
        text: () => Promise.resolve(JSON.stringify({ error: 'Too many audit requests. Try again later.', code: 'RATE_LIMITED' })),
      })
      await expect(runAudit('https://github.com/x/y', 'sk-k')).rejects.toThrow(/Too many|minute/)
    })
    it('returns JSON on 200', async () => {
      const body = { report: { vulnerabilityScore: 0, affectedFiles: [], remediationSteps: 'ok' }, auditSteps: [] }
      fetch.mockResolvedValue({ ok: true, status: 200, text: () => Promise.resolve(JSON.stringify(body)) })
      const result = await runAudit('https://github.com/a/b', 'sk-key')
      expect(result).toEqual(body)
      expect(fetch).toHaveBeenCalledWith(expect.stringContaining('/v1/audit'), expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({ 'X-API-Key': 'sk-key', 'Content-Type': 'application/json' }),
        body: JSON.stringify({ target: 'https://github.com/a/b' }),
      }))
    })
    it('uses remediationSteps from JSON when !res.ok', async () => {
      const errBody = { report: { remediationSteps: 'Audit failed: custom error.' } }
      fetch.mockResolvedValue({
        ok: false,
        status: 500,
        text: () => Promise.resolve(JSON.stringify(errBody)),
      })
      await expect(runAudit('https://github.com/x/y', 'sk-k')).rejects.toThrow('Audit failed: custom error.')
    })
  })
})
