import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import Settings from './Settings.vue'
import * as audit from '../api/audit.js'

vi.mock('../api/audit.js', () => ({
  getStoredApiKey: vi.fn(),
  setStoredApiKey: vi.fn(),
  clearStoredApiKey: vi.fn(),
}))

describe('Settings', () => {
  beforeEach(() => {
    vi.mocked(audit.getStoredApiKey).mockReturnValue('')
  })

  it('renders Settings title and OpenAI API key label', () => {
    const wrapper = mount(Settings)
    expect(wrapper.text()).toContain('Settings')
    expect(wrapper.text()).toContain('OpenAI API key')
  })

  it('shows placeholder sk-... on input', () => {
    const wrapper = mount(Settings)
    const input = wrapper.find('#apiKey')
    expect(input.attributes('placeholder')).toBe('sk-...')
  })

  it('calls setStoredApiKey when Save clicked with key and saveForSession checked', async () => {
    const wrapper = mount(Settings)
    await wrapper.find('#apiKey').setValue('sk-test')
    await wrapper.find('#saveSession').setValue(true)
    await wrapper.find('button').trigger('click')
    expect(audit.setStoredApiKey).toHaveBeenCalledWith('sk-test')
  })

  it('calls clearStoredApiKey when Clear stored key clicked', async () => {
    const wrapper = mount(Settings)
    const buttons = wrapper.findAll('button')
    const clearBtn = buttons.find(b => b.text().includes('Clear'))
    await clearBtn.trigger('click')
    expect(audit.clearStoredApiKey).toHaveBeenCalled()
  })
})
