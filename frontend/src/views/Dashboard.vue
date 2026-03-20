<template>
  <div>
    <h1 class="text-2xl font-semibold text-slate-800 mb-6">Run security audit</h1>

    <div class="bg-white rounded-lg shadow border border-slate-200 p-6 mb-6">
      <label for="target" class="block text-sm font-medium text-slate-700 mb-2">GitHub repository URL</label>
      <div class="flex gap-3">
        <input
          id="target"
          v-model="target"
          type="text"
          placeholder="https://github.com/org/repo"
          class="flex-1 rounded-md border border-slate-300 px-3 py-2 text-slate-900 placeholder-slate-400 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
        />
        <button
          type="button"
          :disabled="loading || !target.trim()"
          @click="runAudit"
          class="px-4 py-2 rounded-md bg-sky-600 text-white font-medium hover:bg-sky-700 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {{ loading ? 'Running…' : 'Run audit' }}
        </button>
      </div>
      <p v-if="!hasApiKey" class="mt-2 text-amber-600 text-sm">
        Add your API key in <router-link to="/settings" class="underline">Settings</router-link> to run audits.
      </p>
      <p v-if="hasApiKey && !response" class="mt-2 text-slate-500 text-sm">
        Audits may take 1–2 minutes for large repositories.
      </p>
    </div>

    <div v-if="error" class="bg-red-50 border border-red-200 text-red-800 rounded-lg p-4 mb-6">
      {{ error }}
    </div>

    <div v-if="response" class="space-y-6">
      <div v-if="response.auditSteps && response.auditSteps.length" class="bg-white rounded-lg shadow border border-slate-200 overflow-hidden">
        <div class="px-6 py-4 border-b border-slate-200 bg-slate-50">
          <h2 class="text-lg font-medium text-slate-800">Audit steps</h2>
          <p class="text-sm text-slate-600 mt-0.5">Tools that ran during this audit.</p>
        </div>
        <div class="divide-y divide-slate-100">
          <div v-for="(step, i) in response.auditSteps" :key="i" class="px-6 py-4" :class="stepBorderClass(step.toolName)">
            <div class="flex items-center gap-3 flex-wrap">
              <span class="inline-flex items-center justify-center w-8 h-8 rounded-full bg-slate-200 text-slate-600 text-sm font-medium">{{ i + 1 }}</span>
              <div class="flex-1 min-w-0">
                <p class="font-medium text-slate-800">{{ stepLabel(step.toolName) }}</p>
                <p v-if="step.arguments" class="text-sm text-slate-500 mt-0.5 truncate" :title="step.arguments">{{ formatStepInput(step) }}</p>
              </div>
              <span :class="stepStatusClass(step.result)" class="text-xs font-medium px-2 py-1 rounded-full">{{ stepStatus(step.result) }}</span>
            </div>
            <div class="mt-3 pl-11">
              <template v-if="step.findings && step.findings.length">
                <div class="text-sm text-slate-700 mb-2">{{ step.findings.length }} finding{{ step.findings.length !== 1 ? 's' : '' }} {{ findingsSourceLabel(step.toolName) }}</div>
                <div class="space-y-3 mb-3">
                  <div v-for="(f, fi) in step.findings" :key="fi" class="text-sm bg-white rounded-lg p-3 border border-slate-200 shadow-sm">
                    <div class="flex flex-wrap items-center gap-2 mb-1">
                      <span class="font-medium text-slate-800 truncate" :title="f.path">{{ formatFindingPath(f.path) }}</span>
                      <span v-if="f.line" class="text-xs text-slate-500 shrink-0">L{{ f.line }}{{ f.col != null ? ':' + f.col : '' }}</span>
                      <span v-if="f.severity" :class="severityClass(f.severity)" class="text-xs font-medium px-1.5 py-0.5 rounded">{{ f.severity }}</span>
                    </div>
                    <p v-if="f.message" class="text-slate-600 mt-1">{{ f.message }}</p>
                    <div v-if="(f.cwe && f.cwe.length) || (f.owasp && f.owasp.length)" class="flex flex-wrap gap-1 mt-2">
                      <template v-for="(c, ci) in (f.cwe || [])" :key="'cwe-' + ci">
                        <span class="text-xs bg-rose-50 text-rose-700 px-1.5 py-0.5 rounded">{{ c }}</span>
                      </template>
                      <template v-for="(o, oi) in (f.owasp || [])" :key="'owasp-' + oi">
                        <span class="text-xs bg-amber-50 text-amber-700 px-1.5 py-0.5 rounded">{{ o }}</span>
                      </template>
                    </div>
                    <p v-if="f.checkId" class="text-xs text-slate-400 mt-1 truncate" :title="f.checkId">Rule: {{ f.checkId }}</p>
                  </div>
                </div>
                <button v-if="step.result" type="button" @click="toggledRaw[i] = !toggledRaw[i]" class="text-xs text-sky-600 hover:underline">
                  {{ toggledRaw[i] ? 'Hide raw output' : 'Show raw output' }}
                </button>
                <pre v-if="step.result && toggledRaw[i]" class="mt-2 text-xs text-slate-600 bg-slate-100 p-3 rounded overflow-x-auto whitespace-pre-wrap max-h-48 overflow-y-auto">{{ step.result }}</pre>
              </template>
              <template v-else-if="parsedStepResult(step)">
                <div v-if="parsedStepResult(step).summary" class="text-sm text-slate-700 mb-2">{{ parsedStepResult(step).summary }}</div>
                <div v-if="parsedStepResult(step).findings && parsedStepResult(step).findings.length" class="space-y-3 mb-3">
                  <div v-for="(f, fi) in parsedStepResult(step).findings" :key="fi" class="text-sm bg-white rounded-lg p-3 border border-slate-200 shadow-sm">
                    <div class="flex flex-wrap items-center gap-2 mb-1">
                      <span class="font-medium text-slate-800 truncate" :title="f.path">{{ formatFindingPath(f.path) }}</span>
                      <span v-if="f.line" class="text-xs text-slate-500 shrink-0">L{{ f.line }}{{ f.col != null ? ':' + f.col : '' }}</span>
                      <span v-if="f.severity" :class="severityClass(f.severity)" class="text-xs font-medium px-1.5 py-0.5 rounded">{{ f.severity }}</span>
                    </div>
                    <p v-if="f.message" class="text-slate-600 mt-1">{{ f.message }}</p>
                    <div v-if="(f.cwe && f.cwe.length) || (f.owasp && f.owasp.length)" class="flex flex-wrap gap-1 mt-2">
                      <template v-for="(c, ci) in (f.cwe || [])" :key="'cwe-' + ci">
                        <span class="text-xs bg-rose-50 text-rose-700 px-1.5 py-0.5 rounded">{{ c }}</span>
                      </template>
                      <template v-for="(o, oi) in (f.owasp || [])" :key="'owasp-' + oi">
                        <span class="text-xs bg-amber-50 text-amber-700 px-1.5 py-0.5 rounded">{{ o }}</span>
                      </template>
                    </div>
                    <p v-if="f.check_id" class="text-xs text-slate-400 mt-1 truncate" :title="f.check_id">Rule: {{ f.check_id }}</p>
                  </div>
                </div>
                <button v-if="parsedStepResult(step).hasRaw" type="button" @click="toggledRaw[i] = !toggledRaw[i]" class="text-xs text-sky-600 hover:underline">
                  {{ toggledRaw[i] ? 'Hide raw output' : 'Show raw output' }}
                </button>
                <pre v-if="parsedStepResult(step).hasRaw && toggledRaw[i]" class="mt-2 text-xs text-slate-600 bg-slate-100 p-3 rounded overflow-x-auto whitespace-pre-wrap max-h-48 overflow-y-auto">{{ step.result }}</pre>
              </template>
              <template v-else>
                <p class="text-sm text-slate-700 whitespace-pre-wrap">{{ step.result || '(no output)' }}</p>
              </template>
            </div>
          </div>
        </div>
      </div>

      <div class="bg-white rounded-lg shadow border border-slate-200 overflow-hidden">
        <div class="px-6 py-4 border-b border-slate-200 bg-slate-50">
          <h2 class="text-lg font-medium text-slate-800">Report</h2>
        </div>
        <div class="p-6 space-y-6">
          <div>
            <span class="text-sm font-medium text-slate-500">Vulnerability score</span>
            <p class="text-2xl font-semibold" :class="scoreClass">{{ report.vulnerabilityScore }} / 100</p>
          </div>
          <div v-if="report.affectedFiles && report.affectedFiles.length">
            <span class="text-sm font-medium text-slate-500">Affected files</span>
            <ul class="mt-1 list-disc list-inside text-slate-700 space-y-0.5">
              <li v-for="(f, i) in report.affectedFiles" :key="i">{{ f }}</li>
            </ul>
          </div>
          <div v-if="report.remediationSteps">
            <span class="text-sm font-medium text-slate-500">Remediation</span>
            <p class="mt-1 text-slate-700 whitespace-pre-wrap">{{ report.remediationSteps }}</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, watch } from 'vue'
import { runAudit as callAuditApi, getStoredApiKey } from '../api/audit'

const target = ref('')
const loading = ref(false)
const error = ref('')
const response = ref(null)
const toggledRaw = ref({})

const report = computed(() => response.value?.report || null)

const hasApiKey = computed(() => !!getStoredApiKey())

const scoreClass = computed(() => {
  if (!report.value) return ''
  const s = report.value.vulnerabilityScore
  if (s >= 70) return 'text-red-600'
  if (s >= 40) return 'text-amber-600'
  return 'text-green-600'
})

function stepLabel(toolName) {
  const labels = {
    cloneRepo: 'Clone repository',
    runStaticScan: 'Static scan (Semgrep)',
    runSecretScan: 'Secret scan (Gitleaks)',
    runSCAScan: 'Dependency scan (SCA)'
  }
  return labels[toolName] || toolName
}

function findingsSourceLabel(toolName) {
  const sources = {
    runStaticScan: 'from Semgrep.',
    runSecretScan: 'from Gitleaks.',
    runSCAScan: 'from SCA.'
  }
  return sources[toolName] || 'from scan.'
}

function stepBorderClass(toolName) {
  const borders = {
    cloneRepo: 'border-l-4 border-l-slate-300',
    runStaticScan: 'border-l-4 border-l-sky-400',
    runSecretScan: 'border-l-4 border-l-violet-400',
    runSCAScan: 'border-l-4 border-l-amber-400'
  }
  return borders[toolName] || ''
}

function formatStepInput(step) {
  if (!step.arguments) return ''
  try {
    const o = JSON.parse(step.arguments)
    if (o.repoUrl) return `Repository: ${o.repoUrl}`
    if (o.localPath) return `Path: ${o.localPath}`
    return step.arguments
  } catch {
    return step.arguments
  }
}

function stepStatus(result) {
  if (!result) return '—'
  const r = (result || '').toLowerCase()
  if (r.includes('sca skipped')) return 'Success'
  if (r.includes('error') || r.includes('failed') || r.includes('TOOL_UNAVAILABLE')) return 'Error'
  if (r.includes('cloned successfully') || r.includes('no findings') || r.includes('Semgrep finished') || r.includes('no secrets found') || r.includes('no vulnerable dependencies')) return 'Success'
  if (r.includes('Semgrep findings') || r.includes('"results":') || r.includes('secret(s) found') || r.includes('vulnerable dependency')) return 'Findings'
  return 'Done'
}

function stepStatusClass(result) {
  const status = stepStatus(result)
  if (status === 'Error') return 'bg-red-100 text-red-700'
  if (status === 'Success' || status === 'Done') return 'bg-emerald-100 text-emerald-700'
  return 'bg-amber-100 text-amber-700'
}

function normalizeSemgrepResult(str) {
  return str.replace(/^Semgrep\s*\(exit\s*\d+\)\s*:?\s*/im, '').trim()
}

function skipJsonString(str, from) {
  if (str[from] !== '"') return from
  for (let i = from + 1; i < str.length; i++) {
    if (str[i] === '\\') {
      i++
      continue
    }
    if (str[i] === '"') return i + 1
  }
  return -1
}

function extractJsonObject(str) {
  const start = str.indexOf('{')
  if (start < 0) return null
  let depth = 0
  for (let i = start; i < str.length; i++) {
    if (str[i] === '"') {
      const next = skipJsonString(str, i)
      if (next < 0) return null
      i = next - 1
      continue
    }
    if (str[i] === '{') depth++
    else if (str[i] === '}') {
      depth--
      if (depth === 0) return str.slice(start, i + 1)
    }
  }
  return null
}

function extractResultsArray(str) {
  const match = str.match(/"results"\s*:\s*\[/)
  if (!match) return null
  const arrayStart = str.indexOf('[', match.index)
  if (arrayStart < 0) return null
  let depth = 0
  for (let i = arrayStart; i < str.length; i++) {
    if (str[i] === '"') {
      const next = skipJsonString(str, i)
      if (next < 0) return null
      i = next - 1
      continue
    }
    if (str[i] === '[') depth++
    else if (str[i] === ']') {
      depth--
      if (depth === 0) {
        const arrayStr = str.slice(arrayStart, i + 1)
        try {
          return JSON.parse(arrayStr)
        } catch {
          return null
        }
      }
    }
  }
  return null
}

function mapResultsToFindings(results) {
  return (results || []).slice(0, 25).map(x => {
    const extra = x.extra || {}
    const meta = extra.metadata || {}
    return {
      path: x.path,
      check_id: x.check_id,
      message: extra.message || x.message,
      severity: x.severity || meta.severity,
      line: x.start?.line,
      col: x.start?.col,
      cwe: meta.cwe ? (Array.isArray(meta.cwe) ? meta.cwe : [meta.cwe]) : null,
      owasp: meta.owasp ? (Array.isArray(meta.owasp) ? meta.owasp : [meta.owasp]) : null
    }
  })
}

function formatFindingPath(path) {
  if (!path) return '—'
  const parts = path.replace(/\\/g, '/').split('/')
  return parts.length > 2 ? parts.slice(-2).join('/') : path
}

function severityClass(severity) {
  const s = (severity || '').toUpperCase()
  if (s === 'ERROR' || s === 'CRITICAL') return 'bg-red-100 text-red-700'
  if (s === 'WARNING') return 'bg-amber-100 text-amber-700'
  if (s === 'SECRET') return 'bg-violet-100 text-violet-700'
  if (s === 'HIGH' || s === 'MODERATE') return 'bg-orange-100 text-orange-700'
  return 'bg-slate-100 text-slate-600'
}

function parsedStepResult(step) {
  const r = step.result || ''
  if (!r) return null
  if (step.toolName === 'cloneRepo') {
    return { summary: r.trim(), findings: [], hasRaw: false }
  }
  if (step.toolName === 'runStaticScan') {
    const normalized = normalizeSemgrepResult(r)
    let results = []

    const jsonStr = extractJsonObject(normalized)
    if (jsonStr) {
      try {
        const obj = JSON.parse(jsonStr)
        results = Array.isArray(obj.results) ? obj.results : []
      } catch {
        results = extractResultsArray(normalized) || extractResultsArray(r) || []
      }
    } else {
      results = extractResultsArray(normalized) || extractResultsArray(r) || []
    }

    if (results.length > 0 || normalized.startsWith('{')) {
      const findings = mapResultsToFindings(results)
      const summary = results.length === 0
        ? 'No issues found.'
        : `${results.length} finding${results.length !== 1 ? 's' : ''} from Semgrep.`
      return { summary, findings, hasRaw: true }
    }

    if (r.includes('Semgrep findings (')) {
      const lines = r.split('\n').filter(Boolean)
      const findings = lines.slice(1).map(line => {
        const pathMatch = line.match(/path=(\S+)/)
        const msgMatch = line.match(/message=(.+)/)
        return { path: pathMatch?.[1], check_id: line.match(/check_id=(\S+)/)?.[1], message: msgMatch?.[1]?.trim() }
      }).filter(f => f.path || f.message)
      return { summary: lines[0] || 'Semgrep scan completed.', findings, hasRaw: true }
    }
    if (r.startsWith('Semgrep (exit')) {
      const firstLine = r.split('\n')[0] || r
      return { summary: firstLine.length > 120 ? firstLine.slice(0, 120) + '…' : firstLine, findings: [], hasRaw: r.length > 200 }
    }
    return { summary: r.length > 300 ? r.slice(0, 300) + '…' : r, findings: [], hasRaw: r.length > 300 }
  }
  if (r.length > 400) return { summary: r.slice(0, 400) + '…', findings: [], hasRaw: true }
  return null
}

watch(response, () => { toggledRaw.value = {} }, { deep: true })

async function runAudit() {
  if (!target.value.trim()) return
  const key = getStoredApiKey()
  if (!key) {
    error.value = 'Add your API key in Settings first.'
    return
  }
  loading.value = true
  error.value = ''
  response.value = null
  try {
    response.value = await callAuditApi(target.value, key)
    const report = response.value?.report
    if (report?.remediationSteps?.startsWith('Audit failed:')) {
      error.value = report.remediationSteps
    } else {
      error.value = ''
    }
  } catch (e) {
    error.value = e.message || 'Audit failed.'
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  response.value = null
  error.value = ''
})
</script>
