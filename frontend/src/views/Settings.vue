<template>
  <div>
    <h1 class="text-2xl font-semibold text-slate-800 mb-6">Settings</h1>

    <div class="bg-white rounded-lg shadow border border-slate-200 p-6 max-w-xl">
      <h2 class="text-lg font-medium text-slate-800 mb-4">API key</h2>
      <p class="text-sm text-slate-600 mb-4">
        Use your <strong>OpenAI API key</strong> (from <a href="https://platform.openai.com/api-keys" target="_blank" rel="noopener noreferrer" class="text-sky-600 hover:underline">platform.openai.com</a>). It is sent only in the request header (X-API-Key) and is never stored on the server. Optionally save for this browser session; it is cleared when you close the tab.
      </p>
      <label for="apiKey" class="block text-sm font-medium text-slate-700 mb-2">OpenAI API key</label>
      <input
        id="apiKey"
        v-model="apiKey"
        type="password"
        autocomplete="off"
        placeholder="sk-..."
        class="w-full rounded-md border border-slate-300 px-3 py-2 text-slate-900 placeholder-slate-400 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
      />
      <div class="mt-3 flex items-center gap-2">
        <input
          id="saveSession"
          v-model="saveForSession"
          type="checkbox"
          class="rounded border-slate-300 text-sky-600 focus:ring-sky-500"
        />
        <label for="saveSession" class="text-sm text-slate-700">Save for this session only</label>
      </div>
      <div class="mt-4 flex gap-3">
        <button
          type="button"
          @click="save"
          class="px-4 py-2 rounded-md bg-sky-600 text-white font-medium hover:bg-sky-700"
        >
          Save
        </button>
        <button
          type="button"
          @click="clear"
          class="px-4 py-2 rounded-md border border-slate-300 text-slate-700 hover:bg-slate-50"
        >
          Clear stored key
        </button>
      </div>
      <p v-if="saved" class="mt-3 text-sm text-green-600">Settings saved. Key is stored in this session only.</p>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { getStoredApiKey, setStoredApiKey, clearStoredApiKey } from '../api/audit'

const apiKey = ref('')
const saveForSession = ref(false)
const saved = ref(false)

onMounted(() => {
  apiKey.value = getStoredApiKey() ? '********' : ''
})

function save() {
  if (saveForSession.value && apiKey.value && apiKey.value !== '********') {
    setStoredApiKey(apiKey.value)
  } else if (!saveForSession.value) {
    clearStoredApiKey()
  }
  if (getStoredApiKey()) {
    apiKey.value = '********'
  }
  saved.value = true
  setTimeout(() => { saved.value = false }, 3000)
}

function clear() {
  clearStoredApiKey()
  apiKey.value = ''
  saved.value = false
}
</script>
