<template>
  <div class="min-h-screen bg-slate-50">
    <nav class="bg-white border-b border-slate-200 shadow-sm">
      <div class="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="flex justify-between h-14">
          <div class="flex items-center gap-6">
            <router-link to="/" class="text-slate-800 font-semibold hover:text-slate-600">
              Security Orchestrator
            </router-link>
            <router-link
              to="/"
              class="text-slate-600 hover:text-slate-900 px-2 py-1 rounded text-sm"
              active-class="text-slate-900 font-medium bg-slate-100 rounded"
            >
              Dashboard
            </router-link>
            <router-link
              to="/settings"
              class="text-slate-600 hover:text-slate-900 px-2 py-1 rounded text-sm"
              active-class="text-slate-900 font-medium bg-slate-100 rounded"
            >
              Settings
            </router-link>
          </div>
        </div>
      </div>
    </nav>
    <main class="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <router-view />
    </main>
  </div>
</template>

<script setup>
</script>
