import { svelte } from '@sveltejs/vite-plugin-svelte'
import { defineConfig, loadEnv } from 'vite'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const backend = env.BACKEND_URL || 'http://127.0.0.1:8000'
  const proxy = {
    '^/v1/': backend,
    '^/admin/(policy|journal)(/|\\?|$)': backend,
  }

  return {
    plugins: [svelte()],
    server: { proxy },
    preview: { proxy },
  }
})
