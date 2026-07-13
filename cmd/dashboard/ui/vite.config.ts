import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dashboard V2 SPA, embedded into the Go binary via go:embed (see
// cmd/dashboard/main.go). base: './' keeps every asset URL relative so the
// bundle works when served from any mount path (not just '/'), and nothing
// is ever loaded from a CDN at runtime — see DESIGN_BRIEF.md / CONTRACTS.md §6.
export default defineConfig({
  base: './',
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
        // SSE (/api/logs/all) needs the connection kept open, not buffered.
        ws: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
  },
})
