const { defineConfig } = require('vite');
const react = require('@vitejs/plugin-react');

module.exports = defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { '/api': 'http://localhost:3100' }
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true
  }
});
