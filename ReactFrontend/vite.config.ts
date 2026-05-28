import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  optimizeDeps: {
    exclude: ['lucide-react'],
  },
  server: {
    host: true, // Crucial: Tells Vite to listen to the network tunnel
    allowedHosts: [
      'localhost',
      '127.0.0.1',
      'swimming-irritate-rummage.ngrok-free.dev',
      'app.descg.store'
    ]
  }
});