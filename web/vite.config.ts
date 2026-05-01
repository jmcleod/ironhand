import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";
import { componentTagger } from "lovable-tagger";

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => ({
  server: {
    host: "::",
    port: 8080,
    hmr: {
      overlay: false,
    },
  },
  plugins: [react(), mode === "development" && componentTagger()].filter(Boolean),
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes("node_modules")) {
            return undefined;
          }

          if (id.includes("/react/") || id.includes("/react-dom/") || id.includes("/react-router-dom/")) {
            return "react-vendor";
          }

          if (id.includes("/@radix-ui/")) {
            return "radix-ui";
          }

          if (id.includes("/@tanstack/")) {
            return "query-vendor";
          }

          if (id.includes("/lucide-react/")) {
            return "icons";
          }

          if (id.includes("/react-hook-form/") || id.includes("/@hookform/") || id.includes("/zod/")) {
            return "forms";
          }

          return "vendor";
        },
      },
    },
  },
}));
