import path from "path"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    host: true,
  },
  build: {
    rollupOptions: {
      output: {
        /**
         * The `home/ui` barrel re-exports the full shadcn set, so every
         * primitive lands in the graph. Split the vendor weight by library
         * family instead of shipping one monolithic chunk.
         */
        manualChunks(id) {
          if (!id.includes("node_modules")) return

          // jspdf only. html2canvas and dompurify are left unassigned so
          // Rollup keeps them as their own deferred chunks — jspdf imports
          // them lazily and a text-only report never pulls them down.
          if (id.includes("node_modules/jspdf")) return "pdf"

          if (id.includes("@radix-ui")) return "radix"

          if (
            id.includes("react-day-picker") ||
            id.includes("date-fns") ||
            id.includes("embla-carousel") ||
            id.includes("cmdk") ||
            id.includes("vaul") ||
            id.includes("react-resizable-panels")
          ) {
            return "widgets"
          }

          if (
            id.includes("react-hook-form") ||
            id.includes("@hookform") ||
            id.includes("node_modules/zod")
          ) {
            return "forms"
          }

          if (id.includes("lucide-react")) return "icons"
          if (id.includes("react-router")) return "router"

          // Exact package boundaries — a loose "/react/" match also catches
          // nested copies and creates a circular chunk reference.
          if (
            id.includes("node_modules/react/") ||
            id.includes("node_modules/react-dom/") ||
            id.includes("node_modules/scheduler/")
          ) {
            return "react"
          }

          // Everything else falls through to Rollup's own grouping.
          return undefined
        },
      },
    },
  },
})
