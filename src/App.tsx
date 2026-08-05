import { Suspense } from "react"
import { Route, Routes } from "react-router-dom"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { Shield } from "lucide-react"

import Home from "@/components/home"
import { Toaster } from "@/components/ui/toaster"
import { TooltipProvider } from "@/components/ui/tooltip"

// Long-running security scans: don't refetch aggressively, retry sparingly.
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 15_000,
    },
  },
})

function BootScreen() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-background">
      <div className="relative">
        <div className="pulse-ring absolute inset-0 rounded-full" />
        <Shield className="h-12 w-12 animate-pulse text-primary" />
      </div>
      <p className="font-mono text-sm text-muted-foreground">
        Initialising VulnEdge engine…
      </p>
    </div>
  )
}

function NotFound() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-3 bg-background">
      <p className="font-mono text-6xl font-bold gradient-text">404</p>
      <p className="text-muted-foreground">No such route on this console.</p>
      <a
        href="/"
        className="mt-2 rounded-md border border-primary/40 px-4 py-2 font-mono text-sm text-primary transition hover:bg-primary/10"
      >
        ← Return to console
      </a>
    </div>
  )
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider delayDuration={200}>
        <Suspense fallback={<BootScreen />}>
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </Suspense>
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  )
}
