/**
 * Home-scoped UI barrel.
 *
 * The canonical shadcn/ui primitives live in `src/components/ui`. This module
 * re-exports the whole set so anything under `components/home` can import from
 * a single local path:
 *
 *   import { Card, Badge, Progress } from "@/components/home/ui"
 *
 * Re-exporting (rather than duplicating the files) keeps one source of truth,
 * so `npx shadcn@latest add <component>` updates stay in effect here too.
 */

export * from "@/components/ui/accordion"
export * from "@/components/ui/alert"
export * from "@/components/ui/alert-dialog"
export * from "@/components/ui/avatar"
export * from "@/components/ui/badge"
export * from "@/components/ui/button"
export * from "@/components/ui/calendar"
export * from "@/components/ui/card"
export * from "@/components/ui/carousel"
export * from "@/components/ui/checkbox"
export * from "@/components/ui/command"
export * from "@/components/ui/context-menu"
export * from "@/components/ui/dialog"
export * from "@/components/ui/drawer"
export * from "@/components/ui/dropdown-menu"
export * from "@/components/ui/form"
export * from "@/components/ui/hover-card"
export * from "@/components/ui/input"
export * from "@/components/ui/label"
export * from "@/components/ui/menubar"
export * from "@/components/ui/navigation-menu"
export * from "@/components/ui/pagination"
export * from "@/components/ui/popover"
export * from "@/components/ui/progress"
export * from "@/components/ui/radio-group"
export * from "@/components/ui/resizable"
export * from "@/components/ui/scroll-area"
export * from "@/components/ui/select"
export * from "@/components/ui/separator"
export * from "@/components/ui/sheet"
export * from "@/components/ui/skeleton"
export * from "@/components/ui/slider"
export * from "@/components/ui/switch"
export * from "@/components/ui/table"
export * from "@/components/ui/tabs"
export * from "@/components/ui/textarea"
export * from "@/components/ui/toast"
export * from "@/components/ui/toaster"
export * from "@/components/ui/toggle"
export * from "@/components/ui/tooltip"
export * from "@/components/ui/use-toast"
