import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"

/**
 * Merge conditional class names, resolving Tailwind conflicts so the
 * last-specified utility wins.
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}
