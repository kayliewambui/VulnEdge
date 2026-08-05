/**
 * Deterministic PRNG.
 *
 * The console must produce the *same* findings for the same target every run —
 * otherwise a retest would show phantom "fixes" caused by nothing but a fresh
 * `Math.random()`. Everything the engine synthesises is therefore derived from
 * a seed hashed off the target string.
 */

/** FNV-1a — small, fast, good enough avalanche for seeding. */
export function hashSeed(input: string): number {
  let h = 0x811c9dc5
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i)
    h = Math.imul(h, 0x01000193)
  }
  return h >>> 0
}

export interface Rng {
  /** Float in [0, 1). */
  next(): number
  /** Integer in [min, max] inclusive. */
  int(min: number, max: number): number
  /** Float in [min, max). */
  float(min: number, max: number): number
  /** True with the given probability. */
  chance(probability: number): boolean
  /** Uniform pick. */
  pick<T>(items: readonly T[]): T
  /** `count` distinct items (or the whole list if it is shorter). */
  sample<T>(items: readonly T[], count: number): T[]
  /** Fisher–Yates shuffle of a copy. */
  shuffle<T>(items: readonly T[]): T[]
}

/** mulberry32 — 32-bit state, well-distributed, trivially reproducible. */
export function createRng(seed: string | number): Rng {
  let state = (typeof seed === "string" ? hashSeed(seed) : seed) >>> 0

  const next = () => {
    state = (state + 0x6d2b79f5) >>> 0
    let t = state
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }

  const rng: Rng = {
    next,
    int: (min, max) => Math.floor(next() * (max - min + 1)) + min,
    float: (min, max) => next() * (max - min) + min,
    chance: (probability) => next() < probability,
    pick: (items) => items[Math.floor(next() * items.length)],
    shuffle: (items) => {
      const copy = [...items]
      for (let i = copy.length - 1; i > 0; i--) {
        const j = Math.floor(next() * (i + 1))
        ;[copy[i], copy[j]] = [copy[j], copy[i]]
      }
      return copy
    },
    sample: (items, count) => rng.shuffle(items).slice(0, Math.min(count, items.length)),
  }

  return rng
}
