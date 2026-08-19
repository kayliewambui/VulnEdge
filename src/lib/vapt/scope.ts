/**
 * Declared in-scope assets for this VulnEdge instance.
 *
 * These are always sent with the Rules of Engagement and merged into the
 * bridge SCOPE_ALLOWLIST so either asset can be assessed without a per-scan
 * scope edit.
 */
export const ENGAGEMENT_SCOPE: readonly string[] = [
  "cecureintel.com",
  "https://soc-scalable-infra-nlb-3d0f3e0030cc246e.elb.us-east-1.amazonaws.com/",
]
