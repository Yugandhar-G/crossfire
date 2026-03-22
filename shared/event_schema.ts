/**
 * Shared event schema -- the contract between proxy and dashboard.
 *
 * WARNING: This file must stay in sync with shared/event_schema.py.
 * Coordinate changes between Yugandhar (Python) and Ruthvik (TypeScript).
 */

export interface Threat {
  type: string;
  severity: "critical" | "high" | "medium" | "low";
  detail: string;
  pattern: string;
  gemini_analysis?: {
    is_threat: boolean;
    confidence: number;
    pattern: string | null;
    explanation: string;
  } | null;
}

/** One row from `crossfire scan` or `POST /api/scan`. */
export interface ScanFinding {
  tool_name: string;
  category: string;
  severity: string;
  detail: string;
  phase: string;
}

/** Full report after a scan completes (mirrors proxy.scanner.ScanReport). */
export interface ScanReport {
  scan_id: string;
  server_name: string;
  command: string;
  tools_found: string[];
  findings: ScanFinding[];
  scan_duration_ms: number;
  timestamp: string;
  error?: string | null;
}

export interface CrossfireEvent {
  id: string;
  timestamp: string;
  protocol: "mcp" | "a2a";
  direction: "request" | "response";
  server: string;
  method: string;
  params: Record<string, unknown>;
  threats: Threat[];
  severity: "critical" | "high" | "medium" | "low" | "clean";
  /** True when Guardian/config blocked the request (tools/call not forwarded). */
  blocked?: boolean | null;
  tools_discovered?: string[] | null;
  tool_poisoning?: Record<string, unknown>[] | null;
  sensitive_data?: Record<string, unknown>[] | null;
  chain_id?: string | null;
  /** Where the traffic originated: "ide", "sdk", "http-proxy", or "scan". */
  source?: "ide" | "sdk" | "http-proxy" | "scan" | null;
}
