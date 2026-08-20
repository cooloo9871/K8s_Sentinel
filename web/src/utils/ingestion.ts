// Shared ingestion-health predicates, so the dashboard and the Event Sources
// page classify a source the same way and cannot drift apart.

export interface IngestSourceLike {
  connected: boolean
  consecutiveFailures: number
  lastError?: string
}

// "Cilium not detected" is a configuration fact, not a broken stream, so it is
// never an alarm — clusters without Cilium should not see a red banner.
export function isNotDetected(s: { lastError?: string }): boolean {
  return (s.lastError ?? '').toLowerCase().includes('not detected')
}

// A source is a problem worth surfacing only once a stream has actually failed
// (a real error or a failure streak), excluding the not-detected case. A source
// still coming up at startup — not connected yet, no failures, no error — is not
// a problem.
export function isIngestProblem(s: IngestSourceLike): boolean {
  return !s.connected && (s.consecutiveFailures > 0 || !!s.lastError) && !isNotDetected(s)
}
