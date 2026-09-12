// Pure helpers shared by the dashboard. Kept free of DOM and module-level
// state so they can be unit tested (see lib.test.ts) -- main.ts owns the
// rendering and the mutable `state`.

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type Alert = {
  id: string;
  alert_name: string;
  severity: Severity;
  status: string;
  source_ip?: string;
  honeypot_type?: string;
  service_name?: string;
  description?: string;
  first_seen?: string;
  last_seen?: string;
  created_at?: string;
  threat_score?: number;
  threat_level?: string;
  acknowledged?: boolean;
  metadata?: string | Record<string, unknown>;
};

export type Playbook = { id: string; name: string; description?: string };
export type ReplayEvent = { label: string; detail: string; source: string; time: string };

export const SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info'];

const ESCAPES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  "'": '&#39;',
  '"': '&quot;',
};

/**
 * Escape a value for interpolation into HTML.
 *
 * Everything this dashboard renders originates from attacker-controlled
 * honeypot traffic (usernames, commands, payload fragments), so every
 * interpolated value must pass through here.
 */
export function esc(value: unknown): string {
  return String(value ?? '').replace(/[&<>'"]/g, (char) => ESCAPES[char]!);
}

/**
 * Restrict a severity to the known vocabulary before it reaches a class
 * attribute. A malformed value would otherwise break out of the attribute.
 */
export function severityClass(severity?: string): string {
  const level = String(severity ?? '').toLowerCase();
  return `severity-${SEVERITY_LEVELS.includes(level) ? level : 'info'}`;
}

export function relativeTime(value?: string, now: number = Date.now()): string {
  if (!value) return 'unknown';
  const parsed = new Date(value).getTime();
  if (Number.isNaN(parsed)) return 'unknown';

  const seconds = Math.max(0, Math.floor((now - parsed) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  return `${Math.floor(seconds / 3600)}h ago`;
}

/** Alert metadata as an object, whether it arrives as JSON text or already parsed. */
export function metadata(alert: Alert): Record<string, unknown> {
  if (!alert.metadata) return {};
  if (typeof alert.metadata === 'object') return alert.metadata;
  try {
    const parsed = JSON.parse(alert.metadata) as unknown;
    return parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

export function filterAlerts(alerts: Alert[], severity: string, search: string): Alert[] {
  const query = search.toLowerCase();
  return alerts.filter((alert) => {
    const matchesSeverity = severity === 'ALL' || alert.severity === severity;
    const haystack = `${alert.alert_name} ${alert.source_ip} ${alert.description} ${alert.service_name}`.toLowerCase();
    return matchesSeverity && haystack.includes(query);
  });
}

export function replayEvents(alert: Alert): ReplayEvent[] {
  const meta = metadata(alert);

  if (Array.isArray(meta.events)) {
    const events = meta.events as Array<Record<string, unknown>>;
    return events.map((event, index) => ({
      label: String(event.type || event.action || `event-${index + 1}`),
      detail: String(event.command || event.path || event.detail || alert.description || 'Observed activity'),
      source: String(event.source || alert.service_name || 'sensor'),
      time: String(event.timestamp || alert.first_seen || ''),
    }));
  }

  const phases = Array.isArray(meta.phases) ? (meta.phases as string[]) : ['reconnaissance', 'access', 'exploitation'];
  return phases.map((phase, index) => ({
    label: phase,
    detail:
      index === 0
        ? `Connection observed from ${alert.source_ip || 'unknown actor'}`
        : index === 1
          ? `Access attempt against ${alert.service_name || 'exposed service'}`
          : alert.description || 'Payload behavior observed by the sensor',
    source: alert.honeypot_type || 'sensor mesh',
    time: alert.first_seen || '',
  }));
}

/**
 * Build the auth header for whatever the operator pasted.
 *
 * Three shapes reach this: a service API key (api/auth.py mints these with an
 * `hf_api_` prefix), a raw JWT as returned by POST /auth/login, or a JWT the
 * operator pasted with the "Bearer " prefix already attached. A raw JWT used
 * to be sent as X-API-Key, which the API rejects -- so the token obtained
 * from the documented login flow could not authenticate the dashboard.
 */
export function buildAuthHeaders(token: string): Record<string, string> {
  const trimmed = token.trim();
  if (!trimmed) return {};

  if (trimmed.startsWith('hf_api_')) return { 'X-API-Key': trimmed };
  if (/^Bearer\s+/i.test(trimmed)) return { Authorization: trimmed.replace(/^Bearer\s+/i, 'Bearer ') };

  return { Authorization: `Bearer ${trimmed}` };
}

/** Operator-supplied API URLs must be absolute http(s) or root-relative. */
export function isValidApiUrl(url: string): boolean {
  return /^(https?:\/\/|\/)/.test(url.trim());
}
