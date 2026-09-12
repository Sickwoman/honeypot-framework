import { describe, expect, it } from 'vitest';

import {
  buildAuthHeaders,
  esc,
  filterAlerts,
  isValidApiUrl,
  metadata,
  relativeTime,
  replayEvents,
  severityClass,
  type Alert,
} from './lib';

function alert(overrides: Partial<Alert> = {}): Alert {
  return {
    id: 'a1',
    alert_name: 'SSHBruteForce',
    severity: 'HIGH',
    status: 'active',
    source_ip: '203.0.113.10',
    honeypot_type: 'cowrie',
    service_name: 'ssh',
    description: 'repeated failed logins',
    ...overrides,
  };
}

// --------------------------------------------------------------------------- //
// esc: the XSS guard. Everything rendered here is attacker-controlled.
// --------------------------------------------------------------------------- //
describe('esc', () => {
  it('neutralizes a script tag', () => {
    expect(esc('<script>alert(1)</script>')).toBe(
      '&lt;script&gt;alert(1)&lt;/script&gt;',
    );
  });

  it('escapes both quote styles so it is safe inside an attribute', () => {
    expect(esc(`" onmouseover="evil()`)).toBe('&quot; onmouseover=&quot;evil()');
    expect(esc("' onload='evil()")).toBe('&#39; onload=&#39;evil()');
  });

  it('escapes ampersands without double-escaping the result', () => {
    expect(esc('a & b')).toBe('a &amp; b');
    expect(esc('&lt;')).toBe('&amp;lt;');
  });

  it('renders null and undefined as empty rather than "null"', () => {
    expect(esc(null)).toBe('');
    expect(esc(undefined)).toBe('');
  });

  it('handles a realistic attacker username from a honeypot log', () => {
    const escaped = esc('root"><img src=x onerror=alert(1)>');

    expect(escaped).not.toContain('<img');
    expect(escaped).not.toContain('">');
  });
});

// --------------------------------------------------------------------------- //
// severityClass: guards an HTML *attribute*, so it must not pass values through
// --------------------------------------------------------------------------- //
describe('severityClass', () => {
  it('maps known severities to their class', () => {
    expect(severityClass('CRITICAL')).toBe('severity-critical');
    expect(severityClass('low')).toBe('severity-low');
  });

  it('falls back to info for an unknown severity', () => {
    expect(severityClass('BOGUS')).toBe('severity-info');
    expect(severityClass(undefined)).toBe('severity-info');
    expect(severityClass('')).toBe('severity-info');
  });

  it('never emits attacker input into the class attribute', () => {
    expect(severityClass('" onload="evil()')).toBe('severity-info');
    expect(severityClass('high"><script>')).toBe('severity-info');
  });
});

// --------------------------------------------------------------------------- //
// buildAuthHeaders
// --------------------------------------------------------------------------- //
describe('buildAuthHeaders', () => {
  it('sends a raw JWT from /auth/login as a Bearer token', () => {
    // Regression: a raw JWT used to be sent as X-API-Key, which the API
    // rejects, so the documented login flow could not authenticate.
    expect(buildAuthHeaders('eyJhbGciOiJIUzI1NiJ9.abc.def')).toEqual({
      Authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.abc.def',
    });
  });

  it('sends a service API key as X-API-Key', () => {
    expect(buildAuthHeaders('hf_api_abc123')).toEqual({ 'X-API-Key': 'hf_api_abc123' });
  });

  it('accepts a token pasted with the Bearer prefix already attached', () => {
    expect(buildAuthHeaders('Bearer abc.def.ghi')).toEqual({
      Authorization: 'Bearer abc.def.ghi',
    });
  });

  it('returns no header for an empty or whitespace token', () => {
    expect(buildAuthHeaders('')).toEqual({});
    expect(buildAuthHeaders('   ')).toEqual({});
  });
});

// --------------------------------------------------------------------------- //
// relativeTime
// --------------------------------------------------------------------------- //
describe('relativeTime', () => {
  const now = new Date('2026-09-10T12:00:00Z').getTime();

  it('formats seconds, minutes and hours', () => {
    expect(relativeTime('2026-09-10T11:59:30Z', now)).toBe('30s ago');
    expect(relativeTime('2026-09-10T11:45:00Z', now)).toBe('15m ago');
    expect(relativeTime('2026-09-10T09:00:00Z', now)).toBe('3h ago');
  });

  it('clamps future timestamps to 0 rather than showing a negative age', () => {
    expect(relativeTime('2026-09-10T13:00:00Z', now)).toBe('0s ago');
  });

  it('reports unknown for missing or unparseable input', () => {
    expect(relativeTime(undefined, now)).toBe('unknown');
    expect(relativeTime('not-a-date', now)).toBe('unknown');
  });
});

// --------------------------------------------------------------------------- //
// metadata
// --------------------------------------------------------------------------- //
describe('metadata', () => {
  it('parses a JSON string', () => {
    expect(metadata(alert({ metadata: '{"phases":["recon"]}' }))).toEqual({ phases: ['recon'] });
  });

  it('passes an already-parsed object through', () => {
    expect(metadata(alert({ metadata: { a: 1 } }))).toEqual({ a: 1 });
  });

  it('returns an empty object for malformed JSON instead of throwing', () => {
    expect(metadata(alert({ metadata: '{not json' }))).toEqual({});
  });

  it('returns an empty object when JSON parses to a non-object', () => {
    expect(metadata(alert({ metadata: '42' }))).toEqual({});
    expect(metadata(alert({ metadata: 'null' }))).toEqual({});
  });

  it('returns an empty object when metadata is absent', () => {
    expect(metadata(alert({ metadata: undefined }))).toEqual({});
  });
});

// --------------------------------------------------------------------------- //
// filterAlerts
// --------------------------------------------------------------------------- //
describe('filterAlerts', () => {
  const alerts = [
    alert({ id: '1', severity: 'CRITICAL', alert_name: 'HoneytokenTriggered', source_ip: '10.0.0.1' }),
    alert({ id: '2', severity: 'LOW', alert_name: 'PortScan', source_ip: '10.0.0.2' }),
  ];

  it('returns everything for ALL with an empty query', () => {
    expect(filterAlerts(alerts, 'ALL', '')).toHaveLength(2);
  });

  it('filters by severity', () => {
    const result = filterAlerts(alerts, 'LOW', '');

    expect(result).toHaveLength(1);
    expect(result[0].id).toBe('2');
  });

  it('searches across name, ip, description and service', () => {
    expect(filterAlerts(alerts, 'ALL', '10.0.0.2')).toHaveLength(1);
    expect(filterAlerts(alerts, 'ALL', 'honeytoken')).toHaveLength(1);
  });

  it('is case insensitive', () => {
    expect(filterAlerts(alerts, 'ALL', 'PORTSCAN')).toHaveLength(1);
  });

  it('combines severity and search', () => {
    expect(filterAlerts(alerts, 'CRITICAL', 'portscan')).toHaveLength(0);
  });
});

// --------------------------------------------------------------------------- //
// replayEvents
// --------------------------------------------------------------------------- //
describe('replayEvents', () => {
  it('builds events from a metadata event list', () => {
    const events = replayEvents(
      alert({ metadata: { events: [{ type: 'login', command: 'whoami', timestamp: 't1' }] } }),
    );

    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ label: 'login', detail: 'whoami', time: 't1' });
  });

  it('falls back to phases when no events are present', () => {
    const events = replayEvents(alert({ metadata: { phases: ['recon', 'access'] } }));

    expect(events.map((e) => e.label)).toEqual(['recon', 'access']);
    expect(events[0].detail).toContain('203.0.113.10');
  });

  it('uses default phases when metadata is empty', () => {
    expect(replayEvents(alert({ metadata: undefined })).map((e) => e.label)).toEqual([
      'reconnaissance',
      'access',
      'exploitation',
    ]);
  });

  it('labels unnamed events by position', () => {
    const events = replayEvents(alert({ metadata: { events: [{}, {}] } }));

    expect(events.map((e) => e.label)).toEqual(['event-1', 'event-2']);
  });
});

// --------------------------------------------------------------------------- //
// isValidApiUrl
// --------------------------------------------------------------------------- //
describe('isValidApiUrl', () => {
  it('accepts absolute http(s) and root-relative URLs', () => {
    expect(isValidApiUrl('https://api.example.com/v1/alerts')).toBe(true);
    expect(isValidApiUrl('http://localhost:8000/api')).toBe(true);
    expect(isValidApiUrl('/api/v1/alerts')).toBe(true);
    expect(isValidApiUrl('  /api/v1/alerts  ')).toBe(true);
  });

  it('rejects other schemes and bare hostnames', () => {
    expect(isValidApiUrl('javascript:alert(1)')).toBe(false);
    expect(isValidApiUrl('api.example.com')).toBe(false);
    expect(isValidApiUrl('')).toBe(false);
  });
});
