/**
 * @vitest-environment jsdom
 *
 * Tests for the dashboard application: rendering, filtering/sorting, the
 * detail panel, and the API/auth paths.
 *
 * lib.test.ts covers the pure helpers in isolation. This file covers what
 * those helpers are actually wired into -- in particular that every
 * attacker-controlled field reaching the DOM goes through esc(), which is the
 * only thing standing between a honeypot log line and script execution in the
 * operator's browser.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { createApp, demoAlerts, type App } from './app';
import type { Alert } from './lib';

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
    first_seen: '2026-09-05T10:00:00Z',
    last_seen: '2026-09-05T10:05:00Z',
    ...overrides,
  };
}

/** A fetch stub whose JSON body and ok-ness the test controls. */
function jsonResponse(body: unknown, ok = true) {
  return { ok, json: async () => body } as unknown as Response;
}

let root: HTMLDivElement;
let app: App;

beforeEach(() => {
  localStorage.clear();
  document.body.innerHTML = '';
  root = document.createElement('div');
  document.body.appendChild(root);
  app = createApp(root);
});

afterEach(() => {
  app.stopPolling();
  vi.restoreAllMocks();
});

/** Put the app on the Alerts view with a known set of alerts. */
function showAlerts(alerts: Alert[]): void {
  app.state.alerts = alerts;
  app.state.view = 'alerts';
  app.render();
}

function rowNames(): string[] {
  return Array.from(root.querySelectorAll('tbody tr td.name')).map((td) => td.textContent!.trim());
}

// --------------------------------------------------------------------------- //
// Rendering
// --------------------------------------------------------------------------- //
describe('rendering', () => {
  it('mounts without touching anything outside its root element', () => {
    app.render();

    expect(root.querySelector('.shell')).not.toBeNull();
    expect(document.body.children).toHaveLength(1);
  });

  it('renders one table row per alert on the alerts view', () => {
    showAlerts([alert({ id: '1', alert_name: 'PortScan' }), alert({ id: '2', alert_name: 'HoneytokenTriggered' })]);

    expect(root.querySelectorAll('tbody tr[data-row-id]')).toHaveLength(2);
    expect(rowNames()).toEqual(expect.arrayContaining(['PortScan', 'HoneytokenTriggered']));
  });

  it('starts on the dashboard with demo data and says so', () => {
    app.render();

    expect(root.querySelector('.topbar h1')!.textContent).toBe('Dashboard');
    expect(root.querySelector('.demo-banner')).not.toBeNull();
  });

  it('counts severities and statuses on the dashboard', () => {
    app.state.alerts = [
      alert({ id: '1', severity: 'CRITICAL', status: 'active' }),
      alert({ id: '2', severity: 'HIGH', status: 'resolved' }),
      alert({ id: '3', severity: 'HIGH', status: 'active' }),
    ];
    app.render();

    const values = Array.from(root.querySelectorAll('.stat-strip .stat')).map((s) => ({
      label: s.querySelector('.label')!.textContent,
      value: s.querySelector('.value')!.textContent,
    }));

    expect(values).toEqual(expect.arrayContaining([
      { label: 'Total', value: '3' },
      { label: 'Critical', value: '1' },
      { label: 'High', value: '2' },
      { label: 'Active', value: '2' },
      { label: 'Resolved', value: '1' },
    ]));
  });

  it('shows an empty state rather than a bare table when nothing matches', () => {
    showAlerts([]);

    expect(root.querySelector('.empty-state')).not.toBeNull();
    expect(root.querySelectorAll('tbody tr[data-row-id]')).toHaveLength(0);
  });
});

// --------------------------------------------------------------------------- //
// XSS -- every field below originates from attacker-controlled honeypot traffic
// --------------------------------------------------------------------------- //
describe('escaping of attacker-controlled data', () => {
  const payload = '<img src=x onerror=alert(1)>';

  it('does not create elements from a malicious alert name or description', () => {
    showAlerts([alert({ alert_name: payload, description: payload })]);

    expect(root.querySelector('img')).toBeNull();
    expect(root.innerHTML).toContain('&lt;img');
  });

  it('does not create elements from a malicious source IP or service name', () => {
    showAlerts([alert({ source_ip: payload, service_name: payload, honeypot_type: payload })]);

    expect(root.querySelector('img')).toBeNull();
  });

  it('keeps a quote-breaking severity out of the class attribute', () => {
    // severityClass() is the guard; this asserts it's actually wired up.
    showAlerts([alert({ severity: '" onload="evil()' as Alert['severity'] })]);

    const badge = root.querySelector('tbody .badge')!;
    expect(badge.className).toBe('badge severity-info');
    expect(root.querySelector('[onload]')).toBeNull();
  });

  it('escapes malicious metadata rendered into the Raw tab', () => {
    showAlerts([alert({ metadata: { note: payload } })]);
    (root.querySelector('[data-row-id]') as HTMLElement).click();
    (root.querySelector('[data-tab="raw"]') as HTMLElement).click();

    expect(root.querySelector('.raw-json')).not.toBeNull();
    expect(root.querySelector('img')).toBeNull();
  });

  it('escapes a malicious playbook name', () => {
    app.state.playbooks = [{ id: 'p1', name: payload }];
    app.state.view = 'playbooks';
    app.render();

    expect(root.querySelector('img')).toBeNull();
  });
});

// --------------------------------------------------------------------------- //
// Filtering and sorting
// --------------------------------------------------------------------------- //
describe('filtering and sorting', () => {
  const alerts = [
    alert({ id: '1', alert_name: 'PortScan', severity: 'LOW', status: 'active', source_ip: '10.0.0.1', last_seen: '2026-09-05T10:00:00Z' }),
    alert({ id: '2', alert_name: 'HoneytokenTriggered', severity: 'CRITICAL', status: 'resolved', source_ip: '10.0.0.2', last_seen: '2026-09-05T12:00:00Z' }),
    alert({ id: '3', alert_name: 'WebRecon', severity: 'MEDIUM', status: 'active', source_ip: '10.0.0.3', last_seen: '2026-09-05T11:00:00Z' }),
  ];

  it('filters by severity from the dropdown', () => {
    showAlerts(alerts);
    const select = root.querySelector<HTMLSelectElement>('#severity')!;
    select.value = 'CRITICAL';
    select.dispatchEvent(new Event('change'));

    expect(rowNames()).toEqual(['HoneytokenTriggered']);
  });

  it('filters by status from the dropdown', () => {
    showAlerts(alerts);
    const select = root.querySelector<HTMLSelectElement>('#status')!;
    select.value = 'resolved';
    select.dispatchEvent(new Event('change'));

    expect(rowNames()).toEqual(['HoneytokenTriggered']);
  });

  it('filters by the search box', () => {
    showAlerts(alerts);
    const search = root.querySelector<HTMLInputElement>('#search')!;
    search.value = '10.0.0.3';
    search.dispatchEvent(new Event('input'));

    expect(rowNames()).toEqual(['WebRecon']);
  });

  it('sorts by severity and reverses on a second click of the same column', () => {
    showAlerts(alerts);
    const header = () => root.querySelector<HTMLElement>('[data-sort="severity"]')!;

    header().click();
    expect(rowNames()).toEqual(['PortScan', 'WebRecon', 'HoneytokenTriggered']);

    header().click();
    expect(rowNames()).toEqual(['HoneytokenTriggered', 'WebRecon', 'PortScan']);
  });

  it('defaults to newest-first by last seen', () => {
    showAlerts(alerts);

    expect(rowNames()).toEqual(['HoneytokenTriggered', 'WebRecon', 'PortScan']);
  });
});

// --------------------------------------------------------------------------- //
// Detail panel
// --------------------------------------------------------------------------- //
describe('detail panel', () => {
  it('opens when a row is clicked and closes again', () => {
    showAlerts([alert({ alert_name: 'PortScan' })]);
    expect(root.querySelector('.detail-panel')).toBeNull();

    (root.querySelector('[data-row-id]') as HTMLElement).click();
    expect(root.querySelector('.detail-panel h3')!.textContent).toBe('PortScan');

    (root.querySelector('[data-action="close-detail"]') as HTMLElement).click();
    expect(root.querySelector('.detail-panel')).toBeNull();
  });

  it('switches between the overview, timeline and raw tabs', () => {
    showAlerts([alert({ metadata: { phases: ['recon', 'access'] } })]);
    (root.querySelector('[data-row-id]') as HTMLElement).click();

    expect(root.querySelector('.kv-grid')).not.toBeNull();

    (root.querySelector('[data-tab="timeline"]') as HTMLElement).click();
    expect(root.querySelectorAll('.timeline-row')).toHaveLength(2);

    (root.querySelector('[data-tab="raw"]') as HTMLElement).click();
    expect(root.querySelector('.raw-json')!.textContent).toContain('phases');
  });

  it('does not open the detail panel when the row checkbox is clicked', () => {
    showAlerts([alert()]);
    (root.querySelector('[data-check-id]') as HTMLElement).click();

    expect(root.querySelector('.detail-panel')).toBeNull();
    expect(app.state.selectedIds.has('a1')).toBe(true);
  });
});

// --------------------------------------------------------------------------- //
// Data fetching and the demo fallback
// --------------------------------------------------------------------------- //
describe('fetching alerts', () => {
  it('uses live data and drops the demo banner when the API answers', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse({ alerts: [alert({ alert_name: 'LiveAlert' })] })));

    await app.fetchAlerts();
    app.state.view = 'alerts';
    app.render();

    expect(app.state.demo).toBe(false);
    expect(rowNames()).toEqual(['LiveAlert']);
    expect(root.querySelector('.demo-banner')).toBeNull();
  });

  it('falls back to clearly-labelled demo data when the API is unreachable', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('network down'); }));

    await app.fetchAlerts();
    app.render();

    expect(app.state.demo).toBe(true);
    expect(app.state.alerts).toHaveLength(demoAlerts.length);
    expect(root.querySelector('.demo-banner')).not.toBeNull();
  });

  it('falls back to demo data on a non-OK response, not just a thrown error', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse({ error: 'unauthorized' }, false)));

    await app.fetchAlerts();

    expect(app.state.demo).toBe(true);
  });

  it('sends the stored token as a bearer header', async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ alerts: [] }));
    vi.stubGlobal('fetch', fetchMock);
    app.state.token = 'eyJhbGciOiJIUzI1NiJ9.abc.def';

    await app.fetchAlerts();

    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/alerts?limit=100'),
      { headers: { Authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.abc.def' } },
    );
  });

  it('sends a service API key as X-API-Key instead', async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ alerts: [] }));
    vi.stubGlobal('fetch', fetchMock);
    app.state.token = 'hf_api_secret';

    await app.fetchAlerts();

    expect(fetchMock).toHaveBeenCalledWith(expect.any(String), { headers: { 'X-API-Key': 'hf_api_secret' } });
  });

  it('does not fetch playbooks while in demo mode', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    app.state.demo = true;

    await app.fetchPlaybooks();

    expect(fetchMock).not.toHaveBeenCalled();
    expect(app.state.playbooks).toEqual([]);
  });

  it('skips polling work entirely while paused', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    app.state.live = false;

    await app.fetchAll();

    expect(fetchMock).not.toHaveBeenCalled();
  });
});

// --------------------------------------------------------------------------- //
// Operator actions
// --------------------------------------------------------------------------- //
describe('operator actions', () => {
  it('acknowledges a live alert against the API with auth', async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ alerts: [] }));
    vi.stubGlobal('fetch', fetchMock);

    app.state.demo = false;
    app.state.token = 'hf_api_key';
    showAlerts([alert({ id: 'abc' })]);
    (root.querySelector('[data-row-id]') as HTMLElement).click();
    (root.querySelector('[data-action="ack"]') as HTMLElement).click();
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalled());

    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/alerts/abc/acknowledge',
      { method: 'POST', headers: { 'X-API-Key': 'hf_api_key' } },
    );
  });

  it('acknowledges every selected alert in bulk', async () => {
    const fetchMock = vi.fn(async (_url: string) => jsonResponse({ alerts: [] }));
    vi.stubGlobal('fetch', fetchMock);

    app.state.demo = false;
    showAlerts([alert({ id: '1' }), alert({ id: '2' })]);
    root.querySelectorAll<HTMLElement>('[data-check-id]').forEach((box) => box.click());
    (root.querySelector('[data-action="bulk-ack"]') as HTMLElement).click();
    // The selection is cleared only after every request settles, so wait on
    // that rather than on the requests being issued.
    await vi.waitFor(() => expect(app.state.selectedIds.size).toBe(0));

    const urls = fetchMock.mock.calls.map((call) => call[0]);
    expect(urls).toContain('/api/v1/alerts/1/acknowledge');
    expect(urls).toContain('/api/v1/alerts/2/acknowledge');
  });

  it('acknowledges locally without calling the API in demo mode', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    app.state.demo = true;
    showAlerts([alert({ id: 'abc' })]);
    (root.querySelector('[data-row-id]') as HTMLElement).click();
    (root.querySelector('[data-action="ack"]') as HTMLElement).click();

    expect(fetchMock).not.toHaveBeenCalled();
    expect(app.state.alerts[0].status).toBe('acknowledged');
  });

  it('runs a matching containment playbook against the API', async () => {
    const fetchMock = vi.fn(async (url: string) => {
      if (url.endsWith('/playbooks')) return jsonResponse({ playbooks: [{ id: 'ssh-block', name: 'SSH Brute Force Block' }] });
      return jsonResponse({ status: 'ok' });
    });
    vi.stubGlobal('fetch', fetchMock);

    app.state.demo = false;
    showAlerts([alert({ id: 'abc' })]);
    (root.querySelector('[data-row-id]') as HTMLElement).click();
    (root.querySelector('[data-action="contain"]') as HTMLElement).click();
    await vi.waitFor(() => expect(app.state.actionBusy).toBe(false));

    expect(fetchMock.mock.calls.map((c) => c[0])).toContain('/api/v1/playbooks/ssh-block/execute');
    expect(root.querySelector('.action-log')!.textContent).toContain('SSH Brute Force Block');
  });

  it('surfaces a containment failure instead of silently doing nothing', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse({}, false)));

    app.state.demo = false;
    showAlerts([alert()]);
    (root.querySelector('[data-row-id]') as HTMLElement).click();
    (root.querySelector('[data-action="contain"]') as HTMLElement).click();
    await vi.waitFor(() => expect(app.state.actionBusy).toBe(false));

    expect(root.querySelector('.action-log')!.textContent).toContain('Playbooks unavailable');
  });
});

// --------------------------------------------------------------------------- //
// Settings
// --------------------------------------------------------------------------- //
describe('settings', () => {
  function openSettings(): void {
    app.render();
    (root.querySelector('[data-action="settings"]') as HTMLElement).click();
  }

  it('persists the API URL and token', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse({ alerts: [] })));
    openSettings();

    root.querySelector<HTMLInputElement>('#settings-url')!.value = 'https://api.example.com/api/v1/alerts';
    root.querySelector<HTMLInputElement>('#settings-token')!.value = 'hf_api_token';
    (root.querySelector('[data-action="save-settings"]') as HTMLElement).click();

    expect(localStorage.getItem('nightwatch-api')).toBe('https://api.example.com/api/v1/alerts');
    expect(localStorage.getItem('nightwatch-token')).toBe('hf_api_token');
    expect(root.querySelector('.modal-overlay')).toBeNull();
  });

  it('rejects a URL that is neither absolute http(s) nor root-relative', () => {
    const warn = vi.fn();
    vi.stubGlobal('alert', warn);
    openSettings();

    root.querySelector<HTMLInputElement>('#settings-url')!.value = 'javascript:alert(1)';
    (root.querySelector('[data-action="save-settings"]') as HTMLElement).click();

    expect(warn).toHaveBeenCalled();
    expect(localStorage.getItem('nightwatch-api')).toBeNull();
  });

  it('clears the stored token on sign out', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('no api'); }));
    localStorage.setItem('nightwatch-token', 'hf_api_old');
    app.state.token = 'hf_api_old';

    openSettings();
    (root.querySelector('[data-action="sign-out"]') as HTMLElement).click();

    expect(localStorage.getItem('nightwatch-token')).toBeNull();
    expect(app.state.token).toBe('');
  });
});

// --------------------------------------------------------------------------- //
// Navigation
// --------------------------------------------------------------------------- //
describe('navigation', () => {
  it('switches views from the sidebar', () => {
    app.render();

    (root.querySelector('[data-view="playbooks"]') as HTMLElement).click();
    expect(root.querySelector('.topbar h1')!.textContent).toBe('Playbooks');

    (root.querySelector('[data-view="alerts"]') as HTMLElement).click();
    expect(root.querySelector('.topbar h1')!.textContent).toBe('Alerts');
  });

  it('jumps from a dashboard row into the selected alert', () => {
    app.state.alerts = [alert({ id: 'abc', alert_name: 'PortScan' })];
    app.render();

    (root.querySelector('[data-goto-alert="abc"]') as HTMLElement).click();

    expect(app.state.view).toBe('alerts');
    expect(root.querySelector('.detail-panel h3')!.textContent).toBe('PortScan');
  });

  it('toggles polling from the alerts toolbar', () => {
    showAlerts([alert()]);
    expect(app.state.live).toBe(true);

    (root.querySelector('[data-action="toggle-live"]') as HTMLElement).click();
    expect(app.state.live).toBe(false);
    expect(root.querySelector('[data-action="toggle-live"]')!.textContent).toContain('Resume');
  });
});
