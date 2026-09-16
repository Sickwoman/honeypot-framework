// The dashboard application: state, rendering, event binding and API calls.
//
// Exposed as a factory rather than module-level singletons so tests can mount
// an instance against a throwaway DOM node, drive it, and throw it away --
// importing this module has no side effects of its own. main.ts is the thin
// bootstrap that mounts it against the real #app element.

import {
  buildAuthHeaders,
  esc,
  filterAlerts,
  isValidApiUrl,
  metadata,
  relativeTime,
  replayEvents,
  severityClass,
} from './lib';
import type { Alert, Playbook } from './lib';

export interface PlaybookDetail extends Playbook {
  enabled?: boolean;
  tags?: string[];
  trigger?: { conditions?: Record<string, unknown> };
  actions?: Array<{ type?: string }>;
}

export type View = 'dashboard' | 'alerts' | 'playbooks';
export type DetailTab = 'overview' | 'timeline' | 'raw';
export type SortKey = 'severity' | 'alert_name' | 'source_ip' | 'service_name' | 'honeypot_type' | 'status' | 'last_seen';

const SEVERITY_WEIGHT: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
const SEVERITY_COLOR: Record<string, string> = { critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--low)', info: 'var(--info)' };

export const POLL_INTERVAL_MS = 10_000;

// Small hand-drawn icons instead of unicode glyphs (⚙ ✕ ⟳ render inconsistently
// across platforms and are an easy tell that nobody looked closely). None of
// these carry user data, so they're safe to inline without esc().
const ICON = {
  sliders: '<svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"><line x1="2" y1="4" x2="14" y2="4"/><circle cx="10" cy="4" r="1.5" fill="currentColor" stroke="none"/><line x1="2" y1="8" x2="14" y2="8"/><circle cx="6" cy="8" r="1.5" fill="currentColor" stroke="none"/><line x1="2" y1="12" x2="14" y2="12"/><circle cx="11" cy="12" r="1.5" fill="currentColor" stroke="none"/></svg>',
  close: '<svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"><line x1="3" y1="3" x2="13" y2="13"/><line x1="13" y1="3" x2="3" y2="13"/></svg>',
  refresh: '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"><path d="M13 8a5 5 0 1 1-1.7-3.7"/><path d="M13 2.3v3.4h-3.4"/></svg>',
  sortUp: '<svg width="8" height="8" viewBox="0 0 8 8"><path d="M4 1l3.2 4.6H0.8z" fill="currentColor"/></svg>',
  sortDown: '<svg width="8" height="8" viewBox="0 0 8 8"><path d="M4 7L0.8 2.4h6.4z" fill="currentColor"/></svg>',
};

/** Shown until an alert API is configured, and whenever it can't be reached. */
export const demoAlerts: Alert[] = [
  {
    id: 'demo-honeytoken', alert_name: 'HoneytokenTriggered', severity: 'CRITICAL', status: 'active',
    source_ip: '185.220.101.44', honeypot_type: 'honeytoken', service_name: 'tripwire',
    description: 'Synthetic AWS credential used in an SSH command', first_seen: '2026-09-05T14:38:00Z', last_seen: '2026-09-05T14:38:00Z',
    threat_score: 1, threat_level: 'CRITICAL', metadata: { honeytoken_label: 'staging-deploy-key', tactic: 'credential-access' },
  },
  {
    id: 'demo-chain', alert_name: 'AttackChainDetected', severity: 'HIGH', status: 'active',
    source_ip: '45.155.205.18', honeypot_type: 'cowrie', service_name: 'ssh',
    description: 'Reconnaissance followed by SSH brute force and payload staging', first_seen: '2026-09-05T14:22:00Z', last_seen: '2026-09-05T14:30:00Z',
    threat_score: .91, threat_level: 'HIGH', metadata: { phases: ['reconnaissance', 'access', 'exploitation'] },
  },
  {
    id: 'demo-web', alert_name: 'WebReconnaissance', severity: 'MEDIUM', status: 'acknowledged',
    source_ip: '103.76.120.9', honeypot_type: 'opencanary', service_name: 'http',
    description: 'Suspicious HTTP path requested: /.env', first_seen: '2026-09-05T14:04:00Z', last_seen: '2026-09-05T14:04:00Z',
    threat_score: .7, threat_level: 'MEDIUM', acknowledged: true, metadata: { path: '/.env', method: 'GET' },
  },
  {
    id: 'demo-ftp', alert_name: 'CredentialsCaptured', severity: 'HIGH', status: 'resolved',
    source_ip: '91.92.241.7', honeypot_type: 'opencanary', service_name: 'ftp',
    description: 'Credentials captured: admin:********', first_seen: '2026-09-05T13:58:00Z', last_seen: '2026-09-05T13:58:00Z',
    threat_score: .85, threat_level: 'HIGH', metadata: { credential_capture: true },
  },
];

export interface AppState {
  view: View;
  alerts: Alert[];
  playbooks: PlaybookDetail[];
  selectedId: string | null;
  detailTab: DetailTab;
  selectedIds: Set<string>;
  severity: string;
  status: string;
  search: string;
  sortKey: SortKey;
  sortDir: 'asc' | 'desc';
  live: boolean;
  demo: boolean;
  lastSync: Date;
  apiUrl: string;
  token: string;
  actionMessage: string;
  actionBusy: boolean;
  settingsOpen: boolean;
}

export interface App {
  state: AppState;
  render(): void;
  fetchAlerts(): Promise<void>;
  fetchPlaybooks(): Promise<void>;
  fetchAll(): Promise<void>;
  startPolling(): void;
  stopPolling(): void;
  visibleAlerts(): Alert[];
}

/** "CRITICAL" -> "Critical". The API speaks in caps; the UI shouldn't shout. */
function titleCase(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1).toLowerCase();
}

export function createApp(root: HTMLElement): App {
  const state: AppState = {
    view: 'dashboard',
    alerts: [...demoAlerts],
    playbooks: [],
    selectedId: null,
    detailTab: 'overview',
    selectedIds: new Set<string>(),
    severity: 'ALL',
    status: 'ALL',
    search: '',
    sortKey: 'last_seen',
    sortDir: 'desc',
    live: true,
    demo: true,
    lastSync: new Date(),
    apiUrl: localStorage.getItem('nightwatch-api') || '/api/v1/alerts',
    token: localStorage.getItem('nightwatch-token') || '',
    actionMessage: '',
    actionBusy: false,
    settingsOpen: false,
  };

  let pollTimer: ReturnType<typeof setInterval> | undefined;

  // ---------------------------------------------------------------- //
  // Derived data
  // ---------------------------------------------------------------- //
  function apiBase(): string {
    return state.apiUrl.replace(/\/alerts$/, '');
  }

  function authHeaders(): HeadersInit {
    return buildAuthHeaders(state.token);
  }

  function visibleAlerts(): Alert[] {
    let list = filterAlerts(state.alerts, state.severity, state.search);
    if (state.status !== 'ALL') list = list.filter((alert) => (alert.status || 'active') === state.status);

    const dir = state.sortDir === 'asc' ? 1 : -1;
    const key = state.sortKey;
    return [...list].sort((a, b) => {
      if (key === 'severity') return dir * ((SEVERITY_WEIGHT[a.severity] ?? -1) - (SEVERITY_WEIGHT[b.severity] ?? -1));
      if (key === 'last_seen') return dir * (new Date(a.last_seen || a.first_seen || 0).getTime() - new Date(b.last_seen || b.first_seen || 0).getTime());
      return dir * String(a[key] || '').localeCompare(String(b[key] || ''));
    });
  }

  function selectedAlert(): Alert | null {
    return state.alerts.find((alert) => alert.id === state.selectedId) || null;
  }

  function selectAlert(id: string | null): void {
    state.selectedId = id;
    state.detailTab = 'overview';
    state.actionMessage = '';
    render();
  }

  // ---------------------------------------------------------------- //
  // Shell: sidebar + topbar
  // ---------------------------------------------------------------- //
  function sidebar(): string {
    const activeCount = state.alerts.filter((alert) => (alert.status || 'active') === 'active').length;
    const navItem = (view: View, label: string, count?: number) =>
      `<button class="nav-item ${state.view === view ? 'active' : ''}" data-view="${view}"><span>${label}</span>${count !== undefined ? `<span class="count">${count}</span>` : ''}</button>`;

    return `<nav class="sidebar">
      <div class="sidebar-brand"><span class="word">night<b>watch</b></span><span class="cursor"></span></div>
      <div class="sidebar-nav">
        ${navItem('dashboard', 'Dashboard')}
        ${navItem('alerts', 'Alerts', activeCount)}
        ${navItem('playbooks', 'Playbooks', state.playbooks.length || undefined)}
      </div>
      <div class="sidebar-foot">
        <div class="conn-status"><span class="dot ${state.demo ? 'demo' : (state.live ? 'live' : '')}"></span>${state.demo ? 'Demo data' : (state.live ? 'Connected' : 'Paused')}</div>
        <button class="sidebar-foot-button" data-action="settings">Settings</button>
      </div>
    </nav>`;
  }

  function topbar(title: string, tools: string): string {
    return `<header class="topbar"><h1>${esc(title)}</h1><div class="topbar-tools">${tools}<button class="icon-button" data-action="refresh" title="Refresh">${ICON.refresh}</button><button class="icon-button" data-action="settings" title="Settings">${ICON.sliders}</button></div></header>`;
  }

  function demoBanner(): string {
    if (!state.demo) return '';
    return `<div class="demo-banner"><span>Showing local demo data — no alert API connected.</span><button data-action="settings">Connect API →</button></div>`;
  }

  // ---------------------------------------------------------------- //
  // Dashboard view
  // ---------------------------------------------------------------- //
  function dashboardView(): string {
    const alerts = state.alerts;
    const count = (sev: string) => alerts.filter((a) => a.severity === sev).length;
    const counts = { CRITICAL: count('CRITICAL'), HIGH: count('HIGH'), MEDIUM: count('MEDIUM'), LOW: count('LOW'), INFO: count('INFO') };
    const total = alerts.length || 1;
    const active = alerts.filter((a) => (a.status || 'active') === 'active').length;
    const acknowledged = alerts.filter((a) => a.status === 'acknowledged').length;
    const resolved = alerts.filter((a) => a.status === 'resolved').length;

    const bar = (Object.keys(counts) as Array<keyof typeof counts>)
      .map((sev) => counts[sev] ? `<span style="width:${(counts[sev] / total) * 100}%;background:${SEVERITY_COLOR[sev.toLowerCase()]}"></span>` : '')
      .join('');
    const legend = (Object.keys(counts) as Array<keyof typeof counts>)
      .map((sev) => `<div class="item"><span class="swatch" style="background:${SEVERITY_COLOR[sev.toLowerCase()]}"></span>${titleCase(sev)} · ${counts[sev]}</div>`)
      .join('');

    const recent = [...alerts]
      .sort((a, b) => new Date(b.last_seen || b.first_seen || 0).getTime() - new Date(a.last_seen || a.first_seen || 0).getTime())
      .slice(0, 5);

    const recentRows = recent.length
      ? recent.map((alert) => `<tr data-goto-alert="${esc(alert.id)}"><td><span class="badge ${severityClass(alert.severity)}">${esc(titleCase(alert.severity))}</span></td><td class="name">${esc(alert.alert_name)}</td><td class="ip">${esc(alert.source_ip || '—')}</td><td><span class="status-badge ${esc(alert.status || 'active')}">${esc(titleCase(alert.status || 'active'))}</span></td><td class="time">${relativeTime(alert.last_seen || alert.first_seen)}</td></tr>`).join('')
      : `<tr><td colspan="5"><div class="empty-state"><strong>No alerts yet</strong><span>Connect the alert API from Settings to see live data.</span></div></td></tr>`;

    return `${topbar('Dashboard', '')}
    <div class="content">
      ${demoBanner()}
      <div class="stat-strip">
        <div class="stat"><span class="label">Total</span><span class="value">${alerts.length}</span></div>
        <div class="stat critical"><span class="label">Critical</span><span class="value">${counts.CRITICAL}</span></div>
        <div class="stat high"><span class="label">High</span><span class="value">${counts.HIGH}</span></div>
        <div class="stat"><span class="label">Active</span><span class="value">${active}</span></div>
        <div class="stat"><span class="label">Acknowledged</span><span class="value">${acknowledged}</span></div>
        <div class="stat"><span class="label">Resolved</span><span class="value">${resolved}</span></div>
      </div>
      <div class="panel">
        <div class="panel-header"><h2>Severity breakdown</h2><span class="meta">${alerts.length} alerts</span></div>
        <div class="panel-body">
          <div class="sev-bar">${bar || '<span style="width:100%;background:var(--border-soft)"></span>'}</div>
          <div class="sev-legend">${legend}</div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-header"><h2>Recent alerts</h2><span class="meta">last 5</span></div>
        <div class="table-wrap"><table class="data-table"><thead><tr><th>Severity</th><th>Alert</th><th>Source IP</th><th>Status</th><th>Last seen</th></tr></thead><tbody>${recentRows}</tbody></table></div>
      </div>
    </div>`;
  }

  // ---------------------------------------------------------------- //
  // Alerts view
  // ---------------------------------------------------------------- //
  function sortArrow(key: SortKey): string {
    if (state.sortKey !== key) return '';
    return state.sortDir === 'asc' ? ICON.sortUp : ICON.sortDown;
  }

  function alertsToolbar(): string {
    const sevOptions = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
      .map((sev) => `<option value="${sev}" ${state.severity === sev ? 'selected' : ''}>${sev === 'ALL' ? 'All severities' : titleCase(sev)}</option>`).join('');
    const statusOptions = ['ALL', 'active', 'acknowledged', 'resolved', 'suppressed']
      .map((s) => `<option value="${s}" ${state.status === s ? 'selected' : ''}>${s === 'ALL' ? 'All statuses' : titleCase(s)}</option>`).join('');
    return `<input id="search" class="field-input search" value="${esc(state.search)}" placeholder="Search IP, service, description..."/><select id="severity" class="field-select">${sevOptions}</select><select id="status" class="field-select">${statusOptions}</select>`;
  }

  function alertsView(): string {
    const rows = visibleAlerts();
    const selected = selectedAlert();
    const allSelected = rows.length > 0 && rows.every((alert) => state.selectedIds.has(alert.id));
    const anySelected = state.selectedIds.size > 0;

    const columns: Array<{ key: SortKey; label: string }> = [
      { key: 'severity', label: 'Severity' },
      { key: 'alert_name', label: 'Alert' },
      { key: 'source_ip', label: 'Source IP' },
      { key: 'service_name', label: 'Service' },
      { key: 'honeypot_type', label: 'Honeypot' },
      { key: 'status', label: 'Status' },
      { key: 'last_seen', label: 'Last seen' },
    ];

    const headerCells = columns.map((col) => `<th data-sort="${col.key}">${col.label}${sortArrow(col.key)}</th>`).join('');

    const bodyRows = rows.length
      ? rows.map((alert) => `<tr class="${alert.id === state.selectedId ? 'selected' : ''}" data-row-id="${esc(alert.id)}">
          <td class="col-check"><input type="checkbox" data-check-id="${esc(alert.id)}" ${state.selectedIds.has(alert.id) ? 'checked' : ''}/></td>
          <td><span class="badge ${severityClass(alert.severity)}">${esc(titleCase(alert.severity))}</span></td>
          <td class="name">${esc(alert.alert_name)}</td>
          <td class="ip">${esc(alert.source_ip || '—')}</td>
          <td>${esc(alert.service_name || '—')}</td>
          <td>${esc(alert.honeypot_type || '—')}</td>
          <td><span class="status-badge ${esc(alert.status || 'active')}">${esc(titleCase(alert.status || 'active'))}</span></td>
          <td class="time">${relativeTime(alert.last_seen || alert.first_seen)}</td>
        </tr>`).join('')
      : `<tr><td colspan="8"><div class="empty-state"><strong>No matching alerts</strong><span>Try clearing filters or connecting the alert API.</span></div></td></tr>`;

    const table = `<div class="table-wrap"><table class="data-table"><thead><tr><th class="col-check"><input type="checkbox" id="select-all" ${allSelected ? 'checked' : ''}/></th>${headerCells}</tr></thead><tbody>${bodyRows}</tbody></table></div>`;

    return `${topbar('Alerts', '')}
    <div class="content">
      ${demoBanner()}
      <div class="toolbar">
        ${alertsToolbar()}
        <div class="toolbar-spacer"></div>
        ${anySelected ? `<button class="btn btn-sm" data-action="bulk-ack">Acknowledge selected (${state.selectedIds.size})</button>` : ''}
        <button class="btn btn-sm" data-action="toggle-live">${state.live ? 'Pause' : 'Resume'} polling</button>
      </div>
      <div class="alerts-layout ${selected ? 'with-detail' : ''}">
        ${table}
        ${selected ? detailPanel(selected) : ''}
      </div>
    </div>`;
  }

  function detailPanel(alert: Alert): string {
    const meta = metadata(alert);
    const events = replayEvents(alert);

    const tabs: Array<{ key: DetailTab; label: string }> = [
      { key: 'overview', label: 'Overview' },
      { key: 'timeline', label: 'Timeline' },
      { key: 'raw', label: 'Raw' },
    ];
    const tabButtons = tabs.map((tab) => `<button class="tab ${state.detailTab === tab.key ? 'active' : ''}" data-tab="${tab.key}">${tab.label}</button>`).join('');

    let body = '';
    if (state.detailTab === 'overview') {
      body = `<div class="kv-grid">
        <div class="kv"><span>Source IP</span><strong>${esc(alert.source_ip || 'Unknown')}</strong></div>
        <div class="kv"><span>Service</span><strong>${esc(alert.service_name || 'Unknown')}</strong></div>
        <div class="kv"><span>Honeypot</span><strong>${esc(alert.honeypot_type || 'Unknown')}</strong></div>
        <div class="kv"><span>Threat level</span><strong style="color:${SEVERITY_COLOR[(alert.threat_level || alert.severity || 'info').toLowerCase()] || 'inherit'}">${esc(alert.threat_level || alert.severity)}</strong></div>
        <div class="kv"><span>Threat score</span><strong>${alert.threat_score !== undefined ? Math.round(alert.threat_score * 100) + '%' : '—'}</strong></div>
        <div class="kv"><span>First seen</span><strong>${esc(alert.first_seen ? new Date(alert.first_seen).toLocaleString() : 'Unknown')}</strong></div>
        <div class="kv"><span>Last seen</span><strong>${esc(alert.last_seen ? new Date(alert.last_seen).toLocaleString() : 'Unknown')}</strong></div>
        <div class="kv"><span>Alert ID</span><strong>${esc(alert.id)}</strong></div>
      </div>
      <p class="detail-description">${esc(alert.description || 'No description available.')}</p>`;
    } else if (state.detailTab === 'timeline') {
      body = `<div class="timeline-list">${events.map((event, index) => `<div class="timeline-row"><div class="timeline-dot">${index + 1}</div><div><b>${esc(event.label)}</b><p>${esc(event.detail)}</p><time>${event.time ? new Date(event.time).toLocaleString() : esc(event.source)}</time></div></div>`).join('')}</div>`;
    } else {
      body = `<pre class="raw-json">${esc(JSON.stringify(meta, null, 2))}</pre>`;
    }

    return `<aside class="detail-panel">
      <div class="detail-head">
        <div class="row-top"><h3>${esc(alert.alert_name)}</h3><button class="detail-close" data-action="close-detail">${ICON.close}</button></div>
        <p>${esc(alert.description || 'No description available.')}</p>
      </div>
      <div class="detail-actions">
        <button class="btn" data-action="ack" ${alert.acknowledged || alert.status !== 'active' ? 'disabled' : ''}>Acknowledge</button>
        <button class="btn" data-action="contain" ${state.actionBusy ? 'disabled' : ''}>Contain</button>
        <button class="btn btn-primary" data-action="resolve" ${state.actionBusy || alert.status === 'resolved' ? 'disabled' : ''}>Resolve</button>
      </div>
      <div class="tabs">${tabButtons}</div>
      <div class="tab-panel">${body}</div>
      ${state.actionMessage ? `<div class="action-log"><span class="dot ${state.actionBusy ? 'live' : ''}"></span>${esc(state.actionMessage)}</div>` : ''}
    </aside>`;
  }

  // ---------------------------------------------------------------- //
  // Playbooks view
  // ---------------------------------------------------------------- //
  function playbooksView(): string {
    const rows = state.playbooks.length
      ? state.playbooks.map((pb) => {
          const trigger = pb.trigger?.conditions ? Object.entries(pb.trigger.conditions).map(([k, v]) => `${k}=${v}`).join(', ') : '—';
          const actionsSummary = (pb.actions || []).map((a) => a.type).filter(Boolean).join(' → ') || '—';
          const tags = (pb.tags || []).map((tag) => `<span class="tag">${esc(tag)}</span>`).join('');
          return `<tr><td colspan="5" class="playbook-cell">
            <details>
              <summary class="playbook-summary">
                <span class="name">${esc(pb.name)}</span>
                <span class="mono playbook-meta">${esc(trigger)}</span>
                <span class="mono playbook-meta">${esc(actionsSummary)}</span>
                <span class="tag-row">${tags}</span>
                <span class="status-badge ${pb.enabled === false ? '' : 'resolved'}">${pb.enabled === false ? 'Disabled' : 'Enabled'}</span>
              </summary>
              <div class="playbook-row-detail"><pre class="raw-json">${esc(JSON.stringify(pb, null, 2))}</pre></div>
            </details>
          </td></tr>`;
        }).join('')
      : `<tr><td colspan="5"><div class="empty-state"><strong>No playbooks loaded</strong><span>Connect the alert API from Settings to list configured playbooks.</span></div></td></tr>`;

    return `${topbar('Playbooks', '')}
    <div class="content">
      ${demoBanner()}
      <div class="panel">
        <div class="panel-header"><h2>Automated response playbooks</h2><span class="meta">${state.playbooks.length} configured</span></div>
        <div class="table-wrap"><table class="data-table"><thead><tr><th>Name</th><th>Trigger</th><th>Actions</th><th>Tags</th><th>State</th></tr></thead><tbody>${rows}</tbody></table></div>
      </div>
    </div>`;
  }

  // ---------------------------------------------------------------- //
  // Settings modal
  // ---------------------------------------------------------------- //
  function settingsModal(): string {
    if (!state.settingsOpen) return '';
    return `<div class="modal-overlay" data-action="modal-overlay">
      <div class="modal">
        <div class="modal-header"><h2>Alert API settings</h2><button class="detail-close" data-action="close-settings">${ICON.close}</button></div>
        <div class="modal-body">
          <div class="modal-field"><label>API URL</label><input id="settings-url" class="field-input" value="${esc(state.apiUrl)}" placeholder="/api/v1/alerts"/><p class="modal-hint">Absolute URL or a root-relative path.</p></div>
          <div class="modal-field"><label>API key or bearer token</label><input id="settings-token" class="field-input" type="password" value="${esc(state.token)}" placeholder="hf_api_... or a JWT"/><p class="modal-hint">Obtained from POST /auth/login, or an API key minted for a service account.</p></div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-danger" data-action="sign-out">Sign out</button>
          <div class="modal-footer-right"><button class="btn" data-action="close-settings">Cancel</button><button class="btn btn-primary" data-action="save-settings">Save</button></div>
        </div>
      </div>
    </div>`;
  }

  // ---------------------------------------------------------------- //
  // Render + bind
  // ---------------------------------------------------------------- //
  function render(): void {
    const view = state.view === 'dashboard' ? dashboardView() : state.view === 'alerts' ? alertsView() : playbooksView();
    root.innerHTML = `<div class="shell">${sidebar()}<main class="main">${view}</main></div>${settingsModal()}`;
    bindEvents();
  }

  function bindEvents(): void {
    const all = <T extends HTMLElement>(selector: string) => Array.from(root.querySelectorAll<T>(selector));
    const one = <T extends HTMLElement>(selector: string) => root.querySelector<T>(selector);

    all('[data-view]').forEach((el) => el.onclick = () => { state.view = el.dataset.view as View; render(); });
    all('[data-action="settings"]').forEach((el) => el.onclick = () => { state.settingsOpen = true; render(); });
    all('[data-action="close-settings"]').forEach((el) => el.onclick = () => { state.settingsOpen = false; render(); });
    all('[data-action="modal-overlay"]').forEach((el) => el.onclick = (event) => { if (event.target === el) { state.settingsOpen = false; render(); } });
    all('[data-action="save-settings"]').forEach((el) => el.onclick = saveSettings);
    all('[data-action="sign-out"]').forEach((el) => el.onclick = signOut);
    all('[data-action="refresh"]').forEach((el) => el.onclick = () => { void fetchAll(); });
    all('[data-action="toggle-live"]').forEach((el) => el.onclick = () => { state.live = !state.live; render(); });

    one<HTMLInputElement>('#search')?.addEventListener('input', (event) => {
      state.search = (event.target as HTMLInputElement).value; render();
      const input = one<HTMLInputElement>('#search');
      input?.focus(); input?.setSelectionRange(input.value.length, input.value.length);
    });
    one<HTMLSelectElement>('#severity')?.addEventListener('change', (event) => { state.severity = (event.target as HTMLSelectElement).value; render(); });
    one<HTMLSelectElement>('#status')?.addEventListener('change', (event) => { state.status = (event.target as HTMLSelectElement).value; render(); });

    all('[data-sort]').forEach((el) => el.onclick = () => {
      const key = el.dataset.sort as SortKey;
      if (state.sortKey === key) state.sortDir = state.sortDir === 'asc' ? 'desc' : 'asc';
      else { state.sortKey = key; state.sortDir = 'asc'; }
      render();
    });

    all('[data-row-id]').forEach((el) => el.onclick = (event) => {
      if ((event.target as HTMLElement).closest('[data-check-id]')) return;
      selectAlert(el.dataset.rowId || null);
    });
    all('[data-goto-alert]').forEach((el) => el.onclick = () => { state.view = 'alerts'; selectAlert(el.dataset.gotoAlert || null); });
    all('[data-action="close-detail"]').forEach((el) => el.onclick = () => selectAlert(null));
    all('[data-tab]').forEach((el) => el.onclick = () => { state.detailTab = el.dataset.tab as DetailTab; render(); });

    all<HTMLInputElement>('[data-check-id]').forEach((el) => el.onclick = (event) => {
      event.stopPropagation();
      const id = el.dataset.checkId!;
      if (state.selectedIds.has(id)) state.selectedIds.delete(id); else state.selectedIds.add(id);
      render();
    });
    one<HTMLInputElement>('#select-all')?.addEventListener('change', (event) => {
      const checked = (event.target as HTMLInputElement).checked;
      if (checked) visibleAlerts().forEach((alert) => state.selectedIds.add(alert.id));
      else visibleAlerts().forEach((alert) => state.selectedIds.delete(alert.id));
      render();
    });
    all('[data-action="bulk-ack"]').forEach((el) => el.onclick = () => { void bulkAcknowledge(); });

    all('[data-action="ack"]').forEach((el) => el.onclick = () => { void acknowledge(); });
    all('[data-action="contain"]').forEach((el) => el.onclick = () => { void containSource(); });
    all('[data-action="resolve"]').forEach((el) => el.onclick = () => { void resolveIncident(); });
  }

  // ---------------------------------------------------------------- //
  // Settings
  // ---------------------------------------------------------------- //
  function saveSettings(): void {
    const url = root.querySelector<HTMLInputElement>('#settings-url')?.value.trim() || '';
    const token = root.querySelector<HTMLInputElement>('#settings-token')?.value.trim() || '';

    if (!url) { signOut(); return; }
    if (!isValidApiUrl(url)) { window.alert('API URL must start with https://, http:// or /'); return; }

    state.apiUrl = url; state.token = token; state.settingsOpen = false;
    localStorage.setItem('nightwatch-api', state.apiUrl);
    localStorage.setItem('nightwatch-token', state.token);
    // Close the modal now rather than when the refresh lands -- fetchAll()
    // renders at the end, so waiting on it leaves the dialog up for the whole
    // round trip (forever, if the API doesn't answer).
    render();
    void fetchAll();
  }

  function signOut(): void {
    state.token = '';
    localStorage.removeItem('nightwatch-token');
    state.alerts = []; state.playbooks = []; state.demo = true; state.settingsOpen = false;
    render();
    void fetchAll();
  }

  // ---------------------------------------------------------------- //
  // Actions
  // ---------------------------------------------------------------- //
  async function acknowledge(): Promise<void> {
    const alert = selectedAlert();
    if (!alert) return;
    if (state.demo) { alert.acknowledged = true; alert.status = 'acknowledged'; render(); return; }
    try {
      await fetch(`${apiBase()}/alerts/${alert.id}/acknowledge`, { method: 'POST', headers: authHeaders() });
      await fetchAlerts();
    } catch { /* keep current state; a failed ack should not disrupt the view */ }
    render();
  }

  async function bulkAcknowledge(): Promise<void> {
    const ids = [...state.selectedIds];
    if (!ids.length) return;
    if (state.demo) {
      state.alerts.forEach((alert) => { if (ids.includes(alert.id)) { alert.acknowledged = true; alert.status = 'acknowledged'; } });
      state.selectedIds.clear();
      render();
      return;
    }
    await Promise.all(ids.map((id) => fetch(`${apiBase()}/alerts/${id}/acknowledge`, { method: 'POST', headers: authHeaders() }).catch(() => undefined)));
    state.selectedIds.clear();
    await fetchAlerts();
    render();
  }

  async function containSource(): Promise<void> {
    const alert = selectedAlert();
    if (!alert) return;
    state.actionBusy = true;
    state.actionMessage = state.demo ? 'Simulating containment in local preview...' : 'Finding a matching response playbook...';
    render();
    if (state.demo) {
      state.actionMessage = `Source ${alert.source_ip || 'actor'} marked for isolation (demo)`;
      state.actionBusy = false;
      render();
      return;
    }
    try {
      const playbookResponse = await fetch(`${apiBase()}/playbooks`, { headers: authHeaders() });
      if (!playbookResponse.ok) throw new Error('Playbooks unavailable');
      const payload = await playbookResponse.json() as { playbooks?: Playbook[] };
      const playbook = payload.playbooks?.find((item) => /block|isolate|contain/i.test(`${item.id} ${item.name}`)) || payload.playbooks?.[0];
      if (!playbook) throw new Error('No response playbook configured');
      const response = await fetch(`${apiBase()}/playbooks/${playbook.id}/execute`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ alert_id: alert.id, alert_data: alert, dry_run: false }),
      });
      if (!response.ok) throw new Error('Playbook execution failed');
      state.actionMessage = `${playbook.name} completed for ${alert.source_ip || 'source actor'}`;
    } catch (error) {
      state.actionMessage = error instanceof Error ? error.message : 'Containment could not be completed';
    }
    state.actionBusy = false;
    render();
  }

  async function resolveIncident(): Promise<void> {
    const alert = selectedAlert();
    if (!alert) return;
    state.actionBusy = true;
    state.actionMessage = state.demo ? 'Writing resolution to local preview...' : 'Recording resolution...';
    render();
    if (state.demo) {
      alert.status = 'resolved';
      state.actionMessage = 'Incident resolved by operator (demo)';
      state.actionBusy = false;
      render();
      return;
    }
    try {
      const response = await fetch(`${apiBase()}/alerts/${alert.id}/resolve`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ notes: 'Resolved from Nightwatch console' }),
      });
      if (!response.ok) throw new Error('Resolution request failed');
      state.actionMessage = 'Incident resolved and audit entry recorded';
      await fetchAlerts();
    } catch (error) {
      state.actionMessage = error instanceof Error ? error.message : 'Resolution could not be recorded';
    }
    state.actionBusy = false;
    render();
  }

  // ---------------------------------------------------------------- //
  // Data fetching
  // ---------------------------------------------------------------- //
  async function fetchAlerts(): Promise<void> {
    try {
      const response = await fetch(`${state.apiUrl}?limit=100`, { headers: authHeaders() });
      if (!response.ok) throw new Error('API unavailable');
      const payload = await response.json() as { alerts?: Alert[] };
      state.alerts = payload.alerts || [];
      state.demo = false;
    } catch {
      state.alerts = [...demoAlerts];
      state.demo = true;
    }
    state.lastSync = new Date();
  }

  async function fetchPlaybooks(): Promise<void> {
    if (state.demo) { state.playbooks = []; return; }
    try {
      const response = await fetch(`${apiBase()}/playbooks`, { headers: authHeaders() });
      if (!response.ok) throw new Error('Playbooks unavailable');
      const payload = await response.json() as { playbooks?: PlaybookDetail[] };
      state.playbooks = payload.playbooks || [];
    } catch {
      state.playbooks = [];
    }
  }

  async function fetchAll(): Promise<void> {
    if (!state.live) return;
    await fetchAlerts();
    await fetchPlaybooks();
    render();
  }

  function startPolling(): void {
    stopPolling();
    pollTimer = setInterval(() => { void fetchAll(); }, POLL_INTERVAL_MS);
  }

  function stopPolling(): void {
    if (pollTimer !== undefined) clearInterval(pollTimer);
    pollTimer = undefined;
  }

  return { state, render, fetchAlerts, fetchPlaybooks, fetchAll, startPolling, stopPolling, visibleAlerts };
}
