import './style.css';

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

type Alert = {
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

type Playbook = { id: string; name: string; description?: string };
type ReplayEvent = { label: string; detail: string; source: string; time: string };

const demoAlerts: Alert[] = [
  {
    id: 'demo-honeytoken', alert_name: 'HoneytokenTriggered', severity: 'CRITICAL', status: 'active',
    source_ip: '185.220.101.44', honeypot_type: 'honeytoken', service_name: 'tripwire',
    description: 'Synthetic AWS credential used in an SSH command', first_seen: '2026-09-05T14:38:00Z',
    threat_score: 1, threat_level: 'CRITICAL', metadata: { honeytoken_label: 'staging-deploy-key', tactic: 'credential-access' },
  },
  {
    id: 'demo-chain', alert_name: 'AttackChainDetected', severity: 'HIGH', status: 'active',
    source_ip: '45.155.205.18', honeypot_type: 'cowrie', service_name: 'ssh',
    description: 'Reconnaissance followed by SSH brute force and payload staging', first_seen: '2026-09-05T14:22:00Z',
    threat_score: .91, threat_level: 'HIGH', metadata: { phases: ['reconnaissance', 'access', 'exploitation'] },
  },
  {
    id: 'demo-web', alert_name: 'WebReconnaissance', severity: 'MEDIUM', status: 'acknowledged',
    source_ip: '103.76.120.9', honeypot_type: 'opencanary', service_name: 'http',
    description: 'Suspicious HTTP path requested: /.env', first_seen: '2026-09-05T14:04:00Z',
    threat_score: .7, threat_level: 'MEDIUM', acknowledged: true, metadata: { path: '/.env', method: 'GET' },
  },
  {
    id: 'demo-ftp', alert_name: 'CredentialsCaptured', severity: 'HIGH', status: 'active',
    source_ip: '91.92.241.7', honeypot_type: 'opencanary', service_name: 'ftp',
    description: 'Credentials captured: admin:********', first_seen: '2026-09-05T13:58:00Z',
    threat_score: .85, threat_level: 'HIGH', metadata: { credential_capture: true },
  },
];

const state = {
  alerts: [] as Alert[],
  selectedId: 'demo-honeytoken',
  severity: 'ALL',
  search: '',
  live: true,
  demo: true,
  lastSync: new Date(),
  apiUrl: localStorage.getItem('nightwatch-api') || '/api/v1/alerts',
  token: localStorage.getItem('nightwatch-token') || '',
  incidentStatus: 'OPEN' as 'OPEN' | 'CONTAINED' | 'RESOLVED',
  actionMessage: 'Awaiting operator decision',
  actionBusy: false,
  replayIndex: 0,
  replayPlaying: false,
};

const app = document.querySelector<HTMLDivElement>('#app')!;

function esc(value: unknown): string {
  return String(value ?? '').replace(/[&<>'"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[char]!);
}

function relativeTime(value?: string): string {
  if (!value) return 'unknown';
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  return `${Math.floor(seconds / 3600)}h ago`;
}

function filteredAlerts(): Alert[] {
  const query = state.search.toLowerCase();
  return state.alerts.filter((alert) => {
    const matchesSeverity = state.severity === 'ALL' || alert.severity === state.severity;
    const haystack = `${alert.alert_name} ${alert.source_ip} ${alert.description} ${alert.service_name}`.toLowerCase();
    return matchesSeverity && haystack.includes(query);
  });
}

function selectedAlert(): Alert {
  return state.alerts.find((alert) => alert.id === state.selectedId) || state.alerts[0] || demoAlerts[0];
}

function severityClass(severity?: string): string {
  return `severity-${String(severity || 'info').toLowerCase()}`;
}

function metadata(alert: Alert): Record<string, unknown> {
  if (!alert.metadata) return {};
  if (typeof alert.metadata === 'object') return alert.metadata;
  try { return JSON.parse(alert.metadata) as Record<string, unknown>; } catch { return {}; }
}

function graph(alert: Alert): string {
  const source = esc(alert.source_ip || 'unknown actor');
  const service = esc(alert.service_name || 'unknown service');
  const honeypot = esc(alert.honeypot_type || 'sensor');
  return `<div class="graph" aria-label="Attack relationship map">
    <div class="graph-node actor"><span>ACTOR</span><strong>${source}</strong></div>
    <div class="graph-line line-one"></div>
    <div class="graph-node sensor"><span>SENSOR</span><strong>${honeypot}</strong></div>
    <div class="graph-line line-two"></div>
    <div class="graph-node target"><span>SERVICE</span><strong>${service}</strong></div>
    <div class="graph-pulse"></div>
  </div>`;
}

function replayEvents(alert: Alert): ReplayEvent[] {
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
  const phases = Array.isArray(meta.phases) ? meta.phases as string[] : ['reconnaissance', 'access', 'exploitation'];
  return phases.map((phase, index) => ({
    label: phase,
    detail: index === 0 ? `Connection observed from ${alert.source_ip || 'unknown actor'}` : index === 1 ? `Access attempt against ${alert.service_name || 'exposed service'}` : alert.description || 'Payload behavior observed by the sensor',
    source: alert.honeypot_type || 'sensor mesh',
    time: alert.first_seen || '',
  }));
}

function replayPanel(alert: Alert): string {
  const events = replayEvents(alert);
  const current = events[Math.min(state.replayIndex, events.length - 1)] || events[0];
  const progress = events.length > 1 ? (state.replayIndex / (events.length - 1)) * 100 : 0;
  return `<section class="replay-panel"><div class="panel-head"><div><p class="eyebrow">ATTACK REPLAY</p><h3>Reconstructed session</h3></div><span class="replay-badge">${state.replayPlaying ? 'PLAYING' : 'PAUSED'} / ${state.replayIndex + 1} OF ${events.length}</span></div><div class="replay-track"><input id="replay-scrubber" type="range" min="0" max="${Math.max(events.length - 1, 0)}" value="${state.replayIndex}" style="--progress: ${progress}%" aria-label="Replay event position"/><div class="replay-times"><span>${events[0]?.time ? new Date(events[0].time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'start'}</span><span>${current?.time ? new Date(current.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'now'}</span></div></div><div class="replay-event"><span class="replay-index">${String(state.replayIndex + 1).padStart(2, '0')}</span><div><b>${esc(current?.label || 'No replay event')}</b><p>${esc(current?.detail || 'No event evidence available')}</p></div><span class="replay-source">${esc(current?.source || 'sensor')}</span></div><div class="replay-controls"><button class="replay-button" data-action="replay-toggle">${state.replayPlaying ? 'Pause replay' : 'Play replay'}</button><span>Evidence reconstructed from alert telemetry</span></div></section>`;
}

function render(): void {
  const visible = filteredAlerts();
  const selected = selectedAlert();
  const highCount = state.alerts.filter((alert) => alert.severity === 'CRITICAL' || alert.severity === 'HIGH').length;
  const activeCount = state.alerts.filter((alert) => alert.status === 'active').length;
  const selectedMeta = metadata(selected);
  const phases = Array.isArray(selectedMeta.phases) ? selectedMeta.phases as string[] : ['reconnaissance', 'access', 'exploitation'];

  app.innerHTML = `<main class="shell">
    <header class="topbar">
      <div class="brand"><div class="brand-mark">NW</div><div><p class="eyebrow">HONEYPOT OPERATIONS</p><h1>Nightwatch</h1></div></div>
      <div class="top-actions"><span class="sync"><i class="status-dot ${state.live ? 'online' : ''}"></i>${state.demo ? 'DEMO STREAM' : 'LIVE STREAM'}</span><button class="icon-button" data-action="settings" title="Configure API">⚙</button><button class="operator">MK<span>operator</span></button></div>
    </header>
    <section class="hero-row">
      <div><p class="eyebrow">REAL-TIME INVESTIGATION DESK</p><h2>See the story<br><em>before it spreads.</em></h2></div>
      <div class="hero-meta"><span class="live-ping"></span><strong>${state.live ? 'Monitoring now' : 'Monitoring paused'}</strong><small>Last sync ${state.lastSync.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</small></div>
    </section>
    ${state.demo ? '<div class="demo-note">Local preview data is active <button data-action="settings">Connect your alert API →</button></div>' : ''}
    <section class="stat-strip">
      <div class="stat"><span>OPEN SIGNALS</span><strong>${activeCount}</strong><small>requiring attention</small></div>
      <div class="stat accent"><span>HIGH CONFIDENCE</span><strong>${highCount}</strong><small>high or critical</small></div>
      <div class="stat"><span>SENSORS ONLINE</span><strong>06 <b>●</b></strong><small>all reporting</small></div>
      <div class="stat"><span>EVENT VELOCITY</span><strong>18<span>/min</span></strong><small class="up">↑ 24% from last hour</small></div>
    </section>
    <section class="workspace">
      <aside class="signal-rail">
        <div class="panel-head"><div><p class="eyebrow">SIGNAL FEED</p><h3>${visible.length} investigations</h3></div><button class="filter-button" data-action="filter">⌄</button></div>
        <div class="filter-row"><input id="search" value="${esc(state.search)}" placeholder="Search IP, tactic, service..."/><select id="severity"><option value="ALL" ${state.severity === 'ALL' ? 'selected' : ''}>All severity</option><option value="CRITICAL" ${state.severity === 'CRITICAL' ? 'selected' : ''}>Critical</option><option value="HIGH" ${state.severity === 'HIGH' ? 'selected' : ''}>High</option><option value="MEDIUM" ${state.severity === 'MEDIUM' ? 'selected' : ''}>Medium</option></select></div>
        <div class="alert-list">${visible.map((alert) => `<button class="alert-card ${alert.id === selected.id ? 'selected' : ''}" data-alert-id="${esc(alert.id)}"><div class="card-top"><span class="severity-pill ${severityClass(alert.severity)}">${esc(alert.severity)}</span><time>${relativeTime(alert.last_seen || alert.first_seen)}</time></div><strong>${esc(alert.alert_name)}</strong><p>${esc(alert.description)}</p><div class="card-foot"><span>${esc(alert.source_ip || 'unknown source')}</span><span>${esc(alert.service_name || 'sensor')}</span></div></button>`).join('')}</div>
        <div class="rail-foot"><span class="status-dot online"></span> Polling every 10 seconds <button data-action="toggle-live">${state.live ? 'Pause' : 'Resume'}</button></div>
      </aside>
      <article class="investigation">
        <div class="investigation-head"><div><div class="crumb">INVESTIGATION / ${esc(selected.service_name || 'SIGNAL')}</div><h3>${esc(selected.alert_name)}</h3><p>${esc(selected.description)}</p></div><div class="head-actions"><span class="confidence">${Math.round((selected.threat_score || .72) * 100)}% confidence</span><button class="ack-button" data-action="ack">${selected.acknowledged || selected.status === 'acknowledged' ? 'Acknowledged' : 'Acknowledge'}</button></div></div>
        <div class="story-bar"><span class="story-icon">✦</span><div><b>ATTACK STORY</b><p>Activity traced from <strong>${esc(selected.source_ip || 'an unknown actor')}</strong> through ${esc(selected.honeypot_type || 'the sensor mesh')}.</p></div><span class="story-arrow">→</span></div>
        ${replayPanel(selected)}
        <div class="canvas-grid"><section class="canvas-panel timeline-panel"><div class="panel-head"><div><p class="eyebrow">CHAIN OF EVENTS</p><h3>Observed progression</h3></div><span class="event-count">${phases.length} phases</span></div><div class="timeline">${phases.map((phase, index) => `<div class="timeline-item"><div class="timeline-marker ${index === phases.length - 1 ? 'current' : ''}">${index + 1}</div><div><b>${esc(phase)}</b><p>${index === 0 ? 'Initial activity detected by sensor mesh' : index === 1 ? 'Credentials or service access attempted' : 'Payload behavior or persistence observed'}</p><time>${index === phases.length - 1 ? relativeTime(selected.last_seen || selected.first_seen) : `${index + 1} events earlier`}</time></div></div>`).join('')}</div></section><section class="canvas-panel map-panel"><div class="panel-head"><div><p class="eyebrow">RELATIONSHIP MAP</p><h3>Signal topology</h3></div><span class="map-key">● live path</span></div>${graph(selected)}</section></div>
        <section class="evidence-panel"><div class="panel-head"><div><p class="eyebrow">EVIDENCE LOCKER</p><h3>What we know</h3></div><span class="locked">▣ preserved</span></div><div class="evidence-grid"><div><span>Source address</span><strong>${esc(selected.source_ip || 'Unknown')}</strong></div><div><span>Target service</span><strong>${esc(selected.service_name || 'Unknown')}</strong></div><div><span>Threat level</span><strong class="${severityClass(selected.threat_level)}">${esc(selected.threat_level || selected.severity)}</strong></div><div><span>Detection ID</span><strong class="mono">${esc(selected.id.slice(0, 14))}</strong></div></div></section>
        <section class="response-panel"><div class="panel-head"><div><p class="eyebrow">RESPONSE CONTROL</p><h3>Decide what happens next</h3></div><span class="incident-state ${state.incidentStatus.toLowerCase()}">${state.incidentStatus}</span></div><div class="response-grid"><button class="response-action" data-action="contain" ${state.actionBusy ? 'disabled' : ''}><span class="action-icon">⊘</span><span><b>Contain source</b><small>Run the matching isolation playbook</small></span><strong>→</strong></button><button class="response-action" data-action="resolve" ${state.actionBusy ? 'disabled' : ''}><span class="action-icon">✓</span><span><b>Resolve incident</b><small>Close with an operator audit trail</small></span><strong>→</strong></button></div><div class="action-status"><span class="status-dot ${state.actionBusy ? 'online' : ''}"></span>${esc(state.actionMessage)}</div></section>
      </article>
    </section>
    <footer class="footer"><span>Nightwatch / deception intelligence console</span><span>API ${esc(state.apiUrl)} <i class="status-dot ${state.demo ? '' : 'online'}"></i></span></footer>
  </main>`;
  bindEvents();
}

function bindEvents(): void {
  document.querySelectorAll<HTMLElement>('[data-alert-id]').forEach((element) => element.onclick = () => { state.selectedId = element.dataset.alertId || state.selectedId; state.replayIndex = 0; state.replayPlaying = false; state.incidentStatus = 'OPEN'; state.actionMessage = 'Awaiting operator decision'; render(); });
  document.querySelector<HTMLInputElement>('#search')?.addEventListener('input', (event) => { state.search = (event.target as HTMLInputElement).value; render(); const input = document.querySelector<HTMLInputElement>('#search'); input?.focus(); input?.setSelectionRange(input.value.length, input.value.length); });
  document.querySelector<HTMLSelectElement>('#severity')?.addEventListener('change', (event) => { state.severity = (event.target as HTMLSelectElement).value; render(); });
  document.querySelectorAll<HTMLElement>('[data-action="toggle-live"]').forEach((button) => button.onclick = () => { state.live = !state.live; render(); });
  document.querySelectorAll<HTMLElement>('[data-action="ack"]').forEach((button) => button.onclick = acknowledge);
  document.querySelectorAll<HTMLElement>('[data-action="settings"]').forEach((button) => button.onclick = configureApi);
  document.querySelectorAll<HTMLElement>('[data-action="contain"]').forEach((button) => button.onclick = containSource);
  document.querySelectorAll<HTMLElement>('[data-action="resolve"]').forEach((button) => button.onclick = resolveIncident);
  document.querySelectorAll<HTMLElement>('[data-action="replay-toggle"]').forEach((button) => button.onclick = () => { state.replayPlaying = !state.replayPlaying; render(); });
  document.querySelector<HTMLInputElement>('#replay-scrubber')?.addEventListener('input', (event) => { state.replayIndex = Number((event.target as HTMLInputElement).value); state.replayPlaying = false; render(); });
}

async function acknowledge(): Promise<void> {
  const alert = selectedAlert();
  if (state.demo) { alert.acknowledged = true; alert.status = 'acknowledged'; render(); return; }
  try {
    await fetch(`${state.apiUrl.replace(/\/alerts$/, '')}/alerts/${alert.id}/acknowledge`, { method: 'POST', headers: authHeaders() });
    await fetchAlerts();
  } catch { state.demo = true; state.alerts = demoAlerts; render(); }
}

async function containSource(): Promise<void> {
  const alert = selectedAlert();
  state.actionBusy = true;
  state.actionMessage = state.demo ? 'Simulating containment in local preview...' : 'Finding a matching response playbook...';
  render();
  if (state.demo) {
    await new Promise((resolve) => window.setTimeout(resolve, 650));
    state.incidentStatus = 'CONTAINED';
    state.actionMessage = `Source ${alert.source_ip || 'actor'} marked for isolation (demo)`;
    state.actionBusy = false;
    render();
    return;
  }
  try {
    const playbookResponse = await fetch(`${state.apiUrl.replace(/\/alerts$/, '')}/playbooks`, { headers: authHeaders() });
    if (!playbookResponse.ok) throw new Error('Playbooks unavailable');
    const payload = await playbookResponse.json() as { playbooks?: Playbook[] };
    const playbook = payload.playbooks?.find((item) => /block|isolate|contain/i.test(`${item.id} ${item.name}`)) || payload.playbooks?.[0];
    if (!playbook) throw new Error('No response playbook configured');
    const response = await fetch(`${state.apiUrl.replace(/\/alerts$/, '')}/playbooks/${playbook.id}/execute`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ alert_id: alert.id, alert_data: alert, dry_run: false }),
    });
    if (!response.ok) throw new Error('Playbook execution failed');
    state.incidentStatus = 'CONTAINED';
    state.actionMessage = `${playbook.name} completed for ${alert.source_ip || 'source actor'}`;
  } catch (error) {
    state.actionMessage = error instanceof Error ? error.message : 'Containment could not be completed';
  }
  state.actionBusy = false;
  render();
}

async function resolveIncident(): Promise<void> {
  const alert = selectedAlert();
  state.actionBusy = true;
  state.actionMessage = state.demo ? 'Writing resolution to local preview...' : 'Recording resolution...';
  render();
  if (state.demo) {
    await new Promise((resolve) => window.setTimeout(resolve, 450));
    state.incidentStatus = 'RESOLVED';
    state.actionMessage = 'Incident resolved by operator (demo)';
    state.actionBusy = false;
    render();
    return;
  }
  try {
    const response = await fetch(`${state.apiUrl.replace(/\/alerts$/, '')}/alerts/${alert.id}/resolve`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ notes: 'Resolved from Nightwatch command center' }),
    });
    if (!response.ok) throw new Error('Resolution request failed');
    state.incidentStatus = 'RESOLVED';
    state.actionMessage = 'Incident resolved and audit entry recorded';
  } catch (error) {
    state.actionMessage = error instanceof Error ? error.message : 'Resolution could not be recorded';
  }
  state.actionBusy = false;
  render();
}

function authHeaders(): HeadersInit {
  if (!state.token) return {};
  return state.token.startsWith('Bearer ') ? { Authorization: state.token } : { 'X-API-Key': state.token };
}

function configureApi(): void {
  const url = window.prompt('Alert API URL', state.apiUrl);
  if (!url) return;
  const token = window.prompt('API key or Bearer token (optional)', state.token);
  state.apiUrl = url; state.token = token || '';
  localStorage.setItem('nightwatch-api', state.apiUrl); localStorage.setItem('nightwatch-token', state.token);
  fetchAlerts();
}

async function fetchAlerts(): Promise<void> {
  if (!state.live) return;
  try {
    const response = await fetch(`${state.apiUrl}?limit=50`, { headers: authHeaders() });
    if (!response.ok) throw new Error('API unavailable');
    const payload = await response.json() as { alerts?: Alert[] };
    state.alerts = payload.alerts || [];
    state.demo = false;
  } catch {
    state.alerts = demoAlerts;
    state.demo = true;
  }
  state.lastSync = new Date();
  render();
}

state.alerts = demoAlerts;
render();
setInterval(fetchAlerts, 10_000);
setInterval(() => {
  if (!state.replayPlaying) return;
  const length = replayEvents(selectedAlert()).length;
  if (state.replayIndex >= length - 1) { state.replayPlaying = false; return; }
  state.replayIndex += 1;
  render();
}, 1400);