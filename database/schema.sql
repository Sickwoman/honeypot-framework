-- Honeypot Framework - Alert Database Schema
-- SQLite3 schema for persistent alert storage and historical tracking
-- Created: 2026-08-29
-- 
-- This schema provides:
-- - Alert persistence and querying
-- - Historical audit trail
-- - Incident tracking
-- - Alert acknowledgment workflow
-- - Performance indices for large datasets

-- ################################################################################
-- ALERTS TABLE
-- ################################################################################

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,                          -- Unique alert identifier (UUID)
    alert_name TEXT NOT NULL,                     -- Alert rule name (e.g., "HighAttackVolume")
    severity TEXT NOT NULL,                       -- Severity level: CRITICAL, HIGH, MEDIUM, LOW, INFO
    status TEXT NOT NULL DEFAULT 'active',        -- Status: active, acknowledged, resolved, suppressed
    
    -- Source Information
    source_ip VARCHAR(45),                        -- Source IP address (IPv4 or IPv6)
    source_port INTEGER,                          -- Source port
    honeypot_type TEXT,                           -- Honeypot type (cowrie, opencanary, etc.)
    service_name TEXT,                            -- Service targeted (ssh, http, ftp, etc.)
    
    -- Threat Intelligence
    threat_level TEXT,                            -- Threat level from intelligence (HIGH, MEDIUM, LOW, UNKNOWN)
    threat_score REAL,                            -- Risk score (0.0-1.0)
    is_known_attacker BOOLEAN DEFAULT 0,          -- Known malicious actor?
    threat_indicators TEXT,                       -- JSON array of threat indicators
    
    -- Event Details
    event_count INTEGER DEFAULT 1,                -- Number of events aggregated
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,-- First occurrence
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP, -- Most recent occurrence
    description TEXT,                             -- Human-readable description
    metadata TEXT,                                -- JSON metadata (flexible storage)
    
    -- Acknowledgment & Response
    acknowledged BOOLEAN DEFAULT 0,               -- Has alert been acknowledged?
    acknowledged_by TEXT,                         -- User who acknowledged
    acknowledged_at DATETIME,                     -- When acknowledged
    response_action TEXT,                         -- Action taken (blocked, monitored, escalated)
    
    -- Resolution
    resolved BOOLEAN DEFAULT 0,                   -- Has alert been resolved?
    resolved_by TEXT,                             -- User who resolved
    resolved_at DATETIME,                         -- When resolved
    resolution_notes TEXT,                        -- Resolution details
    
    -- Time Tracking
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,-- When alert was created
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,-- Last update
    
    -- Lifecycle
    suppressed BOOLEAN DEFAULT 0,                 -- Suppressed (ignored)?
    suppressed_until DATETIME,                    -- Suppression expiration
    archived BOOLEAN DEFAULT 0,                   -- Archived?
    archived_at DATETIME                          -- Archive timestamp
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_honeypot_type ON alerts(honeypot_type);
CREATE INDEX IF NOT EXISTS idx_alerts_service ON alerts(service_name);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_first_seen ON alerts(first_seen);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(first_seen DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_threat_level ON alerts(threat_level);

-- ################################################################################
-- ALERT HISTORY TABLE (Audit Trail)
-- ################################################################################

CREATE TABLE IF NOT EXISTS alert_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL,                      -- Reference to alerts.id
    
    -- Status Change
    old_status TEXT,                              -- Previous status
    new_status TEXT NOT NULL,                     -- New status
    status_changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    -- User Action
    changed_by TEXT,                              -- User who made change
    change_reason TEXT,                           -- Why change was made
    
    -- Additional Info
    action TEXT,                                  -- Action type (acknowledged, resolved, suppressed, etc.)
    details TEXT,                                 -- JSON with additional details
    
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE CASCADE
);

-- Indexes for history
CREATE INDEX IF NOT EXISTS idx_history_alert_id ON alert_history(alert_id);
CREATE INDEX IF NOT EXISTS idx_history_changed_by ON alert_history(changed_by);
CREATE INDEX IF NOT EXISTS idx_history_timestamp ON alert_history(created_at DESC);

-- ################################################################################
-- INCIDENTS TABLE
-- ################################################################################

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,                         -- Unique incident identifier (UUID)
    title TEXT NOT NULL,                         -- Incident title
    description TEXT,                            -- Detailed description
    
    -- Classification
    severity TEXT NOT NULL,                      -- Severity: CRITICAL, HIGH, MEDIUM, LOW
    category TEXT,                               -- Category (intrusion, reconnaissance, lateral movement, etc.)
    attack_phase TEXT,                           -- Attack phase (reconnaissance, exploitation, exfiltration, etc.)
    
    -- Relationship to Alerts
    alert_ids TEXT,                              -- JSON array of related alert IDs
    
    -- Status
    status TEXT NOT NULL DEFAULT 'open',         -- Status: open, investigating, contained, resolved, closed
    
    -- Assignment & Ownership
    assigned_to TEXT,                            -- Assigned analyst
    created_by TEXT,                             -- Who created incident
    
    -- Timeline
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    detected_at DATETIME,                        -- When attack detected
    start_time DATETIME,                         -- Attack start time
    end_time DATETIME,                           -- Attack end time
    
    -- Response
    response_action TEXT,                        -- Action taken
    impact_assessment TEXT,                      -- Assessment of attack impact
    remediation_steps TEXT,                      -- JSON array of remediation steps
    
    -- Resolution
    root_cause TEXT,                             -- Root cause analysis
    lessons_learned TEXT,                        -- Lessons learned
    closed_at DATETIME                           -- When incident closed
);

-- Indexes for incidents
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_assigned_to ON incidents(assigned_to);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at DESC);

-- ################################################################################
-- INCIDENT HISTORY TABLE (Timeline)
-- ################################################################################

CREATE TABLE IF NOT EXISTS incident_timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    
    -- Event
    event_type TEXT NOT NULL,                    -- Event type (created, updated, commented, action_taken, etc.)
    event_description TEXT,                      -- Event description
    
    -- User
    created_by TEXT,                             -- User who triggered event
    
    -- Details
    details TEXT,                                -- JSON with event details
    attachment_url TEXT,                         -- URL to evidence/screenshot
    
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_timeline_incident_id ON incident_timeline(incident_id);
CREATE INDEX IF NOT EXISTS idx_timeline_timestamp ON incident_timeline(created_at DESC);

-- ################################################################################
-- ALERT RULES TABLE
-- ################################################################################

CREATE TABLE IF NOT EXISTS alert_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,                   -- Rule name
    description TEXT,
    enabled BOOLEAN DEFAULT 1,
    
    -- Trigger Condition
    condition TEXT NOT NULL,                     -- Alert condition (JSON)
    threshold REAL,                              -- Trigger threshold
    time_window_seconds INTEGER,                 -- Time window for aggregation
    
    -- Severity
    severity TEXT NOT NULL,                      -- Default severity
    
    -- Actions
    notification_channels TEXT,                  -- JSON array of channels (email, slack, etc.)
    auto_acknowledge BOOLEAN DEFAULT 0,          -- Automatically acknowledge?
    auto_response_action TEXT,                   -- Auto-response (block, isolate, etc.)
    
    -- Management
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_by TEXT,
    
    -- Statistics
    total_alerts INTEGER DEFAULT 0,              -- Total alerts triggered by rule
    last_triggered DATETIME                      -- Last time rule triggered
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON alert_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_rules_severity ON alert_rules(severity);

-- ################################################################################
-- SUPPRESSION RULES TABLE
-- ################################################################################

CREATE TABLE IF NOT EXISTS suppression_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT 1,
    
    -- Suppression Criteria
    alert_name TEXT,                             -- Specific alert to suppress
    source_ip VARCHAR(45),                       -- Source IP to suppress
    honeypot_type TEXT,                          -- Honeypot type
    service_name TEXT,                           -- Service
    
    -- Duration
    active_from DATETIME,
    active_until DATETIME,
    
    -- Management
    created_by TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    reason TEXT,                                 -- Why suppressed
    
    UNIQUE(alert_name, source_ip, honeypot_type, service_name)
);

-- Index
CREATE INDEX IF NOT EXISTS idx_suppression_active ON suppression_rules(active_from, active_until);

-- ################################################################################
-- USERS & ROLES TABLE
-- ################################################################################

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT UNIQUE,
    password_hash TEXT NOT NULL,
    
    -- Profile
    full_name TEXT,
    role TEXT NOT NULL,                         -- Role: admin, analyst, responder, observer
    
    -- Status
    enabled BOOLEAN DEFAULT 1,
    last_login DATETIME,
    failed_login_attempts INTEGER DEFAULT 0,
    
    -- Audit
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT,
    
    -- MFA
    mfa_enabled BOOLEAN DEFAULT 0,
    mfa_secret TEXT                             -- Encrypted MFA secret
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- ################################################################################
-- AUDIT LOG TABLE
-- ################################################################################

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    -- User Action
    user_id TEXT,                                 -- User performing action
    action TEXT NOT NULL,                         -- Action type (create, update, delete, etc.)
    resource_type TEXT,                          -- Resource type (alert, incident, user, etc.)
    resource_id TEXT,                            -- ID of affected resource
    
    -- Details
    description TEXT,
    old_value TEXT,                              -- Old value (JSON)
    new_value TEXT,                              -- New value (JSON)
    
    -- Request
    ip_address VARCHAR(45),                      -- IP address of requester
    user_agent TEXT,                             -- User agent string
    
    -- Timestamp
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for audit log
CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_log(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);

-- ################################################################################
-- METRICS TABLE
-- ################################################################################

CREATE TABLE IF NOT EXISTS metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    -- Metric
    metric_name TEXT NOT NULL,                   -- e.g., "alerts_per_hour", "high_risk_attacks"
    metric_value REAL,                           -- Metric value
    metric_unit TEXT,                            -- Unit (count, percent, ms, etc.)
    
    -- Dimensions
    honeypot_type TEXT,
    severity TEXT,
    attack_type TEXT,
    
    -- Time
    period_start DATETIME,
    period_end DATETIME,
    recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_metrics_name ON metrics(metric_name);
CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(recorded_at DESC);

-- ################################################################################
-- VIEWS FOR COMMON QUERIES
-- ################################################################################

-- View: Recent active alerts
CREATE VIEW IF NOT EXISTS recent_active_alerts AS
SELECT 
    id,
    alert_name,
    severity,
    source_ip,
    honeypot_type,
    service_name,
    first_seen,
    threat_level,
    threat_score
FROM alerts
WHERE status = 'active' AND archived = 0
ORDER BY first_seen DESC
LIMIT 100;

-- View: Alert statistics
CREATE VIEW IF NOT EXISTS alert_statistics AS
SELECT 
    severity,
    COUNT(*) as count,
    COUNT(CASE WHEN status = 'active' THEN 1 END) as active_count,
    COUNT(CASE WHEN acknowledged THEN 1 END) as acknowledged_count,
    COUNT(CASE WHEN resolved THEN 1 END) as resolved_count
FROM alerts
WHERE archived = 0
GROUP BY severity;

-- View: Top attacking IPs
CREATE VIEW IF NOT EXISTS top_attacking_ips AS
SELECT 
    source_ip,
    COUNT(*) as attack_count,
    MAX(threat_score) as max_threat_score,
    COUNT(DISTINCT honeypot_type) as services_targeted,
    MAX(last_seen) as last_seen
FROM alerts
WHERE archived = 0
GROUP BY source_ip
ORDER BY attack_count DESC
LIMIT 50;

-- View: Incident summary
CREATE VIEW IF NOT EXISTS incident_summary AS
SELECT 
    status,
    COUNT(*) as count,
    COUNT(CASE WHEN severity = 'CRITICAL' THEN 1 END) as critical_count,
    COUNT(CASE WHEN severity = 'HIGH' THEN 1 END) as high_count,
    COUNT(CASE WHEN severity = 'MEDIUM' THEN 1 END) as medium_count
FROM incidents
WHERE closed_at IS NULL
GROUP BY status;

-- ################################################################################
-- TRIGGERS (Automatic Updates)
-- ################################################################################

-- Update alert timestamp on modification
CREATE TRIGGER IF NOT EXISTS update_alert_timestamp
AFTER UPDATE ON alerts
FOR EACH ROW
BEGIN
    UPDATE alerts SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- Update incident timestamp on modification
CREATE TRIGGER IF NOT EXISTS update_incident_timestamp
AFTER UPDATE ON incidents
FOR EACH ROW
BEGIN
    UPDATE incidents SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- ################################################################################
-- INITIALIZATION DATA
-- ################################################################################

-- Insert default alert rules (examples)
INSERT OR IGNORE INTO alert_rules (id, name, severity, condition, enabled, created_at) VALUES
('rule_001', 'HighAttackVolume', 'WARNING', '{"events_per_minute": ">10"}', 1, CURRENT_TIMESTAMP),
('rule_002', 'HighRiskIPDetected', 'CRITICAL', '{"threat_score": ">0.8"}', 1, CURRENT_TIMESTAMP),
('rule_003', 'BruteForceAttempt', 'HIGH', '{"failed_logins": ">5"}', 1, CURRENT_TIMESTAMP),
('rule_004', 'SuspiciousCommand', 'MEDIUM', '{"command_pattern": "malware"}', 1, CURRENT_TIMESTAMP);

-- ################################################################################
-- MAINTENANCE
-- ################################################################################

-- Auto-archive old alerts (older than 90 days)
-- Run via cron: sqlite3 alerts.db < maintenance.sql

-- PRAGMA foreign_keys = ON;  -- Uncomment to enable foreign key constraints
-- PRAGMA journal_mode = WAL;  -- Write-ahead logging for better concurrency
-- PRAGMA synchronous = NORMAL; -- Balance safety and performance

-- ################################################################################
-- END OF SCHEMA
-- ################################################################################
