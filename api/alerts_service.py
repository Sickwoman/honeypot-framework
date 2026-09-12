#!/usr/bin/env python3

################################################################################
# Honeypot Framework - Alert REST API Service
# Handles alert CRUD operations, querying, and management
################################################################################

import json
import logging
import os
import sqlite3
import subprocess
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, g, jsonify, request

from api.config import init_config
from api.decorators import require_permission
from api.env import PROJECT_ROOT, apply_schema
from api.middleware import (
    AuditLogger,
    log_request_response,
    rate_limit,
    setup_middleware,
)
from api.rbac import Permission
from api.user_manager import UserManager
from playbooks.playbook_executor import PlaybookExecutor
from playbooks.playbook_model import PlaybookManager

logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Initialize configuration
config = init_config()
app.config['SECRET_KEY'] = config.get('JWT_SECRET_KEY')

# Setup middleware
setup_middleware(app)

# Register authentication / user-management routes. Imported here rather than
# at the top of the file because api.auth_routes imports back from this
# module's app context; moving it up creates a circular import.
from api.auth_routes import auth_bp  # noqa: E402

app.register_blueprint(auth_bp)

# Ensure a bootstrap admin exists on first start (empty users table)
UserManager().ensure_default_admin()

# Initialize audit logger
audit_logger = AuditLogger()


class AlertService:
    """Service for alert database operations"""
    
    def __init__(self, db_path: str = None):
        """
        Initialize alert service
        
        Args:
            db_path: Path to SQLite database
        """
        self.db_path = db_path or config.get('ALERTS_DB_PATH')
        self._ensure_database()
    
    def _ensure_database(self):
        """Create database if it doesn't exist"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        apply_schema(self.db_path)
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection.

        WAL + a busy timeout because the API and the log ingestor run as
        separate processes against this same file (see docker-compose.yml);
        the default journal mode makes concurrent writes fail with
        "database is locked".
        """
        conn = sqlite3.connect(self.db_path, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=15000")
        return conn
    
    def create_alert(self, alert_data: Dict) -> str:
        """
        Create new alert
        
        Args:
            alert_data: Alert information
            
        Returns:
            Alert ID
        """
        alert_data = enrich_alert_with_threat_intel(alert_data) or alert_data
        alert_id = str(uuid.uuid4())
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO alerts (
                    id, alert_name, severity, status, source_ip, source_port,
                    honeypot_type, service_name, threat_level, threat_score,
                    is_known_attacker, threat_indicators, event_count, description,
                    first_seen, last_seen, metadata, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert_id,
                alert_data.get('alert_name'),
                alert_data.get('severity', 'MEDIUM'),
                alert_data.get('status', 'active'),
                alert_data.get('source_ip'),
                alert_data.get('source_port'),
                alert_data.get('honeypot_type'),
                alert_data.get('service_name'),
                alert_data.get('threat_level', 'UNKNOWN'),
                alert_data.get('threat_score', 0.0),
                alert_data.get('is_known_attacker', False),
                json.dumps(alert_data.get('threat_indicators', [])),
                alert_data.get('event_count', 1),
                alert_data.get('description'),
                datetime.utcnow(),
                datetime.utcnow(),
                json.dumps(alert_data.get('metadata', {})),
                datetime.utcnow(),
                datetime.utcnow()
            ))
            
            conn.commit()

        try:
            trigger_matching_playbooks(alert_data, alert_id=alert_id)
        except Exception:
            pass
        
        return alert_id
    
    def get_alert(self, alert_id: str) -> Optional[Dict]:
        """Get alert by ID"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
            row = cursor.fetchone()
            
            if row:
                return dict(row)
            return None
    
    def update_alert(self, alert_id: str, update_data: Dict) -> bool:
        """Update alert"""
        allowed_fields = [
            'status', 'acknowledged', 'acknowledged_by', 'acknowledged_at',
            'resolved', 'resolved_by', 'resolved_at', 'resolution_notes',
            'response_action', 'suppressed', 'suppressed_until', 'threat_score',
            'event_count'
        ]
        
        # Filter allowed fields
        safe_updates = {k: v for k, v in update_data.items() if k in allowed_fields}
        
        if not safe_updates:
            return False
        
        # Build UPDATE query
        set_clause = ', '.join([f"{k} = ?" for k in safe_updates.keys()])
        values = list(safe_updates.values()) + [alert_id]
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"UPDATE alerts SET {set_clause}, updated_at = CURRENT_TIMESTAMP WHERE id = ?", values)
            conn.commit()
            
            return cursor.rowcount > 0
    
    def delete_alert(self, alert_id: str) -> bool:
        """Delete alert (soft delete - archive it)"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE alerts 
                SET archived = 1, archived_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (alert_id,))
            conn.commit()
            
            return cursor.rowcount > 0
    
    def query_alerts(self, filters: Dict = None, limit: int = 100, offset: int = 0) -> Tuple[List[Dict], int]:
        """
        Query alerts with filters
        
        Args:
            filters: Query filters (severity, status, source_ip, etc.)
            limit: Number of results
            offset: Result offset
            
        Returns:
            Tuple of (alerts, total_count)
        """
        query = "SELECT * FROM alerts WHERE archived = 0"
        params = []
        
        # Apply filters
        if filters:
            if 'severity' in filters:
                query += " AND severity = ?"
                params.append(filters['severity'])
            
            if 'status' in filters:
                query += " AND status = ?"
                params.append(filters['status'])
            
            if 'source_ip' in filters:
                query += " AND source_ip = ?"
                params.append(filters['source_ip'])
            
            if 'honeypot_type' in filters:
                query += " AND honeypot_type = ?"
                params.append(filters['honeypot_type'])
            
            if 'service_name' in filters:
                query += " AND service_name = ?"
                params.append(filters['service_name'])
            
            if 'threat_level' in filters:
                query += " AND threat_level = ?"
                params.append(filters['threat_level'])
            
            if 'acknowledged' in filters:
                query += " AND acknowledged = ?"
                params.append(1 if filters['acknowledged'] else 0)
            
            if 'resolved' in filters:
                query += " AND resolved = ?"
                params.append(1 if filters['resolved'] else 0)
            
            # Date range
            if 'start_date' in filters:
                query += " AND first_seen >= ?"
                params.append(filters['start_date'])
            
            if 'end_date' in filters:
                query += " AND first_seen <= ?"
                params.append(filters['end_date'])
            
            # Threat score range
            if 'min_threat_score' in filters:
                query += " AND threat_score >= ?"
                params.append(filters['min_threat_score'])
            
            if 'max_threat_score' in filters:
                query += " AND threat_score <= ?"
                params.append(filters['max_threat_score'])
        
        # Count total
        count_query = f"SELECT COUNT(*) as count FROM ({query})"
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Get count
            cursor.execute(count_query, params)
            total_count = cursor.fetchone()['count']
            
            # Get paginated results
            query += " ORDER BY first_seen DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            alerts = [dict(row) for row in cursor.fetchall()]
        
        return alerts, total_count
    
    def get_alert_statistics(self) -> Dict:
        """Get alert statistics"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Get summary from view
            cursor.execute("SELECT * FROM alert_statistics")
            stats = {}
            for row in cursor.fetchall():
                stats[row['severity']] = {
                    'total': row['count'],
                    'active': row['active_count'],
                    'acknowledged': row['acknowledged_count'],
                    'resolved': row['resolved_count']
                }
            
            # Total statistics
            cursor.execute("SELECT COUNT(*) as total FROM alerts WHERE archived = 0")
            total = cursor.fetchone()['total']
            
            cursor.execute("SELECT COUNT(*) as unacknowledged FROM alerts WHERE archived = 0 AND acknowledged = 0")
            unacknowledged = cursor.fetchone()['unacknowledged']
            
            cursor.execute("SELECT COUNT(*) as active FROM alerts WHERE archived = 0 AND status = 'active'")
            active = cursor.fetchone()['active']
            
            return {
                'total_alerts': total,
                'unacknowledged': unacknowledged,
                'active': active,
                'by_severity': stats
            }
    
    def get_top_attacking_ips(self, limit: int = 10) -> List[Dict]:
        """Get top attacking IPs"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT source_ip, COUNT(*) as attack_count, MAX(threat_score) as max_threat_score,
                       COUNT(DISTINCT honeypot_type) as services_targeted
                FROM alerts
                WHERE archived = 0 AND source_ip IS NOT NULL
                GROUP BY source_ip
                ORDER BY attack_count DESC
                LIMIT ?
            """, (limit,))
            
            return [dict(row) for row in cursor.fetchall()]


_NODE_THREAT_INTEL_SCRIPT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'threatintel', 'advanced-threat-intel.js'))


def enrich_alert_with_threat_intel(alert_data: Optional[Dict]) -> Optional[Dict]:
    """Enhance an alert with threat-intel metadata from the Node-based enricher when possible."""
    if not alert_data or not alert_data.get('source_ip'):
        return alert_data

    if not os.path.exists(_NODE_THREAT_INTEL_SCRIPT):
        return alert_data

    try:
        result = subprocess.run(
            ['node', _NODE_THREAT_INTEL_SCRIPT, '--ip', str(alert_data['source_ip'])],
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, 'ABUSEIPDB_API_KEY': os.environ.get('ABUSEIPDB_API_KEY', ''), 'VT_API_KEY': os.environ.get('VT_API_KEY', '')},
        )
        if result.returncode != 0:
            return alert_data

        payload = json.loads(result.stdout or '{}')
        threat_intel = payload.get('threat_intel') or {}
        threat_score = threat_intel.get('threat_score', alert_data.get('threat_score', 0.0))
        threat_level = threat_intel.get('threat_level', alert_data.get('threat_level', 'UNKNOWN'))
        indicators = threat_intel.get('threat_indicators', alert_data.get('threat_indicators', []))

        enhanced = dict(alert_data)
        enhanced['threat_score'] = threat_score
        enhanced['threat_level'] = threat_level
        enhanced['threat_indicators'] = indicators
        enhanced['metadata'] = {**alert_data.get('metadata', {}), 'threat_intel': threat_intel}
        if 'severity' in enhanced and enhanced['severity'] in {'HIGH', 'CRITICAL'} and threat_level in {'HIGH', 'CRITICAL'}:
            enhanced['severity'] = enhanced['severity']
        return enhanced
    except Exception:
        return alert_data


# Initialize alert service
alert_service = AlertService()
playbook_manager = PlaybookManager(str(PROJECT_ROOT / 'playbooks'))
playbook_executor = PlaybookExecutor(playbook_manager, db_path=alert_service.db_path)


def trigger_matching_playbooks(alert_data: Dict, alert_id: Optional[str] = None, dry_run: bool = False, executed_by: str = "system") -> List[Any]:
    """Trigger all matching playbooks for a newly created alert."""
    if not alert_data:
        return []

    matching = playbook_manager.find_matching_playbooks(alert_data)
    executions = []
    for playbook in matching:
        execution = playbook_executor.execute_playbook(
            playbook.id,
            alert_data,
            alert_id=alert_id,
            dry_run=dry_run,
            executed_by=executed_by,
        )
        if execution:
            executions.append(execution)
    return executions


################################################################################
# ALERT ENDPOINTS
################################################################################

@app.route('/api/v1/alerts', methods=['POST'])
@require_permission(Permission.ALERTS_CREATE)
@log_request_response
def create_alert():
    """Create new alert"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required = ['alert_name', 'severity']
        if not all(field in data for field in required):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Create alert
        alert_id = alert_service.create_alert(data)
        
        # Log audit entry
        audit_logger.log_operation(
            operation='alert_created',
            resource_type='alert',
            resource_id=alert_id,
            action='create',
            user_id=g.user_id,
            status='success',
            details={'alert_name': data.get('alert_name')}
        )
        
        return jsonify({
            'id': alert_id,
            'created_at': datetime.utcnow().isoformat()
        }), 201
    
    except Exception:
        logger.exception("Unhandled error in %s", request.path)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/v1/alerts', methods=['GET'])
@require_permission(Permission.ALERTS_READ)
@rate_limit(max_requests=500)
@log_request_response
def get_alerts():
    """Query alerts with filters"""
    try:
        # Get query parameters
        limit = min(int(request.args.get('limit', 100)), 1000)
        offset = int(request.args.get('offset', 0))
        
        # Build filters
        filters = {}
        for param in ['severity', 'status', 'source_ip', 'honeypot_type', 'service_name', 'threat_level']:
            if param in request.args:
                filters[param] = request.args.get(param)
        
        if 'acknowledged' in request.args:
            filters['acknowledged'] = request.args.get('acknowledged').lower() == 'true'
        
        if 'resolved' in request.args:
            filters['resolved'] = request.args.get('resolved').lower() == 'true'
        
        # Query alerts
        alerts, total_count = alert_service.query_alerts(filters, limit, offset)
        
        return jsonify({
            'alerts': alerts,
            'total': total_count,
            'limit': limit,
            'offset': offset,
            'has_more': offset + limit < total_count
        })
    
    except Exception:
        logger.exception("Unhandled error in %s", request.path)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/v1/alerts/<alert_id>', methods=['GET'])
@require_permission(Permission.ALERTS_READ)
@log_request_response
def get_alert(alert_id):
    """Get specific alert"""
    try:
        alert = alert_service.get_alert(alert_id)
        
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404
        
        return jsonify(alert)
    
    except Exception:
        logger.exception("Unhandled error in %s", request.path)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/v1/alerts/<alert_id>', methods=['PUT'])
@require_permission(Permission.ALERTS_UPDATE)
@log_request_response
def update_alert(alert_id):
    """Update alert"""
    try:
        data = request.get_json()
        
        # Update alert
        if alert_service.update_alert(alert_id, data):
            # Log audit entry
            audit_logger.log_operation(
                operation='alert_updated',
                resource_type='alert',
                resource_id=alert_id,
                action='update',
                user_id=g.user_id,
                status='success',
                details=data
            )
            
            # Get updated alert
            alert = alert_service.get_alert(alert_id)
            return jsonify(alert)
        else:
            return jsonify({'error': 'Alert not found'}), 404
    
    except Exception:
        logger.exception("Unhandled error in %s", request.path)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/v1/alerts/<alert_id>/acknowledge', methods=['POST'])
@require_permission(Permission.ALERTS_ACKNOWLEDGE)
@log_request_response
def acknowledge_alert(alert_id):
    """Acknowledge alert"""
    try:
        data = request.get_json() or {}
        
        # Update alert
        update_data = {
            'acknowledged': True,
            'acknowledged_by': g.username,
            'acknowledged_at': datetime.utcnow().isoformat(),
            'status': 'acknowledged'
        }
        
        if alert_service.update_alert(alert_id, update_data):
            audit_logger.log_operation(
                operation='alert_acknowledged',
                resource_type='alert',
                resource_id=alert_id,
                action='acknowledge',
                user_id=g.user_id,
                status='success',
                details={'reason': data.get('reason')}
            )
            
            return jsonify({'status': 'acknowledged'})
        else:
            return jsonify({'error': 'Alert not found'}), 404
    
    except Exception:
        logger.exception("Unhandled error in %s", request.path)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/v1/alerts/<alert_id>/resolve', methods=['POST'])
@require_permission(Permission.ALERTS_RESOLVE)
@log_request_response
def resolve_alert(alert_id):
    """Resolve alert"""
    try:
        data = request.get_json() or {}
        
        # Update alert
        update_data = {
            'resolved': True,
            'resolved_by': g.username,
            'resolved_at': datetime.utcnow().isoformat(),
            'status': 'resolved',
            'resolution_notes': data.get('notes')
        }
        
        if alert_service.update_alert(alert_id, update_data):
            audit_logger.log_operation(
                operation='alert_resolved',
                resource_type='alert',
                resource_id=alert_id,
                action='resolve',
                user_id=g.user_id,
                status='success',
                details={'notes': data.get('notes')}
            )
            
            return jsonify({'status': 'resolved'})
        else:
            return jsonify({'error': 'Alert not found'}), 404
    
    except Exception:
        logger.exception("Unhandled error in %s", request.path)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/v1/alerts/<alert_id>', methods=['DELETE'])
@require_permission(Permission.ALERTS_DELETE)
@log_request_response
def delete_alert(alert_id):
    """Delete (archive) alert"""
    try:
        if alert_service.delete_alert(alert_id):
            audit_logger.log_operation(
                operation='alert_archived',
                resource_type='alert',
                resource_id=alert_id,
                action='delete',
                user_id=g.user_id,
                status='success'
            )
            
            return jsonify({'status': 'archived'})
        else:
            return jsonify({'error': 'Alert not found'}), 404
    
    except Exception:
        logger.exception("Unhandled error in %s", request.path)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/v1/alerts/statistics', methods=['GET'])
@require_permission(Permission.STATS_READ)
@rate_limit(max_requests=100)
@log_request_response
def get_statistics():
    """Get alert statistics"""
    try:
        stats = alert_service.get_alert_statistics()
        return jsonify(stats)
    
    except Exception:
        logger.exception("Unhandled error in %s", request.path)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/v1/alerts/top-ips', methods=['GET'])
@require_permission(Permission.STATS_READ)
@rate_limit(max_requests=100)
@log_request_response
def get_top_ips():
    """Get top attacking IPs"""
    try:
        limit = int(request.args.get('limit', 10))
        ips = alert_service.get_top_attacking_ips(limit)
        return jsonify({'top_ips': ips})
    
    except Exception:
        logger.exception("Unhandled error in %s", request.path)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/v1/correlations', methods=['GET'])
@require_permission(Permission.STATS_READ)
@rate_limit(max_requests=60)
@log_request_response
def get_correlations():
    """Run the attack correlation engine over stored alerts.

    Query params:
        lookback: hours to look back (default: engine config; 0 = all)
        graph:    'true' to also include an attack-graph representation
    """
    try:
        from analytics.correlation_engine import CorrelationEngine
        lookback = request.args.get('lookback')
        engine = CorrelationEngine(db_path=alert_service.db_path)
        alerts = engine.load_alerts(
            lookback_hours=int(lookback) if lookback is not None else None)
        campaigns = engine.correlate(alerts)

        payload = {
            'analyzed_alerts': len(alerts),
            'campaign_count': len(campaigns),
            'campaigns': [c.to_dict() for c in campaigns],
        }
        if request.args.get('graph', '').lower() == 'true':
            from analytics.attack_graph import AttackGraph
            payload['graph'] = AttackGraph.from_campaigns(campaigns).to_dict()
        return jsonify(payload)

    except Exception:
        logger.exception("Unhandled error in %s", request.path)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/v1/playbooks', methods=['GET'])
@require_permission(Permission.PLAYBOOKS_READ)
@log_request_response
def list_playbooks():
    """List playbooks available to the framework."""
    try:
        playbooks = [p.to_dict() for p in playbook_manager.list_playbooks(enabled_only=False)]
        return jsonify({'playbooks': playbooks})
    except Exception:
        logger.exception("Unhandled error in %s", request.path)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/v1/playbooks', methods=['POST'])
@require_permission(Permission.PLAYBOOKS_WRITE)
@log_request_response
def create_playbook():
    """Create a playbook from a dictionary definition."""
    try:
        data = request.get_json(silent=True) or {}
        if not data:
            return jsonify({'error': 'Playbook definition is required'}), 400

        playbook = playbook_manager.create_playbook(data)
        return jsonify({'playbook': playbook.to_dict()}), 201
    except ValueError as e:
        # Schema validation failures are the caller's problem to fix.
        return jsonify({'error': str(e)}), 400
    except Exception:
        logger.exception("Unhandled error in %s", request.path)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/v1/playbooks/<playbook_id>', methods=['GET'])
@require_permission(Permission.PLAYBOOKS_READ)
@log_request_response
def get_playbook(playbook_id):
    """Fetch a single playbook definition."""
    try:
        playbook = playbook_manager.get_playbook(playbook_id)
        if not playbook:
            return jsonify({'error': 'Playbook not found'}), 404
        return jsonify({'playbook': playbook.to_dict()})
    except Exception:
        logger.exception("Unhandled error in %s", request.path)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/v1/playbooks/<playbook_id>', methods=['PUT'])
@require_permission(Permission.PLAYBOOKS_WRITE)
@log_request_response
def update_playbook(playbook_id):
    """Update an existing playbook."""
    try:
        data = request.get_json(silent=True) or {}
        if not data:
            return jsonify({'error': 'No playbook updates provided'}), 400

        updated = playbook_manager.update_playbook(playbook_id, data)
        if not updated:
            return jsonify({'error': 'Playbook not found'}), 404

        return jsonify({'playbook': updated.to_dict()})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception:
        logger.exception("Unhandled error in %s", request.path)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/v1/playbooks/<playbook_id>', methods=['DELETE'])
@require_permission(Permission.PLAYBOOKS_WRITE)
@log_request_response
def delete_playbook(playbook_id):
    """Delete a playbook."""
    try:
        deleted = playbook_manager.delete_playbook(playbook_id)
        if not deleted:
            return jsonify({'error': 'Playbook not found'}), 404
        return jsonify({'status': 'deleted', 'playbook_id': playbook_id})
    except Exception:
        logger.exception("Unhandled error in %s", request.path)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/v1/playbooks/<playbook_id>/execute', methods=['POST'])
@require_permission(Permission.PLAYBOOKS_EXECUTE)
@log_request_response
def execute_playbook_route(playbook_id):
    """Execute a named playbook against a supplied alert payload."""
    try:
        data = request.get_json(silent=True) or {}
        alert_data = data.get('alert_data') or data.get('alert') or {}
        dry_run = bool(data.get('dry_run', False))
        alert_id = data.get('alert_id') or alert_data.get('id')

        execution = playbook_executor.execute_playbook(
            playbook_id=playbook_id,
            alert_data=alert_data,
            alert_id=alert_id,
            dry_run=dry_run,
            executed_by=g.username,
        )

        if not execution:
            return jsonify({'error': 'Playbook not found or execution failed'}), 404

        return jsonify({'execution': execution.to_dict()})
    except Exception:
        logger.exception("Unhandled error in %s", request.path)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/v1/playbooks/<playbook_id>/history', methods=['GET'])
@require_permission(Permission.PLAYBOOKS_READ)
@log_request_response
def get_playbook_history(playbook_id):
    """Fetch execution history for a playbook."""
    try:
        history = playbook_executor.get_execution_history(playbook_id, limit=25)
        return jsonify({'history': history})
    except Exception:
        logger.exception("Unhandled error in %s", request.path)
        return jsonify({'error': 'Internal server error'}), 500


################################################################################
# HEALTH CHECK
################################################################################

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    })


################################################################################
# MAIN
################################################################################

if __name__ == '__main__':
    import ssl

    from api.config import ConfigurationError

    # Get configuration
    host = config.get('API_HOST', '0.0.0.0')
    port = config.get('API_PORT', 8443)
    debug = config.get('API_DEBUG', False)

    # Fail fast on a misconfigured deployment rather than serving traffic
    # with a default secret, missing certs, or debug mode enabled.
    if not debug:
        try:
            config.validate_production()
        except ConfigurationError as e:
            print(f"✗ {e}")
            raise SystemExit(1) from e

    try:
        config.ensure_ssl_certificates()
    except ConfigurationError as e:
        print(f"✗ {e}")
        raise SystemExit(1) from e

    # SSL/TLS context
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(
        certfile=config.get('SSL_API_CERT_PATH'),
        keyfile=config.get('SSL_API_KEY_PATH')
    )
    
    print("\n🍯 Honeypot Framework - Alert API Server")
    print(f"📍 Starting on {host}:{port}")
    print("🔐 SSL/TLS enabled")
    print("\n✓ Ready to accept connections")
    
    # Run server
    app.run(
        host=host,
        port=port,
        debug=debug,
        ssl_context=ssl_context,
        use_reloader=False
    )
