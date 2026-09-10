#!/usr/bin/env python3

################################################################################
# Honeypot Framework - Action Handlers for Playbooks
# Implements various response actions (block, notify, isolate, etc.)
################################################################################

import os
import json
import ipaddress
import subprocess
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Configure logging
logger = logging.getLogger(__name__)

# Firewall rules added by playbooks are journalled here so
# scripts/expire-firewall-blocks.py can remove them once they expire.
FIREWALL_RULES_FILE = os.getenv(
    'HONEYPOT_FIREWALL_RULES_FILE', '/etc/honeypot-framework/firewall-rules.jsonl'
)

# Ports the honeypot deliberately exposes. isolate_honeypot drops traffic to
# these only -- never a blanket INPUT DROP, which would also cut off the
# management/SSH path used to recover the host.
DEFAULT_HONEYPOT_PORTS = (2222, 2223)


def parse_duration_seconds(duration_str: Any) -> int:
    """Parse a duration like '24h', '30m', '7d' or a bare int into seconds."""
    if isinstance(duration_str, int):
        return duration_str

    duration_str = str(duration_str).lower().strip()
    multipliers = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}

    for unit, multiplier in multipliers.items():
        if duration_str.endswith(unit):
            try:
                return int(duration_str[:-1]) * multiplier
            except ValueError:
                return 0

    try:
        return int(duration_str)
    except ValueError:
        return 0


def validate_ip(value: Any) -> str:
    """Return `value` as a normalized IP string, or raise ValueError.

    Alert fields originate from attacker-controlled honeypot traffic, so every
    IP must be validated before it reaches a firewall command or a rules file.
    """
    return str(ipaddress.ip_address(str(value).strip()))


def _record_firewall_rule(entry: Dict[str, Any]):
    """Append a firewall rule to the expiry journal (one JSON object per line)."""
    os.makedirs(os.path.dirname(FIREWALL_RULES_FILE), exist_ok=True)
    with open(FIREWALL_RULES_FILE, 'a') as f:
        f.write(json.dumps(entry) + "\n")


class ActionHandler(ABC):
    """Base class for all action handlers"""
    
    def __init__(self, action_config: Dict[str, Any]):
        """
        Initialize action handler
        
        Args:
            action_config: Action configuration from playbook
        """
        self.action_config = action_config
        self.action_id = action_config.get('id', '')
        self.action_type = action_config.get('type', '')
    
    @abstractmethod
    def execute(self, context: Dict[str, Any], dry_run: bool = False) -> Tuple[bool, Dict]:
        """
        Execute action
        
        Args:
            context: Execution context with alert data
            dry_run: If True, don't actually execute (just validate)
            
        Returns:
            Tuple of (success, output_dict)
        """
        pass


class BlockIPHandler(ActionHandler):
    """Block attacker IP address"""
    
    def execute(self, context: Dict[str, Any], dry_run: bool = False) -> Tuple[bool, Dict]:
        """Block IP using iptables or firewall"""
        try:
            raw_ip = context.get('alert_data', {}).get('source_ip')
            if not raw_ip:
                return False, {'error': 'No source IP found in alert'}

            try:
                source_ip = validate_ip(raw_ip)
            except ValueError:
                logger.warning("Refusing to block malformed source IP: %r", raw_ip)
                return False, {'error': 'Invalid source IP in alert'}

            duration = self.action_config.get('duration', '24h')
            duration_seconds = parse_duration_seconds(duration)

            if dry_run:
                return True, {
                    'action': 'block_ip',
                    'ip': source_ip,
                    'duration': duration,
                    'message': f'[DRY RUN] Would block {source_ip} for {duration}'
                }

            expires_at = datetime.utcnow() + timedelta(seconds=duration_seconds)
            result = subprocess.run(
                ['sudo', 'iptables', '-I', 'INPUT', '-s', source_ip, '-j', 'DROP'],
                capture_output=True, text=True,
            )

            if result.returncode != 0:
                return False, {'error': result.stderr}

            _record_firewall_rule({
                'type': 'block_ip',
                'ip': source_ip,
                'duration': duration,
                'blocked_at': datetime.utcnow().isoformat(),
                'expires_at': expires_at.isoformat(),
            })

            logger.info(f"Blocked IP: {source_ip} (expires {expires_at.isoformat()})")

            return True, {
                'action': 'block_ip',
                'ip': source_ip,
                'duration': duration,
                'expires_at': expires_at.isoformat(),
                'message': f'Blocked {source_ip} until {expires_at.isoformat()}'
            }

        except Exception as e:
            logger.error(f"Error blocking IP: {e}")
            return False, {'error': str(e)}


class NotifyHandler(ActionHandler):
    """Send notifications via email, Slack, Discord, etc."""
    
    def execute(self, context: Dict[str, Any], dry_run: bool = False) -> Tuple[bool, Dict]:
        """Send notification"""
        try:
            channels = self.action_config.get('channels', [])
            message_template = self.action_config.get('message', '')
            
            # Format message with context variables
            message = self._format_message(message_template, context)
            
            if dry_run:
                return True, {
                    'action': 'notify',
                    'channels': channels,
                    'message': message,
                    'dry_run': True,
                    'message_text': f'[DRY RUN] Would send notification to {", ".join(channels)}'
                }
            
            results = {}
            success_count = 0
            
            for channel in channels:
                if channel == 'email':
                    success, output = self._send_email(message, context)
                    results['email'] = output
                    if success:
                        success_count += 1
                
                elif channel == 'slack':
                    success, output = self._send_slack(message, context)
                    results['slack'] = output
                    if success:
                        success_count += 1
                
                elif channel == 'discord':
                    success, output = self._send_discord(message, context)
                    results['discord'] = output
                    if success:
                        success_count += 1
            
            return success_count > 0, {
                'action': 'notify',
                'channels': channels,
                'results': results,
                'message': f'Sent to {success_count}/{len(channels)} channels'
            }
        
        except Exception as e:
            logger.error(f"Error sending notification: {e}")
            return False, {'error': str(e)}
    
    def _format_message(self, template: str, context: Dict) -> str:
        """Format message with context variables"""
        alert_data = context.get('alert_data', {})
        
        # Simple templating
        message = template
        message = message.replace('{{ source_ip }}', str(alert_data.get('source_ip', '')))
        message = message.replace('{{ alert_name }}', str(alert_data.get('alert_name', '')))
        message = message.replace('{{ severity }}', str(alert_data.get('severity', '')))
        message = message.replace('{{ honeypot_type }}', str(alert_data.get('honeypot_type', '')))
        message = message.replace('{{ timestamp }}', datetime.utcnow().isoformat())
        
        return message
    
    def _send_email(self, message: str, context: Dict) -> Tuple[bool, Dict]:
        """Send email notification"""
        try:
            smtp_host = os.getenv('SMTP_HOST', 'localhost')
            smtp_port = int(os.getenv('SMTP_PORT', 587))
            smtp_user = os.getenv('SMTP_USER', '')
            smtp_password = os.getenv('SMTP_PASSWORD', '')
            from_addr = os.getenv('SMTP_FROM', 'alerts@honeypot.local')
            to_addr = self.action_config.get('recipient', os.getenv('ALERT_EMAIL', ''))
            
            subject = f"[Honeypot Alert] {context.get('alert_data', {}).get('alert_name', 'Incident')}"
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = from_addr
            msg['To'] = to_addr
            msg['Subject'] = subject
            msg.attach(MIMEText(message, 'plain'))
            
            # Send
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                if os.getenv('SMTP_TLS', 'true').lower() == 'true':
                    server.starttls()
                if smtp_user:
                    server.login(smtp_user, smtp_password)
                server.send_message(msg)
            
            logger.info(f"Sent email to {to_addr}")
            return True, {'email': to_addr, 'status': 'sent'}
        
        except Exception as e:
            logger.error(f"Error sending email: {e}")
            return False, {'error': str(e)}
    
    def _send_slack(self, message: str, context: Dict) -> Tuple[bool, Dict]:
        """Send Slack notification"""
        try:
            webhook_url = self.action_config.get('webhook_url') or os.getenv('SLACK_WEBHOOK_URL')
            
            if not webhook_url:
                return False, {'error': 'No Slack webhook URL configured'}
            
            alert_data = context.get('alert_data', {})
            
            payload = {
                'text': 'Honeypot Alert - Automatic Response Executed',
                'attachments': [{
                    'color': 'danger',
                    'fields': [
                        {'title': 'Alert', 'value': alert_data.get('alert_name', 'N/A'), 'short': True},
                        {'title': 'Severity', 'value': alert_data.get('severity', 'N/A'), 'short': True},
                        {'title': 'Source IP', 'value': alert_data.get('source_ip', 'N/A'), 'short': True},
                        {'title': 'Service', 'value': alert_data.get('service_name', 'N/A'), 'short': True},
                        {'title': 'Message', 'value': message, 'short': False}
                    ]
                }]
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            
            if response.status_code == 200:
                logger.info("Sent Slack notification")
                return True, {'status': 'sent', 'webhook': webhook_url}
            else:
                return False, {'error': f'HTTP {response.status_code}'}
        
        except Exception as e:
            logger.error(f"Error sending Slack notification: {e}")
            return False, {'error': str(e)}
    
    def _send_discord(self, message: str, context: Dict) -> Tuple[bool, Dict]:
        """Send Discord notification"""
        try:
            webhook_url = self.action_config.get('webhook_url') or os.getenv('DISCORD_WEBHOOK_URL')
            
            if not webhook_url:
                return False, {'error': 'No Discord webhook URL configured'}
            
            alert_data = context.get('alert_data', {})
            
            payload = {
                'content': 'Honeypot Alert - Automatic Response Executed',
                'embeds': [{
                    'title': alert_data.get('alert_name', 'Honeypot Alert'),
                    'color': 16711680,  # Red
                    'fields': [
                        {'name': 'Severity', 'value': alert_data.get('severity', 'N/A'), 'inline': True},
                        {'name': 'Source IP', 'value': alert_data.get('source_ip', 'N/A'), 'inline': True},
                        {'name': 'Service', 'value': alert_data.get('service_name', 'N/A'), 'inline': True},
                        {'name': 'Honeypot', 'value': alert_data.get('honeypot_type', 'N/A'), 'inline': True},
                        {'name': 'Response', 'value': message, 'inline': False}
                    ]
                }]
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            
            if response.status_code == 204:
                logger.info("Sent Discord notification")
                return True, {'status': 'sent', 'webhook': webhook_url}
            else:
                return False, {'error': f'HTTP {response.status_code}'}
        
        except Exception as e:
            logger.error(f"Error sending Discord notification: {e}")
            return False, {'error': str(e)}


class CreateIncidentHandler(ActionHandler):
    """Create incident from alert"""
    
    def execute(self, context: Dict[str, Any], dry_run: bool = False) -> Tuple[bool, Dict]:
        """Create incident"""
        try:
            alert_data = context.get('alert_data', {})
            
            incident_data = {
                'id': str(__import__('uuid').uuid4()),
                'title': self.action_config.get('title', f"Incident: {alert_data.get('alert_name')}"),
                'description': self.action_config.get('description', ''),
                'severity': self.action_config.get('severity', alert_data.get('severity')),
                'category': self.action_config.get('category', 'security_incident'),
                'alert_ids': [alert_data.get('id', '')],
                'status': 'open',
                'created_by': 'playbook_automation',
                'created_at': datetime.utcnow().isoformat()
            }
            
            if dry_run:
                return True, {
                    'action': 'create_incident',
                    'incident': incident_data,
                    'message': f'[DRY RUN] Would create incident'
                }
            
            # TODO: Insert into database
            # For now, just log
            logger.info(f"Created incident: {incident_data['id']}")
            
            return True, {
                'action': 'create_incident',
                'incident_id': incident_data['id'],
                'incident': incident_data,
                'message': f"Created incident {incident_data['id']}"
            }
        
        except Exception as e:
            logger.error(f"Error creating incident: {e}")
            return False, {'error': str(e)}


class IsolateHoneypotHandler(ActionHandler):
    """Isolate honeypot from network"""
    
    def execute(self, context: Dict[str, Any], dry_run: bool = False) -> Tuple[bool, Dict]:
        """Isolate the honeypot's exposed services.

        Only the honeypot service ports are dropped -- a blanket INPUT DROP
        would also sever the management/SSH path needed to recover the host.
        """
        try:
            isolation_duration = self.action_config.get('duration', '1h')
            preserve_logs = self.action_config.get('preserve_logs', True)
            duration_seconds = parse_duration_seconds(isolation_duration)

            try:
                ports = [int(p) for p in self.action_config.get('ports', DEFAULT_HONEYPOT_PORTS)]
            except (TypeError, ValueError):
                return False, {'error': 'Invalid ports in isolate_honeypot action config'}

            if not ports:
                return False, {'error': 'No honeypot ports configured to isolate'}

            if dry_run:
                return True, {
                    'action': 'isolate_honeypot',
                    'duration': isolation_duration,
                    'ports': ports,
                    'preserve_logs': preserve_logs,
                    'message': f'[DRY RUN] Would isolate ports {ports} for {isolation_duration}'
                }

            expires_at = datetime.utcnow() + timedelta(seconds=duration_seconds)
            for port in ports:
                result = subprocess.run(
                    ['sudo', 'iptables', '-I', 'INPUT', '-p', 'tcp',
                     '--dport', str(port), '-j', 'DROP'],
                    capture_output=True, text=True,
                )
                if result.returncode != 0:
                    return False, {'error': result.stderr}

                _record_firewall_rule({
                    'type': 'isolate_honeypot',
                    'port': port,
                    'duration': isolation_duration,
                    'blocked_at': datetime.utcnow().isoformat(),
                    'expires_at': expires_at.isoformat(),
                })

            logger.info(f"Isolated honeypot ports {ports} until {expires_at.isoformat()}")

            return True, {
                'action': 'isolate_honeypot',
                'duration': isolation_duration,
                'ports': ports,
                'expires_at': expires_at.isoformat(),
                'preserve_logs': preserve_logs,
                'message': f'Isolated ports {ports} until {expires_at.isoformat()}'
            }

        except Exception as e:
            logger.error(f"Error isolating honeypot: {e}")
            return False, {'error': str(e)}


class RunScriptHandler(ActionHandler):
    """Execute custom script"""
    
    def execute(self, context: Dict[str, Any], dry_run: bool = False) -> Tuple[bool, Dict]:
        """Execute script"""
        timeout = self.action_config.get('timeout', 30)
        try:
            script_path = self.action_config.get('script_path')
            script_args = self.action_config.get('args', [])

            if not script_path:
                return False, {'error': 'No script path provided'}
            
            # Build command
            cmd = [script_path] + script_args
            
            if dry_run:
                return True, {
                    'action': 'run_script',
                    'script': script_path,
                    'args': script_args,
                    'message': f'[DRY RUN] Would execute {script_path}'
                }
            
            # Execute
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            
            if result.returncode != 0:
                logger.error(f"Script error: {result.stderr}")
                return False, {'error': result.stderr}
            
            logger.info(f"Executed script: {script_path}")
            
            return True, {
                'action': 'run_script',
                'script': script_path,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'return_code': result.returncode,
                'message': f'Script executed successfully'
            }
        
        except subprocess.TimeoutExpired:
            return False, {'error': f'Script timeout after {timeout} seconds'}
        except Exception as e:
            logger.error(f"Error executing script: {e}")
            return False, {'error': str(e)}


class HTTPRequestHandler(ActionHandler):
    """Make HTTP request"""
    
    def execute(self, context: Dict[str, Any], dry_run: bool = False) -> Tuple[bool, Dict]:
        """Make HTTP request"""
        try:
            url = self.action_config.get('url')
            method = self.action_config.get('method', 'POST').upper()
            headers = self.action_config.get('headers', {})
            body = self.action_config.get('body', {})
            timeout = self.action_config.get('timeout', 10)
            
            if not url:
                return False, {'error': 'No URL provided'}
            
            if dry_run:
                return True, {
                    'action': 'http_request',
                    'url': url,
                    'method': method,
                    'message': f'[DRY RUN] Would make {method} request to {url}'
                }
            
            # Make request
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=timeout)
            elif method == 'POST':
                response = requests.post(url, json=body, headers=headers, timeout=timeout)
            elif method == 'PUT':
                response = requests.put(url, json=body, headers=headers, timeout=timeout)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers, timeout=timeout)
            else:
                return False, {'error': f'Unsupported HTTP method: {method}'}
            
            logger.info(f"HTTP {method} {url}: {response.status_code}")
            
            return response.status_code < 400, {
                'action': 'http_request',
                'url': url,
                'method': method,
                'status_code': response.status_code,
                'response': response.text[:500],
                'message': f'HTTP {method} returned {response.status_code}'
            }
        
        except Exception as e:
            logger.error(f"Error making HTTP request: {e}")
            return False, {'error': str(e)}


class DelayHandler(ActionHandler):
    """Wait/delay"""
    
    def execute(self, context: Dict[str, Any], dry_run: bool = False) -> Tuple[bool, Dict]:
        """Delay execution"""
        try:
            delay_seconds = parse_duration_seconds(self.action_config.get('duration', '0'))
            
            if dry_run:
                return True, {
                    'action': 'delay',
                    'duration': delay_seconds,
                    'message': f'[DRY RUN] Would wait {delay_seconds} seconds'
                }
            
            logger.info(f"Delaying for {delay_seconds} seconds")
            __import__('time').sleep(delay_seconds)
            
            return True, {
                'action': 'delay',
                'duration': delay_seconds,
                'message': f'Waited {delay_seconds} seconds'
            }

        except Exception as e:
            logger.error(f"Error in delay: {e}")
            return False, {'error': str(e)}


class ActionFactory:
    """Factory for creating action handlers"""
    
    HANDLERS = {
        'block_ip': BlockIPHandler,
        'notify': NotifyHandler,
        'create_incident': CreateIncidentHandler,
        'isolate_honeypot': IsolateHoneypotHandler,
        'run_script': RunScriptHandler,
        'http_request': HTTPRequestHandler,
        'delay': DelayHandler,
    }
    
    @staticmethod
    def create(action_config: Dict[str, Any]) -> Optional[ActionHandler]:
        """Create action handler"""
        action_type = action_config.get('type')
        handler_class = ActionFactory.HANDLERS.get(action_type)
        
        if not handler_class:
            logger.warning(f"Unknown action type: {action_type}")
            return None
        
        return handler_class(action_config)


if __name__ == "__main__":
    print("Action handlers module loaded")
