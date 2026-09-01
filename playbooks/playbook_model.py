#!/usr/bin/env python3

################################################################################
# Honeypot Framework - Incident Response Playbook System
# Automates incident response with YAML-defined playbooks
################################################################################

import os
import yaml
import json
import uuid
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
from dataclasses import dataclass, field, asdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PlaybookStatus(str, Enum):
    """Playbook execution status"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ActionStatus(str, Enum):
    """Individual action status"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ActionResult:
    """Result of a single action execution"""
    action_id: str
    action_type: str
    status: ActionStatus
    output: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'action_id': self.action_id,
            'action_type': self.action_type,
            'status': self.status.value,
            'output': self.output,
            'error': self.error,
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'duration_seconds': self.duration_seconds
        }


@dataclass
class PlaybookExecution:
    """Playbook execution record"""
    execution_id: str
    playbook_id: str
    playbook_name: str
    trigger_alert_id: str
    trigger_data: Dict[str, Any]
    status: PlaybookStatus = PlaybookStatus.PENDING
    actions_results: List[ActionResult] = field(default_factory=list)
    dry_run: bool = False
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    executed_by: str = "system"
    notes: str = ""
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'execution_id': self.execution_id,
            'playbook_id': self.playbook_id,
            'playbook_name': self.playbook_name,
            'trigger_alert_id': self.trigger_alert_id,
            'trigger_data': self.trigger_data,
            'status': self.status.value,
            'actions_results': [r.to_dict() for r in self.actions_results],
            'dry_run': self.dry_run,
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'duration_seconds': self.duration_seconds,
            'executed_by': self.executed_by,
            'notes': self.notes
        }


class PlaybookSchema:
    """Validate playbook schema"""
    
    REQUIRED_FIELDS = ['id', 'name', 'description', 'trigger', 'actions']
    
    TRIGGER_TYPES = [
        'alert',           # Based on alert properties
        'incident',        # Based on incident properties
        'schedule',        # Based on time schedule
        'manual',          # Manual trigger
        'webhook'          # Webhook trigger
    ]
    
    ACTION_TYPES = [
        'block_ip',                # Block IP at firewall/iptables
        'notify',                  # Send notification
        'create_incident',         # Create new incident
        'isolate_honeypot',        # Isolate honeypot
        'collect_evidence',        # Collect forensic evidence
        'escalate',                # Escalate to higher severity
        'run_script',              # Run custom script
        'http_request',            # Make HTTP request
        'database_update',         # Update database
        'delay',                   # Wait/delay
        'condition',               # Conditional branch
        'parallel',                # Run actions in parallel
        'execute_playbook'         # Execute another playbook
    ]
    
    @staticmethod
    def validate(playbook_dict: Dict) -> Tuple[bool, List[str]]:
        """
        Validate playbook schema
        
        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []
        
        # Check required fields
        for field in PlaybookSchema.REQUIRED_FIELDS:
            if field not in playbook_dict:
                errors.append(f"Missing required field: {field}")
        
        if errors:
            return False, errors
        
        # Validate trigger
        trigger = playbook_dict.get('trigger', {})
        if isinstance(trigger, dict):
            if 'type' not in trigger:
                errors.append("Trigger must have 'type' field")
            elif trigger['type'] not in PlaybookSchema.TRIGGER_TYPES:
                errors.append(f"Invalid trigger type: {trigger['type']}")
        else:
            errors.append("Trigger must be a dictionary")
        
        # Validate actions
        actions = playbook_dict.get('actions', [])
        if not isinstance(actions, list):
            errors.append("Actions must be a list")
        elif len(actions) == 0:
            errors.append("At least one action is required")
        else:
            for i, action in enumerate(actions):
                if not isinstance(action, dict):
                    errors.append(f"Action {i} must be a dictionary")
                elif 'type' not in action:
                    errors.append(f"Action {i} missing 'type' field")
                elif action['type'] not in PlaybookSchema.ACTION_TYPES:
                    errors.append(f"Action {i} has invalid type: {action['type']}")
        
        return len(errors) == 0, errors


class PlaybookDefinition:
    """Playbook definition model"""
    
    def __init__(self, playbook_dict: Dict):
        """
        Initialize playbook from dictionary
        
        Args:
            playbook_dict: Playbook definition
        """
        # Validate schema
        is_valid, errors = PlaybookSchema.validate(playbook_dict)
        if not is_valid:
            raise ValueError(f"Invalid playbook schema: {', '.join(errors)}")
        
        self.id = playbook_dict.get('id', str(uuid.uuid4()))
        self.name = playbook_dict.get('name')
        self.description = playbook_dict.get('description')
        self.version = playbook_dict.get('version', '1.0.0')
        self.author = playbook_dict.get('author', 'unknown')
        self.enabled = playbook_dict.get('enabled', True)
        self.tags = playbook_dict.get('tags', [])
        
        # Trigger configuration
        self.trigger = playbook_dict.get('trigger')
        
        # Actions
        self.actions = playbook_dict.get('actions', [])
        
        # Error handling
        self.on_failure = playbook_dict.get('on_failure', 'stop')  # stop, continue, rollback
        self.timeout_seconds = playbook_dict.get('timeout_seconds', 3600)
        
        # Metadata
        self.created_at = playbook_dict.get('created_at', datetime.utcnow().isoformat())
        self.updated_at = playbook_dict.get('updated_at', datetime.utcnow().isoformat())
    
    def matches_trigger(self, alert_data: Dict) -> bool:
        """
        Check if alert matches playbook trigger
        
        Args:
            alert_data: Alert data from database
            
        Returns:
            True if alert matches trigger condition
        """
        trigger = self.trigger
        
        if trigger['type'] == 'alert':
            # Check alert properties
            conditions = trigger.get('conditions', {})
            
            for field, value in conditions.items():
                if field not in alert_data:
                    return False
                
                # Handle different condition types
                if isinstance(value, dict):
                    # Advanced condition (e.g., {"$gt": 0.8})
                    if '$eq' in value and alert_data[field] != value['$eq']:
                        return False
                    if '$gt' in value and alert_data[field] <= value['$gt']:
                        return False
                    if '$gte' in value and alert_data[field] < value['$gte']:
                        return False
                    if '$lt' in value and alert_data[field] >= value['$lt']:
                        return False
                    if '$lte' in value and alert_data[field] > value['$lte']:
                        return False
                    if '$in' in value and alert_data[field] not in value['$in']:
                        return False
                    if '$nin' in value and alert_data[field] in value['$nin']:
                        return False
                else:
                    # Simple equality
                    if alert_data[field] != value:
                        return False
            
            return True
        
        return False
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'version': self.version,
            'author': self.author,
            'enabled': self.enabled,
            'tags': self.tags,
            'trigger': self.trigger,
            'actions': self.actions,
            'on_failure': self.on_failure,
            'timeout_seconds': self.timeout_seconds,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }
    
    @staticmethod
    def from_yaml(yaml_path: str) -> 'PlaybookDefinition':
        """Load playbook from YAML file"""
        with open(yaml_path, 'r') as f:
            playbook_dict = yaml.safe_load(f)
        return PlaybookDefinition(playbook_dict)
    
    @staticmethod
    def from_yaml_string(yaml_content: str) -> 'PlaybookDefinition':
        """Load playbook from YAML string"""
        playbook_dict = yaml.safe_load(yaml_content)
        return PlaybookDefinition(playbook_dict)


class PlaybookManager:
    """Manage playbook definitions (CRUD)"""
    
    def __init__(self, playbooks_dir: str = None):
        """
        Initialize playbook manager
        
        Args:
            playbooks_dir: Directory containing playbook YAML files
        """
        self.playbooks_dir = playbooks_dir or './playbooks'
        self.playbooks: Dict[str, PlaybookDefinition] = {}
        self._load_all_playbooks()
    
    def _load_all_playbooks(self):
        """Load all playbooks from directory"""
        if not os.path.exists(self.playbooks_dir):
            os.makedirs(self.playbooks_dir)
            logger.info(f"Created playbooks directory: {self.playbooks_dir}")
            return
        
        for filename in os.listdir(self.playbooks_dir):
            if filename.endswith('.yml') or filename.endswith('.yaml'):
                try:
                    filepath = os.path.join(self.playbooks_dir, filename)
                    playbook = PlaybookDefinition.from_yaml(filepath)
                    self.playbooks[playbook.id] = playbook
                    logger.info(f"Loaded playbook: {playbook.name} ({playbook.id})")
                except Exception as e:
                    logger.error(f"Failed to load playbook {filename}: {e}")
    
    def get_playbook(self, playbook_id: str) -> Optional[PlaybookDefinition]:
        """Get playbook by ID"""
        return self.playbooks.get(playbook_id)
    
    def list_playbooks(self, enabled_only: bool = True) -> List[PlaybookDefinition]:
        """List all playbooks"""
        if enabled_only:
            return [p for p in self.playbooks.values() if p.enabled]
        return list(self.playbooks.values())
    
    def create_playbook(self, playbook_dict: Dict) -> PlaybookDefinition:
        """Create new playbook"""
        playbook = PlaybookDefinition(playbook_dict)
        self.playbooks[playbook.id] = playbook
        
        # Save to file
        self._save_playbook(playbook)
        logger.info(f"Created playbook: {playbook.name}")
        
        return playbook
    
    def update_playbook(self, playbook_id: str, updates: Dict) -> Optional[PlaybookDefinition]:
        """Update playbook"""
        if playbook_id not in self.playbooks:
            return None
        
        playbook_dict = self.playbooks[playbook_id].to_dict()
        playbook_dict.update(updates)
        playbook_dict['updated_at'] = datetime.utcnow().isoformat()
        
        playbook = PlaybookDefinition(playbook_dict)
        self.playbooks[playbook_id] = playbook
        
        # Save to file
        self._save_playbook(playbook)
        logger.info(f"Updated playbook: {playbook.name}")
        
        return playbook
    
    def delete_playbook(self, playbook_id: str) -> bool:
        """Delete playbook"""
        if playbook_id not in self.playbooks:
            return False
        
        playbook = self.playbooks[playbook_id]
        del self.playbooks[playbook_id]
        
        # Remove file
        filepath = os.path.join(self.playbooks_dir, f"{playbook.name.replace(' ', '_')}.yml")
        if os.path.exists(filepath):
            os.remove(filepath)
        
        logger.info(f"Deleted playbook: {playbook.name}")
        return True
    
    def _save_playbook(self, playbook: PlaybookDefinition):
        """Save playbook to YAML file"""
        filename = playbook.name.lower().replace(' ', '_') + '.yml'
        filepath = os.path.join(self.playbooks_dir, filename)
        
        with open(filepath, 'w') as f:
            yaml.dump(playbook.to_dict(), f, default_flow_style=False, sort_keys=False)
    
    def find_matching_playbooks(self, alert_data: Dict) -> List[PlaybookDefinition]:
        """Find playbooks that match alert trigger"""
        matching = []
        
        for playbook in self.list_playbooks(enabled_only=True):
            if playbook.trigger['type'] == 'alert':
                if playbook.matches_trigger(alert_data):
                    matching.append(playbook)
        
        return matching


if __name__ == "__main__":
    # Test playbook loading
    manager = PlaybookManager('./playbooks')
    
    print(f"Loaded {len(manager.playbooks)} playbooks")
    for pb in manager.list_playbooks():
        print(f"  - {pb.name} ({pb.id})")
