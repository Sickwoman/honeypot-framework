#!/usr/bin/env python3

################################################################################
# Honeypot Framework - Playbook Executor
# Orchestrates playbook execution with action sequencing and error handling
################################################################################

import json
import logging
import os
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional

from api.env import PROJECT_ROOT
from playbooks.action_handlers import ActionFactory
from playbooks.playbook_model import (
    ActionResult,
    ActionStatus,
    PlaybookDefinition,
    PlaybookExecution,
    PlaybookManager,
    PlaybookStatus,
)

# Configure logging.
#
# Best-effort file logging, mirroring api/middleware.py: importing this module
# must never fail because a log directory isn't writable -- the API imports it
# at startup, so a crash here takes the whole service down. This used to write
# to ./logs relative to the current working directory, which scattered logs
# wherever the process happened to be launched from and raised PermissionError
# outside the repo.
_LOG_DIR = os.getenv('LOG_DIR', '/var/log/honeypot')
_handlers = [logging.StreamHandler()]
_log_dir_error = None

try:
    os.makedirs(_LOG_DIR, exist_ok=True)
    _handlers.append(logging.FileHandler(os.path.join(_LOG_DIR, 'playbook-execution.log')))
except OSError as exc:
    _log_dir_error = exc

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=_handlers
)
logger = logging.getLogger(__name__)

if _log_dir_error is not None:
    logger.warning(
        "Playbook logs go to stderr only: cannot write to LOG_DIR=%s (%s)",
        _LOG_DIR, _log_dir_error,
    )


class PlaybookExecutor:
    """Execute playbooks with action orchestration"""
    
    def __init__(self, playbook_manager: PlaybookManager, db_path: str = None):
        """
        Initialize executor
        
        Args:
            playbook_manager: PlaybookManager instance
            db_path: Path to SQLite database for storing executions
        """
        self.playbook_manager = playbook_manager
        self.db_path = db_path or str(PROJECT_ROOT / 'data' / 'alerts.db')
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.executions: Dict[str, PlaybookExecution] = {}
        self._create_execution_table()
    
    def _create_execution_table(self):
        """Create playbook execution table if it doesn't exist"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS playbook_executions (
                        id TEXT PRIMARY KEY,
                        playbook_id TEXT,
                        playbook_name TEXT,
                        trigger_alert_id TEXT,
                        trigger_data TEXT,
                        status TEXT,
                        actions_results TEXT,
                        dry_run BOOLEAN,
                        started_at DATETIME,
                        completed_at DATETIME,
                        duration_seconds REAL,
                        executed_by TEXT,
                        notes TEXT
                    )
                """)
                conn.commit()
        except Exception as e:
            logger.error(f"Error creating execution table: {e}")
    
    def execute_playbook(
        self,
        playbook_id: str,
        alert_data: Dict[str, Any],
        alert_id: str = None,
        dry_run: bool = False,
        executed_by: str = "system"
    ) -> Optional[PlaybookExecution]:
        """
        Execute playbook
        
        Args:
            playbook_id: Playbook to execute
            alert_data: Alert data that triggered playbook
            alert_id: Alert ID that triggered playbook
            dry_run: If True, don't actually execute actions
            executed_by: User who triggered execution
            
        Returns:
            PlaybookExecution result
        """
        try:
            # Get playbook
            playbook = self.playbook_manager.get_playbook(playbook_id)
            if not playbook:
                logger.error(f"Playbook not found: {playbook_id}")
                return None
            
            # Create execution record
            execution = PlaybookExecution(
                execution_id=str(__import__('uuid').uuid4()),
                playbook_id=playbook.id,
                playbook_name=playbook.name,
                trigger_alert_id=alert_id or "manual",
                trigger_data=alert_data,
                dry_run=dry_run,
                executed_by=executed_by
            )
            
            logger.info(f"Starting playbook execution: {playbook.name} ({execution.execution_id})")
            
            # Execute actions
            execution.status = PlaybookStatus.RUNNING
            context = {
                'alert_data': alert_data,
                'alert_id': alert_id,
                'execution_id': execution.execution_id,
                'playbook_id': playbook_id,
                'playbook_name': playbook.name
            }
            
            # Execute actions sequentially or in parallel
            self._execute_actions(playbook, execution, context, dry_run)
            
            # Determine final status
            failed_count = len([a for a in execution.actions_results if a.status == ActionStatus.FAILED])
            if failed_count == 0:
                execution.status = PlaybookStatus.SUCCESS
            elif failed_count == len(execution.actions_results):
                execution.status = PlaybookStatus.FAILED
            else:
                execution.status = PlaybookStatus.PARTIAL_SUCCESS
            
            # Set completion time
            execution.completed_at = datetime.utcnow()
            execution.duration_seconds = (execution.completed_at - execution.started_at).total_seconds()
            
            # Store execution
            self.executions[execution.execution_id] = execution
            self._save_execution(execution)
            
            logger.info(f"Playbook execution completed: {playbook.name} - Status: {execution.status.value}")
            
            return execution
        
        except Exception as e:
            logger.error(f"Error executing playbook: {e}")
            return None
    
    def _execute_actions(
        self,
        playbook: PlaybookDefinition,
        execution: PlaybookExecution,
        context: Dict[str, Any],
        dry_run: bool = False
    ):
        """Execute playbook actions"""
        for action_config in playbook.actions:
            action_id = action_config.get('id', f"action_{len(execution.actions_results)}")
            action_type = action_config.get('type')
            
            logger.info(f"Executing action: {action_type} ({action_id})")
            
            # Create action result
            action_result = ActionResult(
                action_id=action_id,
                action_type=action_type,
                status=ActionStatus.PENDING
            )
            
            try:
                # Get action handler
                handler = ActionFactory.create(action_config)
                if not handler:
                    action_result.status = ActionStatus.FAILED
                    action_result.error = f"Unknown action type: {action_type}"
                    execution.actions_results.append(action_result)
                    
                    # Check on_failure policy
                    if playbook.on_failure == 'stop':
                        break
                    continue
                
                # Execute action
                action_result.status = ActionStatus.RUNNING
                start_time = datetime.utcnow()
                
                success, output = handler.execute(context, dry_run=dry_run)
                
                action_result.completed_at = datetime.utcnow()
                action_result.duration_seconds = (action_result.completed_at - start_time).total_seconds()
                action_result.output = output
                
                if success:
                    action_result.status = ActionStatus.SUCCESS
                    logger.info(f"Action succeeded: {action_type}")
                else:
                    action_result.status = ActionStatus.FAILED
                    action_result.error = output.get('error', 'Unknown error')
                    logger.error(f"Action failed: {action_type} - {action_result.error}")
                    
                    # Check on_failure policy
                    if playbook.on_failure == 'stop':
                        break
            
            except Exception as e:
                action_result.status = ActionStatus.FAILED
                action_result.error = str(e)
                logger.error(f"Error executing action {action_type}: {e}")
                
                # Check on_failure policy
                if playbook.on_failure == 'stop':
                    break
            
            # Add result to execution
            execution.actions_results.append(action_result)
    
    def _save_execution(self, execution: PlaybookExecution):
        """Save execution to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO playbook_executions (
                        id, playbook_id, playbook_name, trigger_alert_id,
                        trigger_data, status, actions_results, dry_run,
                        started_at, completed_at, duration_seconds,
                        executed_by, notes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    execution.execution_id,
                    execution.playbook_id,
                    execution.playbook_name,
                    execution.trigger_alert_id,
                    json.dumps(execution.trigger_data),
                    execution.status.value,
                    json.dumps([r.to_dict() for r in execution.actions_results]),
                    execution.dry_run,
                    execution.started_at,
                    execution.completed_at,
                    execution.duration_seconds,
                    execution.executed_by,
                    execution.notes
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Error saving execution: {e}")
    
    def get_execution(self, execution_id: str) -> Optional[PlaybookExecution]:
        """Get execution by ID"""
        return self.executions.get(execution_id)
    
    def list_executions(self, playbook_id: str = None, limit: int = 100) -> List[PlaybookExecution]:
        """List executions"""
        if playbook_id:
            return [e for e in list(self.executions.values())[-limit:] if e.playbook_id == playbook_id]
        return list(self.executions.values())[-limit:]
    
    def get_execution_history(self, playbook_id: str, limit: int = 50) -> List[Dict]:
        """Get execution history from database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT * FROM playbook_executions
                    WHERE playbook_id = ?
                    ORDER BY started_at DESC
                    LIMIT ?
                """, (playbook_id, limit))
                
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error getting execution history: {e}")
            return []
    
    def find_and_execute(
        self,
        alert_data: Dict[str, Any],
        alert_id: str = None,
        dry_run: bool = False,
        executed_by: str = "system"
    ) -> List[PlaybookExecution]:
        """
        Find matching playbooks and execute them
        
        Args:
            alert_data: Alert data
            alert_id: Alert ID
            dry_run: If True, don't execute
            executed_by: User who triggered
            
        Returns:
            List of executions
        """
        results = []
        
        # Find matching playbooks
        matching_playbooks = self.playbook_manager.find_matching_playbooks(alert_data)
        
        logger.info(f"Found {len(matching_playbooks)} matching playbooks for alert")
        
        # Execute each playbook
        for playbook in matching_playbooks:
            execution = self.execute_playbook(
                playbook.id,
                alert_data,
                alert_id,
                dry_run,
                executed_by
            )
            
            if execution:
                results.append(execution)
        
        return results


class PlaybookScheduler:
    """Schedule playbook execution (for scheduled triggers)"""
    
    def __init__(self, executor: PlaybookExecutor):
        """
        Initialize scheduler
        
        Args:
            executor: PlaybookExecutor instance
        """
        self.executor = executor
        self.scheduled_tasks = {}
    
    def schedule_playbook(
        self,
        playbook_id: str,
        schedule_cron: str,
        alert_data: Dict[str, Any]
    ):
        """Schedule playbook to run on cron schedule"""
        # TODO: Implement cron-based scheduling
        logger.info(f"Scheduled playbook {playbook_id} with cron: {schedule_cron}")


if __name__ == "__main__":
    # Test executor
    from playbooks.playbook_model import PlaybookManager
    
    manager = PlaybookManager('./playbooks')
    executor = PlaybookExecutor(manager)
    
    # Test execution
    test_alert = {
        'id': 'alert_123',
        'alert_name': 'High Risk IP',
        'severity': 'HIGH',
        'source_ip': '192.168.1.100',
        'honeypot_type': 'cowrie',
        'service_name': 'ssh'
    }
    
    # Find and execute playbooks (dry run)
    results = executor.find_and_execute(test_alert, alert_id='alert_123', dry_run=True)
    
    for result in results:
        print(f"Playbook: {result.playbook_name}")
        print(f"Status: {result.status.value}")
        for action in result.actions_results:
            print(f"  - {action.action_type}: {action.status.value}")
