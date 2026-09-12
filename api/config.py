#!/usr/bin/env python3

################################################################################
# Honeypot Framework - Configuration Manager
# Loads and validates environment variables from .env file
################################################################################

import logging
import os
from pathlib import Path
from typing import Any, Dict

from dotenv import load_dotenv

from api.env import PROJECT_ROOT

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ConfigurationError(Exception):
    """Exception for configuration errors"""
    pass


class ConfigManager:
    """Manage application configuration from environment variables"""
    
    # Default configuration values
    DEFAULTS = {
        # Security
        "JWT_ALGORITHM": "HS256",
        "TOKEN_EXPIRATION_HOURS": 24,
        "SESSION_LIFETIME": 86400,
        "JWT_SECRET_KEY": "",

        # SSL/TLS certificate paths
        "SSL_CA_CERT_PATH": "",
        "SSL_ELASTICSEARCH_CERT_PATH": "",
        "SSL_ELASTICSEARCH_KEY_PATH": "",
        "SSL_KIBANA_CERT_PATH": "",
        "SSL_KIBANA_KEY_PATH": "",
        "SSL_API_CERT_PATH": "",
        "SSL_API_KEY_PATH": "",
        
        # API Server
        "API_HOST": "0.0.0.0",
        "API_PORT": 8443,
        "API_DEBUG": False,
        "API_WORKERS": 4,
        "API_TIMEOUT": 30,
        "API_RATE_LIMIT": 1000,
        "API_RATE_LIMIT_WINDOW": 3600,
        "API_KEY_EXPIRATION_DAYS": 90,
        
        # Database
        "ALERTS_DB_PATH": "/var/lib/honeypot/alerts.db",
        
        # Logging
        "LOG_LEVEL": "INFO",
        "LOG_DIR": "/var/log/honeypot",
        "LOG_RETENTION_DAYS": 90,
        
        # Services
        "COWRIE_HOST": "127.0.0.1",
        "COWRIE_PORT": 2222,
        "OPENCANARY_HOST": "127.0.0.1",
        
        # Elasticsearch
        "ELASTICSEARCH_HOST": "localhost",
        "ELASTICSEARCH_PORT": 9200,
        "ELASTICSEARCH_SSL": True,
        "ELASTICSEARCH_VERIFY_CERTS": True,
        
        # Monitoring
        "PROMETHEUS_HOST": "localhost",
        "PROMETHEUS_PORT": 9090,
        "ALERT_HIGH_RISK_THRESHOLD": 0.8,
        "ALERT_MEDIUM_RISK_THRESHOLD": 0.5,
        "ALERT_LOW_RISK_THRESHOLD": 0.2,
        
        # Development
        "DEBUG": False,
        "TESTING": False,
    }
    
    def __init__(self, env_file: str | None = None):
        """
        Initialize config manager

        Args:
            env_file: Path to .env file. Defaults to the repo-root .env, so
                configuration does not depend on the current working directory.
        """
        self.env_file = str(env_file or PROJECT_ROOT / ".env")
        self.config = {}
        self._load_env_file()
        self._load_environment()
    
    def _load_env_file(self):
        """Load .env file if it exists.

        override=False: a real environment variable (set by the shell, a
        systemd unit, CI, or Docker Compose) always wins over the checked-out
        .env file. This used to be override=True, which meant .env silently
        clobbered anything already exported -- e.g. ALERTS_DB_PATH or LOG_DIR
        set on the command line would be discarded in favor of the .env
        defaults, with no error and no indication why.
        """
        if os.path.exists(self.env_file):
            try:
                load_dotenv(self.env_file, override=False)
                logger.info(f"Loaded configuration from {self.env_file}")
            except Exception as e:
                logger.warning(f"Failed to load .env file: {e}")
        else:
            logger.warning(f".env file not found at {self.env_file}")
    
    def _load_environment(self):
        """Load configuration from environment variables"""
        # Load from defaults first
        self.config = self.DEFAULTS.copy()
        
        # Override with environment variables
        for key, default_value in self.DEFAULTS.items():
            env_value = os.getenv(key)
            if env_value is not None:
                self.config[key] = self._parse_value(env_value, type(default_value))
    
    @staticmethod
    def _parse_value(value: str, expected_type: type) -> Any:
        """
        Parse environment variable value to correct type
        
        Args:
            value: String value from environment
            expected_type: Expected Python type
            
        Returns:
            Parsed value
        """
        if expected_type is bool:
            return value.lower() in ('true', '1', 'yes', 'on')
        elif expected_type is int:
            return int(value)
        elif expected_type is float:
            return float(value)
        elif expected_type is list:
            return [v.strip() for v in value.split(',')]
        else:
            return value
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value
        
        Args:
            key: Configuration key
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        return self.config.get(key, default)
    
    def get_required(self, key: str) -> Any:
        """
        Get required configuration value
        
        Args:
            key: Configuration key
            
        Returns:
            Configuration value
            
        Raises:
            ConfigurationError: If key not found
        """
        if key not in self.config:
            raise ConfigurationError(f"Required configuration key not found: {key}")
        
        value = self.config[key]
        if value is None or (isinstance(value, str) and value.strip() == ""):
            raise ConfigurationError(f"Required configuration key is empty: {key}")
        
        return value
    
    def validate_required(self, keys: list) -> bool:
        """
        Validate that all required keys are present
        
        Args:
            keys: List of required configuration keys
            
        Returns:
            True if all keys present
            
        Raises:
            ConfigurationError: If any key missing
        """
        missing = []
        empty = []
        
        for key in keys:
            if key not in self.config:
                missing.append(key)
            elif self.config[key] is None or (isinstance(self.config[key], str) and self.config[key].strip() == ""):
                empty.append(key)
        
        if missing or empty:
            msg = ""
            if missing:
                msg += f"Missing keys: {', '.join(missing)}. "
            if empty:
                msg += f"Empty keys: {', '.join(empty)}."
            raise ConfigurationError(msg)
        
        return True
    
    def ensure_ssl_certificates(self) -> bool:
        """
        Validate that SSL certificate files exist
        
        Returns:
            True if all certificate files exist
            
        Raises:
            ConfigurationError: If any certificate missing
        """
        required_certs = [
            "SSL_CA_CERT_PATH",
            "SSL_ELASTICSEARCH_CERT_PATH",
            "SSL_ELASTICSEARCH_KEY_PATH",
            "SSL_KIBANA_CERT_PATH",
            "SSL_KIBANA_KEY_PATH",
            "SSL_API_CERT_PATH",
            "SSL_API_KEY_PATH",
        ]
        
        missing = []
        for cert_key in required_certs:
            cert_path = self.get(cert_key)
            if not cert_path or not os.path.exists(cert_path):
                missing.append(f"{cert_key} ({cert_path})")
        
        if missing:
            msg = f"SSL certificates not found: {', '.join(missing)}\n"
            msg += "Run: sudo ./scripts/generate-ssl-certificates.sh"
            raise ConfigurationError(msg)
        
        return True
    
    def ensure_log_directories(self) -> bool:
        """
        Create required log directories if they don't exist
        
        Returns:
            True if all directories created
        """
        log_dir = self.get("LOG_DIR")
        
        try:
            Path(log_dir).mkdir(parents=True, exist_ok=True)
            os.chmod(log_dir, 0o755)
            
            # Create subdirectories
            for subdir in ["honeypot", "alerts", "security", "api"]:
                Path(f"{log_dir}/{subdir}").mkdir(parents=True, exist_ok=True)
                os.chmod(f"{log_dir}/{subdir}", 0o755)
            
            logger.info(f"Log directories created: {log_dir}")
            return True
        except Exception as e:
            raise ConfigurationError(f"Failed to create log directories: {e}") from e
    
    def ensure_database_directories(self) -> bool:
        """
        Create required database directories if they don't exist
        
        Returns:
            True if all directories created
        """
        db_path = self.get("ALERTS_DB_PATH")
        db_dir = os.path.dirname(db_path)
        
        try:
            Path(db_dir).mkdir(parents=True, exist_ok=True)
            os.chmod(db_dir, 0o700)
            
            logger.info(f"Database directories created: {db_dir}")
            return True
        except Exception as e:
            raise ConfigurationError(f"Failed to create database directories: {e}") from e
    
    def validate_production(self) -> bool:
        """
        Validate production-ready configuration
        
        Returns:
            True if configuration is production-ready
        """
        checks = [
            ("DEBUG must be False", not self.get("DEBUG")),
            ("API_WORKERS must be >= 2", self.get("API_WORKERS") >= 2),
            ("JWT_SECRET_KEY must be custom", 
             self.get("JWT_SECRET_KEY") and "change_me" not in self.get("JWT_SECRET_KEY", "").lower()),
            ("SESSION_LIFETIME must be set", self.get("SESSION_LIFETIME") > 0),
            ("ELASTICSEARCH_SSL must be True", bool(self.get("ELASTICSEARCH_SSL"))),
            ("LOG_RETENTION_DAYS must be >= 30", self.get("LOG_RETENTION_DAYS") >= 30),
        ]
        
        failures = [msg for msg, result in checks if not result]
        
        if failures:
            msg = "Production validation failed:\n"
            for failure in failures:
                msg += f"  ✗ {failure}\n"
            raise ConfigurationError(msg)
        
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Get configuration as dictionary (without sensitive values)"""
        safe_config = {}
        sensitive_keys = [
            "JWT_SECRET_KEY", "SECRET_KEY", "PASSWORD", "TOKEN",
            "API_KEY", "WEBHOOK", "SLACK", "DISCORD", "SMTP",
            "AWS", "GCP", "AZURE"
        ]
        
        for key, value in self.config.items():
            # Mask sensitive values
            if any(sensitive in key.upper() for sensitive in sensitive_keys):
                safe_config[key] = "***REDACTED***"
            else:
                safe_config[key] = value
        
        return safe_config
    
    def __repr__(self) -> str:
        """String representation"""
        return f"ConfigManager({len(self.config)} settings)"


# Global config instance
config = None


def init_config(env_file: str | None = None) -> ConfigManager:
    """
    Initialize global configuration

    Args:
        env_file: Path to .env file. Defaults to the repo-root .env.

    Returns:
        ConfigManager instance
    """
    global config
    config = ConfigManager(env_file)
    return config


def get_config() -> ConfigManager:
    """
    Get global configuration instance

    Returns:
        ConfigManager instance

    Raises:
        ConfigurationError: If init_config() has not been called yet.
        Auto-initializing here would silently paper over a missing or
        misconfigured .env for whichever module imported first.
    """
    global config
    if config is None:
        raise ConfigurationError(
            "Configuration not initialized -- call init_config() before get_config()."
        )
    return config


if __name__ == "__main__":
    # Test configuration loading
    try:
        cfg = init_config()
        
        print("✓ Configuration loaded successfully")
        print(f"✓ Configuration: {cfg}")
        print(f"\nEnvironment: {cfg.get('DEBUG') and 'DEVELOPMENT' or 'PRODUCTION'}")
        print(f"Log Level: {cfg.get('LOG_LEVEL')}")
        print(f"API Server: {cfg.get('API_HOST')}:{cfg.get('API_PORT')}")
        print(f"Elasticsearch: {cfg.get('ELASTICSEARCH_HOST')}:{cfg.get('ELASTICSEARCH_PORT')}")
        
        print("\n✓ Configuration validation passed!")
    
    except ConfigurationError as e:
        print(f"✗ Configuration error: {e}")
        exit(1)
