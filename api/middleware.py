#!/usr/bin/env python3

################################################################################
# Honeypot Framework - API Middleware
# Rate limiting, request logging, and security headers
################################################################################

import os
import time
import logging
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict
from collections import defaultdict
from flask import request, jsonify, g

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/honeypot/api-requests.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class RateLimiter:
    """Rate limiting middleware"""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 3600):
        """
        Initialize rate limiter
        
        Args:
            max_requests: Maximum requests allowed per window
            window_seconds: Time window in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)  # {client_id: [timestamps]}
    
    def is_rate_limited(self, client_id: str) -> bool:
        """
        Check if client is rate limited
        
        Args:
            client_id: Client identifier (IP, user ID, API key, etc.)
            
        Returns:
            True if rate limited, False otherwise
        """
        now = time.time()
        window_start = now - self.window_seconds
        
        # Remove old requests outside the window
        self.requests[client_id] = [
            req_time for req_time in self.requests[client_id]
            if req_time > window_start
        ]
        
        # Check if limit exceeded
        if len(self.requests[client_id]) >= self.max_requests:
            return True
        
        # Add current request
        self.requests[client_id].append(now)
        return False
    
    def get_remaining(self, client_id: str) -> int:
        """Get remaining requests for client"""
        now = time.time()
        window_start = now - self.window_seconds
        
        current_requests = len([
            req_time for req_time in self.requests[client_id]
            if req_time > window_start
        ])
        
        return max(0, self.max_requests - current_requests)


class SecurityHeaders:
    """Add security headers to responses"""
    
    @staticmethod
    def apply_headers(response):
        """Apply security headers"""
        # Prevent clickjacking
        response.headers['X-Frame-Options'] = 'DENY'
        
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        # Enable XSS protection
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Referrer policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Content security policy
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'"
        )
        
        # Strict transport security
        response.headers['Strict-Transport-Security'] = (
            'max-age=31536000; includeSubDomains; preload'
        )
        
        # Disable caching for sensitive data
        response.headers['Cache-Control'] = (
            'no-store, no-cache, must-revalidate, max-age=0'
        )
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        # Additional security headers
        response.headers['Permissions-Policy'] = (
            'accelerometer=(), camera=(), microphone=(), geolocation=()'
        )
        
        return response


class RequestLogger:
    """Log API requests and responses"""
    
    @staticmethod
    def log_request(method: str, path: str, status_code: int, 
                   duration: float, user_id: str = None, error: str = None):
        """Log request details"""
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "method": method,
            "path": path,
            "status_code": status_code,
            "duration_ms": round(duration * 1000, 2),
            "user_id": user_id or "anonymous",
            "ip_address": request.remote_addr
        }
        
        if error:
            log_data["error"] = error
        
        # Log different levels based on status
        if status_code >= 500:
            logger.error(log_data)
        elif status_code >= 400:
            logger.warning(log_data)
        else:
            logger.info(log_data)


class AuditLogger:
    """Log sensitive operations for audit trail"""
    
    @staticmethod
    def log_operation(operation: str, resource_type: str, resource_id: str,
                     action: str, user_id: str, status: str, details: dict = None):
        """
        Log audit event
        
        Args:
            operation: Operation type (e.g., "alert_acknowledged")
            resource_type: Type of resource (e.g., "alert", "incident")
            resource_id: ID of resource
            action: Action performed (e.g., "create", "update", "delete")
            user_id: User performing action
            status: Success/failure status
            details: Additional details
        """
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "operation": operation,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "action": action,
            "user_id": user_id,
            "status": status,
            "ip_address": request.remote_addr if request else "system",
            "details": details or {}
        }
        
        audit_logger = logging.getLogger("audit")
        audit_logger.info(audit_entry)
        
        return audit_entry


# Initialize middleware components
rate_limiter = RateLimiter(
    max_requests=int(os.getenv("API_RATE_LIMIT", 1000)),
    window_seconds=3600
)

security_headers = SecurityHeaders()
request_logger = RequestLogger()
audit_logger = AuditLogger()


def rate_limit(max_requests: int = None, window_seconds: int = None):
    """
    Decorator for rate limiting specific endpoints
    
    Args:
        max_requests: Max requests for this endpoint
        window_seconds: Time window
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get client identifier
            if hasattr(g, 'user_id'):
                client_id = g.user_id
            else:
                client_id = request.remote_addr
            
            # Check rate limit
            limiter = RateLimiter(
                max_requests=max_requests or 100,
                window_seconds=window_seconds or 3600
            )
            
            if limiter.is_rate_limited(client_id):
                return jsonify({
                    "error": "Rate limit exceeded",
                    "retry_after": window_seconds or 3600
                }), 429
            
            # Add rate limit headers
            remaining = limiter.get_remaining(client_id)
            response = f(*args, **kwargs)
            if isinstance(response, tuple):
                response, status_code = response
                # Add headers
                if isinstance(response, dict):
                    pass  # Can't add headers to dict
            
            return response
        
        return decorated_function
    return decorator


def log_request_response(f):
    """Decorator to log API requests and responses"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        start_time = time.time()
        
        try:
            response = f(*args, **kwargs)
            
            # Extract response details
            if isinstance(response, tuple):
                data, status_code = response
            else:
                data = response
                status_code = 200
            
            # Log request
            duration = time.time() - start_time
            user_id = getattr(g, 'user_id', None)
            
            request_logger.log_request(
                method=request.method,
                path=request.path,
                status_code=status_code,
                duration=duration,
                user_id=user_id
            )
            
            return response
        
        except Exception as e:
            # Log error
            duration = time.time() - start_time
            user_id = getattr(g, 'user_id', None)
            
            request_logger.log_request(
                method=request.method,
                path=request.path,
                status_code=500,
                duration=duration,
                user_id=user_id,
                error=str(e)
            )
            
            raise
    
    return decorated_function


def setup_middleware(app):
    """Setup Flask app middleware"""
    
    @app.before_request
    def before_request():
        """Before request hook"""
        g.start_time = time.time()
        g.request_id = request.headers.get('X-Request-ID', 'unknown')
    
    @app.after_request
    def after_request(response):
        """After request hook"""
        # Add security headers
        response = security_headers.apply_headers(response)
        
        # Add rate limit headers
        if hasattr(g, 'user_id'):
            client_id = g.user_id
        else:
            client_id = request.remote_addr
        
        remaining = rate_limiter.get_remaining(client_id)
        response.headers['X-RateLimit-Remaining'] = str(remaining)
        response.headers['X-RateLimit-Limit'] = str(rate_limiter.max_requests)
        response.headers['X-RateLimit-Reset'] = str(int(time.time()) + rate_limiter.window_seconds)
        
        # Add request tracking
        response.headers['X-Request-ID'] = g.request_id
        
        return response
    
    @app.errorhandler(400)
    def bad_request(error):
        """Handle 400 errors"""
        return jsonify({"error": "Bad request"}), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        """Handle 401 errors"""
        return jsonify({"error": "Unauthorized"}), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        """Handle 403 errors"""
        return jsonify({"error": "Forbidden"}), 403
    
    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 errors"""
        return jsonify({"error": "Not found"}), 404
    
    @app.errorhandler(429)
    def rate_limit_exceeded(error):
        """Handle 429 rate limit errors"""
        return jsonify({"error": "Rate limit exceeded"}), 429
    
    @app.errorhandler(500)
    def server_error(error):
        """Handle 500 errors"""
        return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    print("Middleware module loaded successfully")
