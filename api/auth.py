#!/usr/bin/env python3

################################################################################
# Honeypot Framework - JWT Authentication Module
# Handles API authentication, token generation, and validation
################################################################################

import os
import jwt
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
from functools import wraps
from flask import request, jsonify, g

# Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change_me_in_production")
ALGORITHM = "HS256"
TOKEN_EXPIRATION_HOURS = int(os.getenv("TOKEN_EXPIRATION_HOURS", 24))
API_KEY_LENGTH = 32

class AuthenticationError(Exception):
    """Custom exception for authentication errors"""
    pass


class JWTManager:
    """Manage JWT token generation and validation"""
    
    def __init__(self, secret_key: str = SECRET_KEY, algorithm: str = ALGORITHM):
        self.secret_key = secret_key
        self.algorithm = algorithm
    
    def generate_token(self, user_id: str, username: str, roles: list = None, 
                      expiration_hours: int = TOKEN_EXPIRATION_HOURS) -> str:
        """
        Generate JWT token
        
        Args:
            user_id: Unique user identifier
            username: Username
            roles: List of roles (e.g., ['analyst', 'responder'])
            expiration_hours: Token expiration in hours
            
        Returns:
            JWT token string
        """
        if roles is None:
            roles = []
        
        now = datetime.utcnow()
        expiration = now + timedelta(hours=expiration_hours)
        
        payload = {
            "sub": user_id,
            "username": username,
            "roles": roles,
            "iat": now,
            "exp": expiration,
            "iss": "honeypot-framework",
            "aud": "honeypot-api"
        }
        
        try:
            token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
            return token
        except Exception as e:
            raise AuthenticationError(f"Failed to generate token: {str(e)}")
    
    def validate_token(self, token: str) -> Dict:
        """
        Validate JWT token
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded token payload
            
        Raises:
            AuthenticationError: If token is invalid or expired
        """
        try:
            payload = jwt.decode(
                token, 
                self.secret_key, 
                algorithms=[self.algorithm],
                options={"verify_signature": True}
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise AuthenticationError(f"Invalid token: {str(e)}")
    
    def refresh_token(self, token: str, expiration_hours: int = TOKEN_EXPIRATION_HOURS) -> str:
        """
        Refresh an existing valid token
        
        Args:
            token: Current JWT token
            expiration_hours: New expiration in hours
            
        Returns:
            New JWT token
        """
        try:
            payload = self.validate_token(token)
            new_token = self.generate_token(
                user_id=payload["sub"],
                username=payload["username"],
                roles=payload.get("roles", []),
                expiration_hours=expiration_hours
            )
            return new_token
        except AuthenticationError:
            raise


class APIKeyManager:
    """Manage API keys for service-to-service authentication"""
    
    def __init__(self):
        # In production, store API keys in encrypted database
        self.api_keys = {}  # Format: {api_key: {user_id, username, roles, created_at, expires_at}}
    
    def generate_api_key(self, user_id: str, username: str, roles: list = None,
                        expires_in_days: int = 90) -> Tuple[str, Dict]:
        """
        Generate API key
        
        Args:
            user_id: User identifier
            username: Username
            roles: List of roles
            expires_in_days: Expiration in days
            
        Returns:
            Tuple of (api_key, key_info)
        """
        if roles is None:
            roles = []
        
        # Generate random API key
        api_key = f"hf_api_{secrets.token_urlsafe(24)}"
        
        # Hash for storage
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        key_info = {
            "user_id": user_id,
            "username": username,
            "roles": roles,
            "created_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(days=expires_in_days),
            "last_used": None,
            "revoked": False
        }
        
        self.api_keys[key_hash] = key_info
        
        return api_key, key_info
    
    def validate_api_key(self, api_key: str) -> Dict:
        """
        Validate API key
        
        Args:
            api_key: API key string
            
        Returns:
            Key information if valid
            
        Raises:
            AuthenticationError: If key is invalid
        """
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        if key_hash not in self.api_keys:
            raise AuthenticationError("Invalid API key")
        
        key_info = self.api_keys[key_hash]
        
        # Check expiration
        if key_info["expires_at"] < datetime.utcnow():
            raise AuthenticationError("API key has expired")
        
        # Check revocation
        if key_info["revoked"]:
            raise AuthenticationError("API key has been revoked")
        
        # Update last used
        key_info["last_used"] = datetime.utcnow()
        
        return key_info
    
    def revoke_api_key(self, api_key: str) -> bool:
        """Revoke an API key"""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        if key_hash not in self.api_keys:
            return False
        
        self.api_keys[key_hash]["revoked"] = True
        return True


# Initialize managers
jwt_manager = JWTManager()
api_key_manager = APIKeyManager()


def require_auth(required_roles: list = None):
    """
    Flask decorator for endpoint authentication
    
    Args:
        required_roles: List of roles required to access endpoint
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Check for API key
                api_key = request.headers.get("X-API-Key")
                if api_key:
                    key_info = api_key_manager.validate_api_key(api_key)
                    g.user_id = key_info["user_id"]
                    g.username = key_info["username"]
                    g.roles = key_info["roles"]
                    g.auth_method = "api_key"
                else:
                    # Check for JWT token
                    auth_header = request.headers.get("Authorization")
                    if not auth_header:
                        return jsonify({"error": "Missing authentication"}), 401
                    
                    try:
                        token = auth_header.split(" ")[1]
                    except IndexError:
                        return jsonify({"error": "Invalid authorization header"}), 401
                    
                    payload = jwt_manager.validate_token(token)
                    g.user_id = payload["sub"]
                    g.username = payload["username"]
                    g.roles = payload.get("roles", [])
                    g.auth_method = "jwt"
                
                # Check required roles
                if required_roles:
                    user_roles = set(g.roles)
                    required = set(required_roles)
                    if not user_roles & required:
                        return jsonify({"error": "Insufficient permissions"}), 403
                
                return f(*args, **kwargs)
            
            except AuthenticationError as e:
                return jsonify({"error": str(e)}), 401
            except Exception as e:
                return jsonify({"error": "Authentication failed"}), 401
        
        return decorated_function
    return decorator


def login_required(f):
    """Simple authentication decorator (requires authentication but no specific role)"""
    return require_auth()(f)


def admin_required(f):
    """Decorator requiring admin role"""
    return require_auth(required_roles=["admin"])(f)


def analyst_required(f):
    """Decorator requiring analyst role"""
    return require_auth(required_roles=["analyst", "admin"])(f)


def responder_required(f):
    """Decorator requiring responder role"""
    return require_auth(required_roles=["responder", "admin"])(f)


# ============================================================================
# Example Flask Application Usage
# ============================================================================

if __name__ == "__main__":
    from flask import Flask
    
    app = Flask(__name__)
    app.secret_key = SECRET_KEY
    
    # Test endpoints
    @app.route("/auth/login", methods=["POST"])
    def login():
        """Login endpoint - returns JWT token"""
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")
        
        # TODO: Validate credentials against database
        # This is a placeholder
        if username and password:
            token = jwt_manager.generate_token(
                user_id="user_123",
                username=username,
                roles=["analyst", "responder"]
            )
            return jsonify({
                "token": token,
                "expires_in": TOKEN_EXPIRATION_HOURS * 3600
            })
        
        return jsonify({"error": "Invalid credentials"}), 401
    
    @app.route("/auth/refresh", methods=["POST"])
    @login_required
    def refresh():
        """Refresh token endpoint"""
        auth_header = request.headers.get("Authorization")
        token = auth_header.split(" ")[1]
        
        new_token = jwt_manager.refresh_token(token)
        return jsonify({
            "token": new_token,
            "expires_in": TOKEN_EXPIRATION_HOURS * 3600
        })
    
    @app.route("/auth/api-key", methods=["POST"])
    @login_required
    def create_api_key():
        """Create API key for service account"""
        api_key, key_info = api_key_manager.generate_api_key(
            user_id=g.user_id,
            username=g.username,
            roles=["service"]
        )
        
        return jsonify({
            "api_key": api_key,
            "expires_at": key_info["expires_at"].isoformat()
        })
    
    @app.route("/api/alerts", methods=["GET"])
    @analyst_required
    def get_alerts():
        """Protected endpoint requiring analyst role"""
        return jsonify({
            "alerts": [],
            "user": g.username
        })
    
    print("Authentication module loaded successfully")
