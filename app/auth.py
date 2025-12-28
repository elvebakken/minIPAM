from __future__ import annotations
import os
import time
import secrets
import bcrypt
from typing import Optional, Callable
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from fastapi import Request, HTTPException, Depends, Response

COOKIE_NAME = "miniipam_session"
CSRF_COOKIE_NAME = "csrf_token"
# Default to 1 hour, configurable via SESSION_TIMEOUT_SECONDS env var
DEFAULT_SESSION_TIMEOUT = 60 * 60  # 1 hour
MAX_AGE_SECONDS = int(os.getenv("SESSION_TIMEOUT_SECONDS", str(DEFAULT_SESSION_TIMEOUT)))

# Generate a unique server instance ID on startup
# This changes on each container restart, invalidating all existing sessions
SERVER_INSTANCE_ID = f"{int(time.time()*1000)}_{secrets.token_hex(8)}"

def get_secret() -> str:
    secret = os.getenv("SECRET_KEY", "")
    if not secret or len(secret) < 16:
        # Still works but you should set a strong one
        secret = "dev-secret-key-change-me"
    return secret

def serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(get_secret(), salt="mini-ipam")

def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt.
    Bcrypt has a 72-byte limit, so we truncate if necessary.
    """
    # Encode password to bytes and ensure it's within bcrypt's 72-byte limit
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
    
    # Generate salt and hash the password
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    
    # Return as string (bcrypt hashes are base64 encoded)
    return hashed.decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """
    Verify a password against a bcrypt hash.
    """
    # Encode password to bytes and ensure it's within bcrypt's 72-byte limit
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
    
    # Verify the password
    hashed_bytes = hashed.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_bytes)

def create_session_token(username: str, role: str) -> str:
    # Include server instance ID to invalidate sessions on container restart
    return serializer().dumps({"u": username, "r": role, "i": SERVER_INSTANCE_ID})

def read_session_token(token: str) -> Optional[dict]:
    try:
        data = serializer().loads(token, max_age=MAX_AGE_SECONDS)
        # Validate that the token was issued by this server instance
        # This ensures sessions are invalidated on container restart
        if data.get("i") != SERVER_INSTANCE_ID:
            return None
        return data
    except (BadSignature, SignatureExpired):
        return None

def require_user(request: Request) -> dict:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Not logged in")
    data = read_session_token(token)
    if not data:
        raise HTTPException(status_code=401, detail="Invalid session")
    return data

def require_role(allowed: set[str]):
    def dep(user=Depends(require_user)):
        role = user.get("r")
        if role not in allowed:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return dep

def cookie_params():
    secure = os.getenv("COOKIE_SECURE", "false").lower() == "true"
    return {
        "httponly": True,
        "secure": secure,
        "samesite": "lax",
        "path": "/",
        "max_age": MAX_AGE_SECONDS,
    }

def generate_csrf_token() -> str:
    """Generate a random CSRF token."""
    return secrets.token_urlsafe(32)

def set_csrf_cookie(response: Response, token: str):
    """Set CSRF token cookie. Note: httponly=False so JavaScript can read it."""
    secure = os.getenv("COOKIE_SECURE", "false").lower() == "true"
    response.set_cookie(
        CSRF_COOKIE_NAME,
        token,
        httponly=False,  # Must be readable by JavaScript for double-submit pattern
        secure=secure,
        samesite="lax",
        path="/",
        max_age=MAX_AGE_SECONDS,
    )

def require_csrf(request: Request, user=Depends(require_user)) -> dict:
    """
    CSRF protection: require X-CSRF-Token header to match csrf_token cookie
    for state-changing requests (POST/PATCH/DELETE).
    """
    # Get token from cookie
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
    if not cookie_token:
        raise HTTPException(status_code=403, detail="CSRF token missing")
    
    # Get token from header
    header_token = request.headers.get("X-CSRF-Token")
    if not header_token:
        raise HTTPException(status_code=403, detail="CSRF token header missing")
    
    # Compare tokens (constant-time comparison to prevent timing attacks)
    if not secrets.compare_digest(cookie_token, header_token):
        raise HTTPException(status_code=403, detail="CSRF token mismatch")
    
    return user

def require_csrf_and_role(allowed: set[str]):
    """Combine CSRF protection with role check."""
    def dep(request: Request, user=Depends(require_csrf)):
        role = user.get("r")
        if role not in allowed:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return dep
