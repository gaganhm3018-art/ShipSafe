"""
ShipSafe Authentication Security Module
Implements Argon2id password hashing and JWT token lifecycle.
"""

import os
import hashlib
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

# Environment secrets with secure defaults for dev
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "shipsafe-dev-insecure-secret-key-change-in-prod-2026")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.environ.get("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

# Argon2id password hasher with RFC 9106 recommended parameters
ph = PasswordHasher(
    time_cost=2,
    memory_cost=19456,  # 19 MiB
    parallelism=1,
    hash_len=32,
    salt_len=16
)



def hash_password(password: str) -> str:
    """Hashes a plaintext password using Argon2id."""
    return ph.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a password against an Argon2id hash."""
    try:
        return ph.verify(hashed_password, plain_password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def hash_token(token: str) -> str:
    """SHA-256 hash of a token for secure database indexing without storing plaintext."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Generates a short-lived access JWT."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire,
        "iat": now,
        "type": "access"
    })
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def create_refresh_token(user_id: str, expires_delta: Optional[timedelta] = None) -> (str, datetime):
    """Generates a cryptographically strong refresh JWT and returns token string and expiry."""
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    payload = {
        "sub": user_id,
        "exp": expire,
        "iat": now,
        "type": "refresh",
        "jti": hashlib.sha256(f"{user_id}:{time.time_ns()}".encode()).hexdigest()[:16]
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token, expire


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    """Safely decodes and verifies a JWT token signature."""
    try:
        return jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError:
        return None


from collections import defaultdict


class SlidingWindowRateLimiter:
    """In-memory sliding window rate limiter for authentication endpoints."""
    def __init__(self):
        self._requests = defaultdict(list)

    def is_allowed(self, key: str, max_requests: int = 15, window_seconds: int = 60) -> bool:
        now = time.time()
        timestamps = self._requests[key]
        self._requests[key] = [t for t in timestamps if now - t < window_seconds]
        if len(self._requests[key]) >= max_requests:
            return False
        self._requests[key].append(now)
        return True

    def reset(self, key: Optional[str] = None):
        if key:
            self._requests.pop(key, None)
        else:
            self._requests.clear()


auth_rate_limiter = SlidingWindowRateLimiter()


def validate_password_strength(password: str) -> Dict[str, Any]:
    """Evaluates password complexity without arbitrary restrictive rules."""
    score = 0
    feedback = []
    if len(password) >= 12:
        score += 1
    else:
        feedback.append("Minimum 12 characters required")
    if any(c.isupper() for c in password):
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        score += 1

    label = "Weak"
    if score >= 4:
        label = "Strong"
    elif score >= 2:
        label = "Fair"

    return {
        "score": score,
        "label": label,
        "valid": len(password) >= 8,
        "is_recommended": len(password) >= 12,
        "feedback": feedback
    }
