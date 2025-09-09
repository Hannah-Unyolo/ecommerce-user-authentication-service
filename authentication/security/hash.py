import hmac

import bcrypt
from django.conf import settings


def hash_password(plain: str) -> str:
    """Hash a password using bcrypt with configurable salt rounds"""
    salt_rounds = getattr(settings, 'BCRYPT_SALT_ROUNDS', 12)
    salt = bcrypt.gensalt(rounds=salt_rounds)
    hashed = bcrypt.hashpw(plain.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(plain: str, hashed: str) -> bool:
    """
    Verify a password against a hash using timing-safe comparison
    """
    try:
        # Use bcrypt's built-in timing-safe comparison
        return bcrypt.checkpw(
            plain.encode('utf-8'), 
            hashed.encode('utf-8')
        )
    except (ValueError, TypeError):
        # Handle invalid hash formats securely with constant-time comparison
        # Compare with a dummy hash to prevent timing attacks
        dummy_hash = bcrypt.hashpw(b"dummy_password", bcrypt.gensalt())
        hmac.compare_digest(
            hashed.encode('utf-8'), 
            dummy_hash.decode('utf-8')
        )
        return False

def hash_token(token: str) -> str:
    """Hash a token for secure storage"""
    return hash_password(token)