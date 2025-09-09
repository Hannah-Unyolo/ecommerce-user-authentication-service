from django.conf import settings

import bcrypt
def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    salt_rounds = getattr(settings, 'BCRYPT_SALT_ROUNDS', 12)
    salt = bcrypt.gensalt(rounds=salt_rounds)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def check_password(password: str, hashed: str) -> bool:
    """Check if a password matches the hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def hash_token(token: str) -> str:
    """Hash a token for secure storage"""
    return hash_password(token)