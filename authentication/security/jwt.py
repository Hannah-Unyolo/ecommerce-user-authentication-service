import jwt
import datetime
from django.conf import settings
from typing import Dict, Any, Optional
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError

class JWTManager:
    def __init__(self):
        self.algorithm = getattr(settings, 'JWT_ALGORITHM', 'HS256')
        
        # Configurable TTL with environment variables
        self.access_token_ttl = datetime.timedelta(
            minutes=getattr(settings, 'JWT_ACCESS_TOKEN_TTL', 15)
        )
        self.refresh_token_ttl = datetime.timedelta(
            days=getattr(settings, 'JWT_REFRESH_TOKEN_TTL', 7)
        )
        
        # Configurable clock skew
        self.clock_skew = datetime.timedelta(
            seconds=getattr(settings, 'JWT_CLOCK_SKEW', 30)
        )
        
        if self.algorithm.startswith('RS'):
            self.private_key = getattr(settings, 'JWT_PRIVATE_KEY', None)
            self.public_key = getattr(settings, 'JWT_PUBLIC_KEY', None)
            self.secret = None
            if not self.private_key or not self.public_key:
                raise ValueError("RS256 algorithm requires both private and public keys")
        else:
            self.secret = getattr(settings, 'JWT_SECRET_KEY', None)
            self.private_key = None
            self.public_key = None
            if not self.secret:
                raise ValueError("HS256 algorithm requires a secret key")

    def sign_access(self, payload: Dict[str, Any]) -> str:
        """Sign an access token with configurable TTL"""
        payload = payload.copy()
        payload['exp'] = datetime.datetime.utcnow() + self.access_token_ttl
        payload['type'] = 'access'
        
        # Ensure required claims
        if 'sub' not in payload:
            raise ValueError("sub claim is required")
        if 'role' not in payload:
            raise ValueError("role claim is required")
        if 'sid' not in payload:
            raise ValueError("sid claim is required")
            
        return self._sign(payload)

    def sign_refresh(self, payload: Dict[str, Any]) -> str:
        """Sign a refresh token with configurable TTL"""
        payload = payload.copy()
        payload['exp'] = datetime.datetime.utcnow() + self.refresh_token_ttl
        payload['type'] = 'refresh'
        
        # Ensure required claims
        if 'sub' not in payload:
            raise ValueError("sub claim is required")
        if 'sid' not in payload:
            raise ValueError("sid claim is required")
            
        return self._sign(payload)

    def _sign(self, payload: Dict[str, Any]) -> str:
        """Internal method to sign JWT tokens"""
        if self.algorithm.startswith('RS'):
            return jwt.encode(payload, self.private_key, algorithm=self.algorithm)
        else:
            return jwt.encode(payload, self.secret, algorithm=self.algorithm)

    def verify_access(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify an access token with clock skew handling"""
        try:
            payload = self._verify(token)
            if payload.get('type') != 'access':
                raise InvalidTokenError("Invalid token type")
            return payload
        except (InvalidTokenError, ExpiredSignatureError):
            return None

    def verify_refresh(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify a refresh token with clock skew handling"""
        try:
            payload = self._verify(token)
            if payload.get('type') != 'refresh':
                raise InvalidTokenError("Invalid token type")
            return payload
        except (InvalidTokenError, ExpiredSignatureError):
            return None

    def _verify(self, token: str) -> Dict[str, Any]:
        """Internal method to verify JWT tokens with clock skew"""
        if self.algorithm.startswith('RS'):
            key = self.public_key
        else:
            key = self.secret
            
        return jwt.decode(
            token, 
            key, 
            algorithms=[self.algorithm],
            options={
                'verify_exp': True,
                'leeway': self.clock_skew.total_seconds()
            }
        )

jwt_manager = JWTManager()