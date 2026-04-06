"""
JWT token creation and verification, plus password hashing utilities.
Uses python-jose for JWT and passlib with bcrypt for password hashing.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException, status
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.config import settings


# Password hashing context using bcrypt
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT algorithm
_ALGORITHM = "HS256"


def get_password_hash(password: str) -> str:
    """Hash a plain-text password using bcrypt."""
    return _pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plain-text password against a bcrypt hash."""
    return _pwd_context.verify(plain, hashed)


def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Create a signed JWT access token.

    Args:
        data: Payload claims to encode into the token.
        expires_delta: Optional custom expiry duration. Defaults to
            ACCESS_TOKEN_EXPIRE_MINUTES from settings.

    Returns:
        Encoded JWT string.
    """
    to_encode = data.copy()
    if expires_delta is not None:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=_ALGORITHM)


def create_refresh_token(data: dict) -> str:
    """
    Create a signed JWT refresh token with a longer expiry.

    Args:
        data: Payload claims to encode into the token.

    Returns:
        Encoded JWT string.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=_ALGORITHM)


def verify_token(token: str) -> dict:
    """
    Decode and verify a JWT token.

    Args:
        token: Encoded JWT string.

    Returns:
        Decoded payload dict.

    Raises:
        HTTPException 401 if the token is invalid, expired, or malformed.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[_ALGORITHM])
        return payload
    except JWTError:
        raise credentials_exception
