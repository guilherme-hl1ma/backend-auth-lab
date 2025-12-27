import bcrypt


def hash_password(password: str) -> str:
    """Hashes the plain-text password."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain-text password against a hash."""
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password)
