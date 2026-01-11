import os

from .auth_strategies import (
    get_user_basic_auth,
    get_user_jwt_auth,
    get_user_session_based_auth,
)


AUTH_MODE = os.getenv("AUTH_MODE")


def get_auth_strategy():
    if AUTH_MODE == "basic":
        return get_user_basic_auth
    elif AUTH_MODE == "session":
        return get_user_session_based_auth
    elif AUTH_MODE == "jwt":
        return get_user_jwt_auth
