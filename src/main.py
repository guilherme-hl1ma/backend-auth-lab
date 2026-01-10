import os
from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI
from src.middleware import (
    BasicAuthMiddleware,
    JWTAuthMiddleware,
    SessionBasedAuthMiddleware,
)
from .routers import basic_auth, session_auth, jwt_auth, users


app = FastAPI()

auth_mode = os.getenv("AUTH_MODE")

if auth_mode == "basic":
    app.add_middleware(BasicAuthMiddleware)
elif auth_mode == "session":
    app.add_middleware(SessionBasedAuthMiddleware)
elif auth_mode == "jwt":
    app.add_middleware(JWTAuthMiddleware)

app.include_router(basic_auth.router)
app.include_router(session_auth.router)
app.include_router(jwt_auth.router)
app.include_router(users.router)
