import os

from fastapi import FastAPI
from .routers import basic_auth, session_auth, jwt_auth, users


app = FastAPI()

auth_mode = os.getenv("AUTH_MODE")

if auth_mode == "basic":
    app.include_router(basic_auth.router)
elif auth_mode == "session":
    app.include_router(session_auth.router)
elif auth_mode == "jwt":
    app.include_router(jwt_auth.router)

app.include_router(users.router)
