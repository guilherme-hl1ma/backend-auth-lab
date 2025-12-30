import os
from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI
from src.middleware import BasicAuthMiddleware, SessionBasedAuthMiddleware
from starlette.middleware.sessions import SessionMiddleware
from .routers import authentication, users


app = FastAPI()

# app.add_middleware(BasicAuthMiddleware)
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET_KEY"))
app.add_middleware(SessionBasedAuthMiddleware)
app.include_router(authentication.router)
app.include_router(users.router)
