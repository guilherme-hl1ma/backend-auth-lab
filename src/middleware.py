import base64
from uuid import uuid4
import redis
from starlette.responses import Response
from starlette.requests import Request
from fastapi.responses import JSONResponse
from sqlmodel import Session, select
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from src.models import User
from src.database import engine
from src.security.encrypt_password import verify_password


WHITELIST_PATHS = ["/auth/signup", "/docs", "/openapi.json", "/redoc"]


redis_instance = redis.Redis(host="localhost", port=6379, decode_responses=True)


class BasicAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        path = request.url.path
        if path in WHITELIST_PATHS:
            return await call_next(request)

        auth = request.headers.get("Authorization")

        if not auth:
            return JSONResponse(
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="Login Required"'},
                content={"detail": "Authorization missing."},
            )

        _, b64_credentials = auth.split(" ", 1)
        byte_credentials = base64.b64decode(b64_credentials)
        decoded_credentials = byte_credentials.decode("utf-8")
        email, password = decoded_credentials.split(":")

        with Session(engine) as session:
            user = session.exec(select(User).where(User.email == email)).first()
            if not user:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Email not found"},
                )
            is_valid_password = verify_password(
                plain_password=password, hashed_password=user.password
            )
            if not is_valid_password:
                return JSONResponse(
                    status_code=401, content={"detail": "Incorret Password"}
                )
        return await call_next(request)


class SessionBasedAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        try:
            path = request.url.path

            print("path", path)
            if path in WHITELIST_PATHS:
                return await call_next(request)

            user_session = request.cookies.get("ses_num")

            if not user_session:
                return JSONResponse(
                    status_code=401, content={"detail": "Authorization missing."}
                )

            await call_next(request)
        except Exception as e:
            print(e)
