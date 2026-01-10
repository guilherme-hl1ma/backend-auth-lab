import base64
import os
import jwt
import redis
from fastapi.responses import JSONResponse
from sqlmodel import Session, select
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from src.models import User
from src.database import engine
from src.security.encrypt_password import verify_password

WHITELIST_PATHS = ["/docs", "/openapi.json", "/redoc"]
SECRET_JWT = os.getenv("SECRET_JWT")
JWT_ISSUER = os.getenv("JWT_ISSUER")


redis_instance = redis.Redis(host="localhost", port=6379, decode_responses=True)


class BasicAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        path = request.url.path
        if path in WHITELIST_PATHS or path.startswith("/auth"):
            print(f"[BasicAuthMiddleware] Info - request url path: {path}")
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

            if path in WHITELIST_PATHS or path.startswith("/auth"):
                print(f"[SessionBasedAuthMiddleware] Info - request url path: {path}")
                return await call_next(request)

            user_session = request.cookies.get("ses_num")

            if not user_session:
                return JSONResponse(
                    status_code=401, content={"detail": "Authorization missing."}
                )

            email = redis_instance.get(f"session_id:{user_session}")
            if not email:
                return JSONResponse(
                    status_code=401, content={"detail": "Invalid session."}
                )

            return await call_next(request)
        except Exception as e:
            print("[SessionBasedAuthMiddleware] Error:", e)
            return JSONResponse(
                status_code=500, content={"detail": "Internal Server Error"}
            )


class JWTAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        try:
            path = request.url.path

            if path in WHITELIST_PATHS or path.startswith("/auth"):
                print(f"[JWTAuthMiddleware] Info - request url path: {path}")
                return await call_next(request)

            token = request.cookies.get("token")

            if not token:
                return JSONResponse(
                    status_code=401, content={"detail": "Authorization missing."}
                )

            token_decoded: dict = jwt.decode(
                jwt=token, key=SECRET_JWT, algorithms=["HS256"], issuer=JWT_ISSUER
            )

            email = token_decoded.get("sub", None)
            if email is None:
                print("[JWTAuthMiddleware] Error: email cannot be None")
                return JSONResponse(
                    status_code=401, content={"detail": "Invalid credential"}
                )

            return await call_next(request)
        except (jwt.ExpiredSignatureError, jwt.InvalidIssuerError) as e:
            print("[JWTAuthMiddleware] Error:", e)
            return JSONResponse(
                status_code=401, content={"detail": "Invalid credential"}
            )
        except Exception as e:
            print("[JWTAuthMiddleware] Error:", e)
            return JSONResponse(
                status_code=500, content={"detail": "Internal Server Error"}
            )
