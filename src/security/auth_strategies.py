import base64
import os
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic
import jwt
from sqlmodel import Session, select

from src.config.redis_instance import RedisSingleton
from src.database import engine
from src.models import User
from src.security.encrypt_password import verify_password

security_basic = HTTPBasic()

redis_instance = RedisSingleton().getInstance()

SECRET_JWT = os.getenv("SECRET_JWT")
JWT_ISSUER = os.getenv("JWT_ISSUER")


def get_user_basic_auth(request: Request):
    try:
        auth = request.headers.get("Authorization")

        if not auth:
            raise HTTPException(
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="Login Required"'},
                detail="Authorization missing.",
            )

        _, b64_credentials = auth.split(" ", 1)
        byte_credentials = base64.b64decode(b64_credentials)
        decoded_credentials = byte_credentials.decode("utf-8")
        email, password = decoded_credentials.split(":")

        with Session(engine) as session:
            user = session.exec(select(User).where(User.email == email)).first()
            if not user:
                raise JSONResponse(
                    status_code=401,
                    content={"detail": "Email not found"},
                )
            is_valid_password = verify_password(
                plain_password=password, hashed_password=user.password
            )
            if not is_valid_password:
                raise HTTPException(status_code=401, detail="Incorret Password")
    except HTTPException:
        raise
    except Exception as e:
        print("[get_user_basic_auth] Error:", e)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    return user.email


def get_user_session_based_auth(request: Request):
    try:
        user_session = request.cookies.get("ses_num")

        if not user_session:
            raise HTTPException(status_code=401, detail="Authorization missing.")

        email = redis_instance.get(f"session_id:{user_session}")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid session")

    except HTTPException:
        raise
    except Exception as e:
        print("[get_user_session_based_auth] Error:", e)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    return email


def get_user_jwt_auth(request: Request):
    try:
        token = request.cookies.get("token")

        if not token:
            raise HTTPException(status_code=401, detail="Invalid credential")

        token_decoded: dict = jwt.decode(
            jwt=token, key=SECRET_JWT, algorithms=["HS256"], issuer=JWT_ISSUER
        )

        email = token_decoded.get("sub", None)
        if email is None:
            print("[get_user_jwt_auth] Error: email cannot be None")
            raise HTTPException(status_code=401, detail="Invalid credential")
    except HTTPException:
        raise
    except (jwt.ExpiredSignatureError, jwt.InvalidIssuerError) as e:
        print("[get_user_jwt_auth] Error:", e)
        raise HTTPException(status_code=401, detail="Invalid credential")
    except Exception as e:
        print("[get_user_jwt_auth] Error:", e)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    return email
