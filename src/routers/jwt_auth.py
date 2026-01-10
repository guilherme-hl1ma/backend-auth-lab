from datetime import datetime, timedelta, timezone
import os
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
import jwt
from sqlmodel import select
from src import SessionDep, User
from src.security import hash_password, verify_password

router = APIRouter(prefix="/auth/jwt", tags=["JWT Authentication"])

SECRET_JWT = os.getenv("SECRET_JWT")
JWT_ISSUER = os.getenv("JWT_ISSUER")


@router.post("/login")
def login_jwt(user: User, session: SessionDep):
    try:
        email = user.email
        password = user.password

        user_db = session.exec(select(User).where(User.email == email)).first()

        is_pass_correct = verify_password(
            plain_password=password, hashed_password=user_db.password
        )

        if not user_db or not is_pass_correct:
            raise HTTPException(
                status_code=404,
                detail="Invalid user. Try again.",
            )

        issued_time = datetime.now(timezone.utc).timestamp()
        expiration_time = (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()
        payload = {
            "iss": JWT_ISSUER,
            "sub": email,
            "iat": issued_time,
            "exp": expiration_time,
        }

        token = jwt.encode(
            payload=payload,
            algorithm="HS256",
            key=SECRET_JWT,
        )

        response = JSONResponse(status_code=200, content=token)
        response.set_cookie(
            key="token",
            value=str(token),
            httponly=True,
            # secure=True,
            samesite="lax",
            max_age=60 * 60 * 24,
        )

        return response
    except (Exception, HTTPException) as e:
        print("[jwt_auth - login] Error:", e)
        return JSONResponse(
            status_code=500, content={"detail": "Internal Server Error"}
        )


@router.post("/signup")
def signup_jwt(user: User, session: SessionDep):
    try:
        user_db = session.exec(select(User).where(User.email == user.email)).first()
        if user_db:
            raise HTTPException(
                status_code=409,
                detail="E-mail already exists. Try again using another one.",
            )

        email = user.email
        password = user.password
        hashed = hash_password(password)
        user.password = hashed

        issued_time = datetime.now(timezone.utc).timestamp()
        expiration_time = (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()
        payload = {
            "iss": JWT_ISSUER,
            "sub": email,
            "iat": issued_time,
            "exp": expiration_time,
        }

        token = jwt.encode(
            payload=payload,
            algorithm="HS256",
            key=SECRET_JWT,
        )

        response = JSONResponse(status_code=200, content=token)
        response.set_cookie(
            key="token",
            value=str(token),
            httponly=True,
            # secure=True,
            samesite="lax",
            max_age=60 * 60 * 24,
        )

        session.add(user)
        session.commit()
        session.refresh(user)

        return response
    except (Exception, HTTPException) as e:
        print("[signup_jwt - signup_session] Error:", e)
        return JSONResponse(
            status_code=500, content={"detail": "Internal Server Error"}
        )


@router.post("/logout")
def logout_jwt(request: Request):
    session_id = request.cookies.get("token")

    response = JSONResponse(status_code=200, content={"detail": "OK"})

    if session_id:
        response.delete_cookie("token")

    return response
