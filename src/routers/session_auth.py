from uuid import uuid4
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlmodel import select
from src.config.redis_instance import RedisSingleton
from src.database import SessionDep
from src.models import User
from src.security.encrypt_password import hash_password, verify_password


redis = RedisSingleton().getInstance()

router = APIRouter(prefix="/auth/session-based", tags=["Session-Based Authentication"])


@router.post("/signup")
def signup_session(user: User, session: SessionDep):
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

        session_id = uuid4()
        response = JSONResponse(status_code=201, content={"detail": "User registered."})
        response.set_cookie(
            key="ses_num",
            value=str(session_id),
            httponly=True,
            # secure=True,
            samesite="lax",
            max_age=60 * 60 * 24,
        )
        redis.set(name=f"session_id:{session_id}", value=email, ex=60 * 60 * 24)

        session.add(user)
        session.commit()
        session.refresh(user)

        return response
    except (Exception, HTTPException) as e:
        print("[session_auth - signup_session] Error:", e)
        return JSONResponse(
            status_code=500, content={"detail": "Internal Server Error"}
        )


@router.post("/login")
def signin_session(user: User, session: SessionDep, request: Request):
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

        session_id = uuid4()
        response = JSONResponse(status_code=200, content={"detail": "OK"})
        response.set_cookie(
            key="ses_num",
            value=str(session_id),
            httponly=True,
            # secure=True,
            samesite="lax",
            max_age=60 * 60 * 24,
        )
        redis.set(name=f"session_id:{session_id}", value=email, ex=60 * 60 * 24)

        return response
    except (Exception, HTTPException) as e:
        print("[session_auth - signin_session] Error:", e)
        return JSONResponse(
            status_code=500, content={"detail": "Internal Server Error"}
        )


@router.post("/logout")
def signout_session(request: Request):
    session_id = request.cookies.get("ses_num")

    response = JSONResponse(status_code=200, content={"detail": "OK"})

    if session_id:
        redis.delete(f"session_id:{session_id}")
        response.delete_cookie("ses_num")

    return response
