from uuid import uuid4
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
import redis
from sqlmodel import select

from src.database import SessionDep
from src.models import User
from src.security.encrypt_password import hash_password


redis_instance = redis.Redis(host="localhost", port=6379, decode_responses=True)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/signup")
def signup(user: User, session: SessionDep):
    pass
    try:
        user_db = session.exec(select(User).where(User.email == user.email)).first()
        if user_db:
            raise HTTPException(
                status_code=409,
                detail="E-mail already exists. Try again using another one.",
            )

        password = user.password
        hashed = hash_password(password)
        user.password = hashed

        session.add(user)
        session.commit()
        session.refresh(user)
    except HTTPException as e:
        raise e

    return JSONResponse(status_code=201, content={"detail": "User registered."})


@router.post("/signup")
def signup_session(user: User, session: SessionDep, request: Request):
    try:
        user_db = session.exec(select(User).where(User.email == user.email)).first()
        if user_db:
            raise HTTPException(
                status_code=409,
                detail="E-mail already exists. Try again using another one.",
            )

        password = user.password
        hashed = hash_password(password)
        user.password = hashed

        session_id = uuid4()
        response = JSONResponse(status_code=201, content={"detail": "User registered."})
        response.set_cookie("ses_num", str(session_id))
        redis_instance.set(f"user:{user.email}:session_id", str(session_id))

        session.add(user)
        session.commit()
        session.refresh(user)

        return response
    except HTTPException as e:
        raise e
