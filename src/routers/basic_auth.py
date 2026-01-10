from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from sqlmodel import select

from src.config import RedisSingleton
from src import SessionDep, User
from src.security import hash_password


redis = RedisSingleton().getInstance()

router = APIRouter(prefix="/auth/basic", tags=["Basic Authentication"])


@router.post("/signup")
def signup_basic_auth(user: User, session: SessionDep):
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
    except (Exception, HTTPException) as e:
        print("[basic_auth - signup_basic_auth] Error:", e)
        return JSONResponse(
            status_code=500, content={"detail": "Internal Server Error"}
        )

    return JSONResponse(status_code=201, content={"detail": "User registered."})
