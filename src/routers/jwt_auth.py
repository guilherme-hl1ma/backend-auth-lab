from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from sqlmodel import select
from src.config.redis_instance import RedisSingleton
from src.database import SessionDep
from src.models import User
from src.security.encrypt_password import hash_password


redis = RedisSingleton().getInstance()

router = APIRouter(prefix="/auth/jwt", tags=["JWT Authentication"])


@router.post("/signup")
def signup(user: User, session: SessionDep):
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
