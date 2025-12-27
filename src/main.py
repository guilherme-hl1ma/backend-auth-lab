import json
from typing import Union
from dotenv import load_dotenv

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlmodel import select
from src.database import SessionDep
from src.middleware import BasicAuthMiddleware
from src.models import User
from src.security.encrypt_password import hash_password

load_dotenv()

app = FastAPI()

app.add_middleware(BasicAuthMiddleware)


class UserAuth(BaseModel):
    email: str
    password: str


@app.post("/signup")
def signup(user: User, session: SessionDep):
    user_db = session.exec(select(User).where(User.email == user.email))
    if user_db:
        return JSONResponse(
            status_code=409,
            content=json.dumps("E-mail already exists. Try again using another one."),
        )

    password = user.password
    hashed = hash_password(password)
    user.password = hashed

    session.add(user)
    session.commit()
    session.refresh(user)

    return JSONResponse(status_code=201, content=json.dumps("User registered."))


@app.get("/users")
async def get_users(session: SessionDep):
    return session.exec(select(User)).all()
