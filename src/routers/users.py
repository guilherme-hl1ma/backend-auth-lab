from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import select

from config import SessionDep
from models import User
from security import get_auth_strategy


router = APIRouter(prefix="/users", tags=["Users"])

auth_strategy = get_auth_strategy()


@router.get("/")
async def get_users(session: SessionDep, email: Annotated[str, Depends(auth_strategy)]):
    try:
        return session.exec(select(User)).all()
    except HTTPException as e:
        raise e
