from typing import Annotated
from fastapi import Depends
from sqlmodel import Session, create_engine
import os


sqlite_url = os.getenv("POSTGRES_URL")
connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url)


def get_session():
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]
