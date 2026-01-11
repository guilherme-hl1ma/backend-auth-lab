from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    email: str = Field(primary_key=True, nullable=False)
    password: str = Field(nullable=False)
