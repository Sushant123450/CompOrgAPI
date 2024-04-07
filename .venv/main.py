from fastapi import FastAPI, Depends, HTTPException, Header
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from fastapi import FastAPI
from model import User, Organization, UserOrganization
from auth import get_current_user, create_access_token
from starlette import status
from pydantic import EmailStr, BaseModel
import orgauth
import auth
from database import *
from typing import Annotated
from fastapi.responses import JSONResponse
from typing import Dict, List
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from datetime import timedelta

# FastAPI app instance
app = FastAPI()
app.include_router(auth.router)
app.include_router(orgauth.router)


# Create tables
Base.metadata.create_all(bind=engine)


# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Pydantic model for request data
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    confirm_password: str


# Pydantic model
class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    password: str


db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]


@app.get("/", status_code=status.HTTP_200_OK)
async def login(user: user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication Failed")
    return {"User": user}


@app.post("/token-refresh")
async def refresh_token(user: user_dependency):
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        user["username"], user["id"], expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/alluser")
async def list_All_Users(db: db_dependency):
    # Query all records from table 'users'
    users = db.query(User)
    user_list = [i for i in users]

    return user_list


@app.get("/allorg")
async def list_All_Organizations(db: db_dependency):
    # Query all records from table 'organization'
    orgs = db.query(Organization)
    orgs_list = [i for i in orgs]

    return orgs_list


@app.get("/allassociation")
async def list_All_Association(db: db_dependency):
    # Query all records from table 'users'
    Assoc = db.query(UserOrganization)
    Assoc_list = [i for i in Assoc]

    return Assoc_list
