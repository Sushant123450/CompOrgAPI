from fastapi import FastAPI, Depends, HTTPException, Header
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from fastapi import FastAPI
from model import User, Organization, UserOrganization, Invitation
from auth import get_current_user, create_access_token, get_db
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


# All these enpoints for Testing purposes
###################################################################################################################################################
'''
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


# Query all records from table 'User'
@app.get("/all/user")
async def list_All_Users(db: db_dependency):
    """
    Returns a list of all users in the database.

    Args:
        db (Session): The database session.

    Returns:
        List[User]: A list of all users in the database.
    """
    users = db.query(User)
    user_list = [i for i in users]
    return user_list


# Query all records from table 'Organization'
@app.get("/all/org")
async def list_All_Organizations(db: db_dependency):
    """
    Returns a list of all users in the database.

    Args:
        db (Session): The database session.

    Returns:
        List[User]: A list of all users in the database.
    """

    orgs = db.query(Organization)
    orgs_list = [i for i in orgs]

    return orgs_list


# Query all records from table 'Association'
@app.get("/all/association")
async def list_All_Association(db: db_dependency):
    """
    Returns a list of all associations between users and organizations in the database.

    Args:
        db (Session): The database session.

    Returns:
        List[UserOrganization]: A list of all associations between users and organizations in the database.
    """
    Assoc = db.query(UserOrganization)
    Assoc_list = [i for i in Assoc]

    return Assoc_list


# Query all records from table 'Invitation'
@app.get("/all/invitaion")
async def list_All_Invitation(db: db_dependency):
    """
    Returns a list of all Invitation sent to users .

    Args:
        db (Session): The database session.

    Returns:
        List[Invitation]: A list of all associations between users and organizations in the database.
    """
    Invites = db.query(Invitation)
    Invite_list = [i for i in Invites]

    return Invite_list


# Delete all records from table 'User'
@app.get("/all/user/delete")
async def delete_All_User(db: db_dependency):
    """
    Deletes all users from the database.

    Args:
        db (Session): The database session.
    """
    Assoc = db.query(Organization).delete()
    db.commit()
    return {"response": f"{Assoc} user deleted"}


# Delete all records from table 'Organization'
@app.get("/all/org/delete")
async def delete_All_Organization(db: db_dependency):
    """
    Deletes all organizations and their associations from the database.

    Args:
        db (Session): The database session.

    Returns:
        Dict[str, int]: A dictionary containing the number of organizations and associations deleted.
    """
    Org = db.query(Organization).delete()
    Assoc = db.query(UserOrganization).delete()
    db.commit()
    return {"response": f"{Org} org and {Assoc}assoc deleted"}


# Delete all records from table 'Invitations'
@app.get("/all/invite/delete")
async def delete_All_Invitation(db: db_dependency):
    """
    Deletes all invitations from the database.

    Args:
        db (Session): The database session.

    Returns:
        Dict[str, int]: A dictionary containing the number of invitations deleted.
    """
    Invites = db.query(Invitation).delete()
    db.commit()
    return {"response": f"{Invites} invites deleted"}

'''