from auth import get_current_user, get_db
from fastapi.responses import JSONResponse
from model import User, Organization, UserOrganization
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from sqlalchemy import Column, Boolean
from starlette import status
from database import SessionLocal
from pydantic import BaseModel, EmailStr
from datetime import timedelta, datetime
from typing import Dict, List, Annotated, Literal
from fastapi import APIRouter, Depends, HTTPException, Request


router = APIRouter(prefix="/orgauth", tags=["orgauth"])

db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]


class RegisterOrganization(BaseModel):
    name: str
    description: str


def is_Owner(db: db_dependency, user_id: int, org_id: int):
    query = db.query(Organization).filter(Organization.id == org_id).first()
    if query is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization with give ID {org_id} does not exist",
        )
    if query.owner_id is user_id:
        return True
    else:
        return False

def is_Admin(db: db_dependency, user_id: int, org_id: int):
    query = db.query(UserOrganization).filter(UserOrganization.org_id == org_id,UserOrganization.user_id == user_id).first()
    if query is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No Association exist",
        )
    if query.isAdmin is True:
        return True
    else:
        return False

@router.post("/register")
def register_organization(
    request: Request,
    organization: RegisterOrganization,
    user: user_dependency,
    db: db_dependency,
):
    try:
        db_org = (
            db.query(Organization)
            .filter(Organization.name == organization.name)
            .first()
        )

        if db_org:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Organization already exists",
            )
        create_organization = Organization(
            name=organization.name,
            description=organization.description,
            owner_id=user["id"],
        )
        db.add(create_organization)
        create_association = UserOrganization(
            user_id=user["id"], org_id=db_org.id, isAdmin=True
        )
        db.add(create_association)
        db.commit()
        db.refresh(create_organization)
        db.refresh(create_association)

        return JSONResponse(
            status_code=status.HTTP_201_CREATED, content=organization.dict()
        )
    except:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )


@router.put("/update/{org_id}")
def update_organization(
    org_id: int,
    organization: RegisterOrganization,
    user: user_dependency,
    db: db_dependency,
):
    try:
        db_org = db.query(Organization).filter(Organization.id == org_id).first()

        if not db_org:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found",
            )

        if db_org.owner_id != user["id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not authorized to update this organization",
            )

        db_org.name = organization.name
        db_org.description = organization.description
        db.commit()
        db.refresh(db_org)

        return JSONResponse(status_code=status.HTTP_200_OK, content=db_org.dict())
    except:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )
