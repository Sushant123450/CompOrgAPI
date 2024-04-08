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
from typing import Dict, List, Annotated, Literal, Optional, Union
from fastapi import APIRouter, Depends, HTTPException, Request


router = APIRouter(prefix="/orgauth", tags=["orgauth"])

db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]


class RegisterOrganization(BaseModel):
    name: str
    description: str


class UpdateOrganization(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None


class User_detail(BaseModel):
    id: int
    username: str
    email: str


def is_Owner(user_id: int, org_id: int, db: db_dependency):
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


def is_Admin(user_id: int, org_id: int, db: db_dependency):
    query = (
        db.query(UserOrganization)
        .filter(UserOrganization.org_id == org_id, UserOrganization.user_id == user_id)
        .first()
    )
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
        db.commit()
        db.refresh(create_organization)

        create_association = UserOrganization(
            user_id=user["id"], org_id=create_organization.id, isAdmin=True
        )
        db.add(create_association)
        db.commit()
        db.refresh(create_association)

        return JSONResponse(
            status_code=status.HTTP_201_CREATED, content=organization.dict()
        )

    except:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=user,
        )


@router.get("/org")
async def list_All_Organizations(db: db_dependency):
    # Query all records from table 'organization'
    orgs = db.query(Organization)
    orgs_list = [i for i in orgs]
    return orgs_list


@router.get("/org/{org_id}")
def get_organization_details(request: Request, db: db_dependency, org_id: int):
    try:
        db_org = db.query(Organization).filter(Organization.id == org_id).first()

        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={
                "id": db_org.id,
                "name": db_org.name,
                "description": db_org.description,
                "owner_id": db_org.owner_id,
            },
        )

    except:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization Not Found",
        )


@router.put("/org/{org_id}/update")
def update_organization(
    org_id: int,
    organization: UpdateOrganization,
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

        if organization.name is not None and organization.description is not None:
            db_org = (
                db.query(Organization)
                .filter(Organization.id == org_id)
                .update(
                    {
                        "description": organization.description,
                        "name": organization.name,
                    }
                )
            )
        db.commit()

        return JSONResponse(status_code=status.HTTP_200_OK, content="Updation Done")
    except:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Updation Not Made",
        )


@router.post("/org/{org_id}/delete")
def delete_organization(
    db: db_dependency,
    org_id: int,
    user: user_dependency,
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
        Org = db.query(Organization).filter(Organization.id == org_id).delete()
        Assoc = (
            db.query(UserOrganization)
            .filter(UserOrganization.org_id == org_id)
            .delete()
        )
        db.commit()
        return {"response": f"{Org} org and {Assoc} Assoc deleted"}

    except:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Deletion Not Made",
        )


@router.post("/member/add")
def add_member_to_org(
    member_id: int,
    org_id: int,
    db: db_dependency,
    user: user_dependency,
    Admin: bool = False,
):
    if is_Owner(user["id"], org_id, db):
        organization = db.query(Organization).filter(Organization.id == org_id).first()
        if organization is not None:
            member = db.query(User).filter(User.id == member_id).first()
            if member is not None:
                organization.add_user(member, db, Admin)
            else:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Member does not exists",
                )

    elif is_Admin(user["id"], org_id, db):
        organization = db.query(Organization).filter(Organization.id == org_id).first()
        if organization is not None:
            member = db.query(User).filter(User.id == member_id).first()
            if member is not None:
                organization.add_user(member, db)
            else:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Member does not exists",
                )

    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to update this organization",
        )
    return JSONResponse(
        status_code=200, content={"message": "Member is added to organinzation"}
    )


@router.post("/member/remove")
def remove_member_from_org(
    member_id: int,
    org_id: int,
    db: db_dependency,
    user: user_dependency,
):
    organization = db.query(Organization).filter(Organization.id == org_id).first()
    if organization is not None:
        if is_Owner(user["id"], org_id, db):
            user = db.query(User).filter(User.id == member_id).first()
            organization.remove_user(user, db)

        elif is_Admin(user["id"], org_id, db):
            user = db.query(User).filter(User.id == member_id).first()
            organization.add_user(user, db)
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not authorized to update this organization",
            )
    else:
        raise (
            HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Not Organization Found with given Organization ID ",
            )
        )
    return JSONResponse(
        status_code=200, content={"message": "Member is removed from organinzation"}
    )


@router.get("/org/{org_id}/members", response_model=List[User_detail])
async def all_member_of_organization(org_id: int, db: db_dependency):
    # list_of_members_id = db.query(UserOrganization).filter(UserOrganization.org_id == org_id).all()
    # all_member_details = []
    # for i in list_of_members_id:
    #     member = db.query(User).filter(User.id == i.id).
    organization = db.query(Organization).filter(Organization.id == org_id).first()

    if organization is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found"
        )

    members = organization.users
    return members
