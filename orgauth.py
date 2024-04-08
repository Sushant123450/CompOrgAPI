from auth import get_current_user, get_db, send_mail
from fastapi.responses import JSONResponse
from model import User, Organization, UserOrganization, Invitation
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from sqlalchemy import Column, Boolean
from starlette import status
from database import SessionLocal
from pydantic import BaseModel, EmailStr
from datetime import timedelta, datetime
from typing import Dict, List, Annotated, Literal, Optional, Union
from fastapi import APIRouter, Depends, HTTPException, Request
from secrets import token_bytes


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


class InvitationDetails(BaseModel):
    email: EmailStr
    org_id: int


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


def generate_random_token(token_length=32):
    """
    Generates a random token of specified length (default 32 bytes).
    """
    random_bytes = token_bytes(token_length)
    return random_bytes.hex()


@router.post("/org/register")
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
        if is_Owner(user["id"], org_id, db):
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
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not authorized to update this organization",
            )

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
        if is_Owner(user["id"], org_id, db):
            Org = db.query(Organization).filter(Organization.id == org_id).delete()
            Assoc = (
                db.query(UserOrganization)
                .filter(UserOrganization.org_id == org_id)
                .delete()
            )
            db.commit()
            return {"response": f"{Org} org and {Assoc} Assoc deleted"}
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not authorized to update this organization",
            )

    except:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Deletion Not Made",
        )


@router.post("/org/{org_id}/member/add")
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


@router.post("/org/{org_id}/member/delete")
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
    organization = db.query(Organization).filter(Organization.id == org_id).first()

    if organization is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found"
        )

    members = organization.users
    return members


@router.post("/org/invite")
async def send_invitation(
    invitation: InvitationDetails,
    db: db_dependency,
    user: user_dependency,
):
    """
    Send an invitation email to a user.

    This endpoint allows the owner or an administrator of an organization to send an invitation email to a user.

    **Parameters**

    * `invitation`: The invitation object containing the email of the user to invite and the ID of the organization to invite the user to.
    * `db`: The database session.
    * `user`: The current user.

    **Returns**

    A JSON response with a message indicating that the invitation was sent.

    **Raises**

    * `HTTPException`: If the user is not authorized to send invitations or the organization does not exist.
    """
    if is_Owner(user["id"], invitation.org_id, db) or is_Admin(
        user["id"], invitation.org_id, db
    ):
        organization = (
            db.query(Organization).filter(Organization.id == invitation.org_id).first()
        )
        user_detail = db.query(User).filter(User.email == (invitation.email)).first()
        if organization is not None and user_detail is not None:
            invite_token = generate_random_token()
            invite_data = Invitation(
                email=invitation.email,
                org_id=invitation.org_id,
                invite_token=invite_token,
            )
            db.add(invite_data)
            db.commit()
            db.refresh(invite_data)
            link = (
                f"http://127.0.0.1:8000/orgauth/member/accept_invitation/{invite_token}"
            )
            await send_mail(invitation.email, user_detail.username, link, "Invitation")

        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization or User does not exist",
            )

    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to send invitations",
        )
    return JSONResponse(status_code=200, content={"message": "Invitation sent"})


@router.get("/member/accept_invitation/{invite_token}")
async def accept_invitation(
    invite_token: str,
    db: db_dependency,
    user: user_dependency,
):
    """
    Accept an invitation.

    This endpoint allows a user to accept an invitation to an organization.

    **Parameters**

    * `invitation_id`: The ID of the invitation to accept.
    * `db`: The database session.
    * `user`: The current user.

    **Returns**

    A JSON response with a message indicating that the invitation was accepted.

    **Raises**

    * `HTTPException`: If the invitation does not exist or the user is not authorized to accept the invitation.
    """
    invitation = db.query(Invitation).filter(Invitation.token == invite_token).first()
    user_data = db.query(User).filter(User.id == user["id"]).first()
    if invitation is not None:
        if user_data is not None:
            if str(user_data.email) == str(invitation.email):
                organization = (
                    db.query(Organization)
                    .filter(Organization.id == invitation.org_id)
                    .first()
                )
                if organization is not None:
                    organization.add_user(user_data, db)
                    db.delete(invitation)
                    db.commit()
                    return JSONResponse(
                        status_code=200, content={"message": "Invitation accepted"}
                    )
                else:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Organization does not exist",
                    )
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not authorized to accept this invitation",
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation does not exist",
        )
