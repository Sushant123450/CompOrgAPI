from datetime import timedelta, datetime
from typing import Dict, Annotated
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from sqlalchemy import Column, Boolean
from starlette import status
from database import SessionLocal
from model import User
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError
from fastapi.responses import JSONResponse
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType

router = APIRouter(prefix="/auth", tags=["auth"])

SECRET_KEY = "98c49823694c2n34nx23423m4234n02384207394n023049"
ALGORITHM = "HS256"

conf = ConnectionConfig(
    MAIL_USERNAME="Sushant123450.sk@gmail.com",
    MAIL_PASSWORD="hxha ixew ebur urot",
    MAIL_FROM="Sushant123450.sk@gmail.com",
    MAIL_PORT=465,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_STARTTLS=False,
    MAIL_SSL_TLS=True,
)

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="auth/token")


class UserResponse(BaseModel):
    username: str
    email: EmailStr
    password: str
    confirm_password: str


class NewPasswordRequest(BaseModel):
    NewPassword: str
    ConfirmNewPassword: str


class ForgotPasswordRequest(BaseModel):
    username: str
    email: EmailStr


class CreateUserRequest(BaseModel):
    username: str
    email: EmailStr
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def authenticate_user(username: str, password: str, db):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return {"error": "User Not Found"}
    if not bcrypt_context.verify(password, user.hashed_password):
        return {"error": "Incorrect Password Found"}
    if not user.isVerified:
        return {"error": "Verification Pending"}
    return user


def create_access_token(
    username: Column[str], user_id: Column[int], expires_delta: timedelta
):
    encode = {"sub": username, "id": user_id}
    expires = datetime.utcnow() + expires_delta
    encode.update({"exp": expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


def token_decode(token: str):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    return payload.get("sub"), payload.get("id")


async def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    try:
        username, user_id = token_decode(token)
        if username is None or user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="UserId and Username can not be null.",
            )
        return {"id": user_id, "username": username}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Could not validate user. {e}",
        )


@router.post("/revalidate-token")
async def revalidate_token(token: str = Depends(oauth2_bearer)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        user_id = payload.get("id")

        if not username or not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="UserId and Username can not be null.",
            )

        access_token_expires = timedelta(minutes=30)
        new_token = create_access_token(username, user_id, access_token_expires)

        return {"access_token": new_token, "token_type": "bearer"}
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token"
        )


async def send_mail(email: EmailStr, username: Column[str], link: str, type: str):
    if type == "Verification":
        template = f"""
            <html><head>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
            </head><body>
        <p>Hello {username}</p><p> Thank you registering to our service. Click on button to verify your account.</p>  
        <a href="{link}"><button type="button" class="btn btn-primary btn-lg">Verify Account</button></a></br>
        </body></html>
        """
        message = MessageSchema(
            subject="CompOrgAPI Verification",
            recipients=[email],
            body=template,
            subtype=MessageType.html,
        )

    elif type == "Forgot":
        template = f"""
            <html><head>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
            </head><body>
        <p>Hello {username}</p><p> Click on button to forget password</p>  
        <a href="{link}"><button type="button" class="btn btn-primary btn-lg">Verify Account</button></a></br>
        </body></html>
        """
        message = MessageSchema(
            subject="CompOrgAPI Account Forgot Password",
            recipients=[email],
            body=template,
            subtype=MessageType.html,
        )
    elif type == "Invite":
        template = f"""
            <html><head>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
            </head><body>
        <p>Hello {username}</p><p> Click on button to join organization</p>  
        <a href="{link}"><button type="button" class="btn btn-primary btn-lg">Join Now</button></a></br>
        </body></html>
        """
        message = MessageSchema(
            subject="Join organization Today",
            recipients=[email],
            body=template,
            subtype=MessageType.html,
        )

    fm = FastMail(conf)
    await fm.send_message(message)
    return JSONResponse(status_code=200, content={"message": "email has been sent"})


db_dependency = Annotated[Session, Depends(get_db)]


@router.post("/register/")
async def register_user(
    request: Request,
    input: UserResponse,
    db: Session = Depends(get_db),
):
    hashed_confirm_password = bcrypt_context.hash(input.confirm_password)
    if bcrypt_context.verify(input.password, hashed_confirm_password):
        create_user_model = User(
            username=input.username,
            email=input.email,
            hashed_password=hashed_confirm_password,
        )
        db.add(create_user_model)
        db.commit()
        id = create_user_model.id
        username = create_user_model.username
        email = create_user_model.email

        token = create_access_token(username, id, timedelta(minutes=60))
        link = f"http://127.0.0.1:8000/auth/verify?token={token}"

        await send_mail(str(email), username, link, "Verification")

    else:
        return JSONResponse(
            status_code=406,
            content={
                "message": "Both Passwords Doesn't match. Try again",
            },
        )

    return JSONResponse(
        status_code=200,
        content={
            "message": "User registered successfully",
            "username": create_user_model.username,
            "email": create_user_model.email,
            "token": link,
            "id": id,
            "isVerified": create_user_model.isVerified,
        },
    )


@router.get("/verify")
async def verify(request: Request, db: db_dependency, token: str):
    try:
        username, user_id = token_decode(token)

        if username is None or user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": "Invalid access token"},
            )
        else:
            user = db.query(User).filter(User.username == username).first()
            if user:
                user.isVerified = True
                db.commit()
    except JWTError:
        raise HTTPException(status_code=status.HTTP_402_UNAUTHORIZED, detail="JWTError")
    return JSONResponse(
        status_code=200,
        content={"token": token, "message": "You account is verified"},
    )


@router.post("/token")  # , response_model=Token)
async def Login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependency
):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate user."
        )
    if type(user) == dict:
        return user
    if user:
        token = create_access_token(user.username, user.id, timedelta(minutes=20))
        return {"access_token": token, "token_type": "bearer"}


@router.post("/forgot-password/")
async def forgot_password(
    db: db_dependency, request: Request, ForgotPassword: ForgotPasswordRequest
):
    User_email = ForgotPassword.email
    User_username = ForgotPassword.username
    result = (
        db.query(User)
        .filter(User.username == User_username, User.email == User_email)
        .first()
    )
    if result is None:
        return {"msg": "No such email or username exists"}

    token = create_access_token(result.username, result.id, timedelta(minutes=20))
    link = f"http://127.0.0.1:8000/auth/forgot-pass?token={token}"

    await send_mail(str(User_email), result.username, link, "Forgot")
    return {"msg": "Email has sent  to your registered mail id"}


@router.post("/reset-password/")
async def email_forgot_password(
    request: Request, db: db_dependency, token: str, NewPass: NewPasswordRequest
):
    try:
        username, user_id = token_decode(token)
        if username is None or user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": "Invalid access token"},
            )
        else:
            user = (
                db.query(User)
                .filter(User.username == username, User.id == user_id)
                .first()
            )
            if user:
                password = bcrypt_context.hash(NewPass.ConfirmNewPassword)
                if bcrypt_context.verify(NewPass.NewPassword, password):
                    db.query(User).filter(User.username == username).update(
                        {"hashed_password": password}
                    )
                db.commit()
            else:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="User Not Found"
                )
    except JWTError:
        raise HTTPException(status_code=status.HTTP_402_UNAUTHORIZED, detail="JWTError")
    return JSONResponse(
        status_code=200,
        content={"token": token, "message": "Password is resetted"},
    )
