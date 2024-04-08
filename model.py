from database import Base
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey
from sqlalchemy.orm import relationship, Session


class UserOrganization(Base):
    __tablename__ = "user_organizations"
    id = Column(Integer, primary_key=True)
    user_id = Column("user_id", Integer, ForeignKey("users.id"))
    org_id = Column("org_id", Integer, ForeignKey("organizations.id"))
    isAdmin = Column(Boolean, default=False)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    email = Column(String(100), unique=True, index=True)
    hashed_password = Column(String)
    isVerified = Column(Boolean, default=False)
    isDeleted = Column(Boolean, default=False)
    organizations = relationship(
        "Organization", secondary="user_organizations", back_populates="users"
    )


class Organization(Base):
    __tablename__ = "organizations"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), index=True)
    description = Column(String, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    users = relationship(
        "User", secondary="user_organizations", back_populates="organizations"
    )

    def add_user(self, user: User, db: Session, is_admin: bool = False):
        user_organization = UserOrganization(
            user_id=user.id, org_id=self.id, isAdmin=is_admin
        )
        db.add(user_organization)
        db.commit()
        db.refresh(user_organization)

    def remove_user(self, user: User, db: Session):
        user_organization = (
            db.query(UserOrganization)
            .filter(
                UserOrganization.user_id == user.id, UserOrganization.org_id == self.id
            )
            .first()
        )
        if user_organization:
            db.delete(user_organization)
            db.commit()
