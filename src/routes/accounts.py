from datetime import datetime, timezone, UTC
from typing import cast
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload
from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from exceptions import BaseSecurityError
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register_user(user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Default group not found")
    try:
        user = UserModel.create(email=user_data.email, raw_password=user_data.password, group_id=group.id)
        db.add(user)
        try:
            await db.flush()
        except IntegrityError:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail=f"A user with this email {user.email} already exists."
            )
        activation_token = ActivationTokenModel(user_id=user.id)
        db.add(activation_token)
        await db.commit()
        return user
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An error occurred during user creation."
        )


@router.post("/activate/")
async def activate_account(activation_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ActivationTokenModel)
        .options(joinedload(ActivationTokenModel.user))
        .where(ActivationTokenModel.token == activation_data.token)
    )
    token_obj = result.scalar_one_or_none()
    if token_obj is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired activation token.")
    expires_at = token_obj.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    user = token_obj.user
    error = None
    if expires_at < datetime.now(UTC):
        error = "Invalid or expired activation token."
    elif user is None:
        error = "User not found."
    elif user.is_active:
        error = "User account is already active."
    if error:
        await db.delete(token_obj)
        await db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)
    user.is_active = True
    await db.delete(token_obj)
    await db.commit()
    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/")
async def request_password_reset(input_data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == input_data.email))
    user = result.scalar_one_or_none()
    if user:
        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
        if user.is_active:
            token = PasswordResetTokenModel(user_id=user.id)
            db.add(token)
            await db.commit()
    return {"message": "If you are registered, you will receive an email with instructions."}
