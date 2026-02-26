from datetime import datetime, timezone
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload
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
from exceptions import TokenExpiredError, InvalidTokenError
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    MessageResponseSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
)
from security.interfaces import JWTAuthManagerInterface
from security.utils import ensure_utc

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
            await db.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail=f"A user with this email {user_data.email} already exists."
            )
        activation_token = ActivationTokenModel(user_id=user.id)
        db.add(activation_token)
        await db.commit()
        return user
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An error occurred during user creation."
        )


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_account(activation_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ActivationTokenModel)
        .join(ActivationTokenModel.user)
        .options(joinedload(ActivationTokenModel.user))
        .where(ActivationTokenModel.token == activation_data.token, UserModel.email == activation_data.email.lower())
    )
    token_obj = result.scalar_one_or_none()
    if token_obj is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired activation token.")
    expires_at = ensure_utc(token_obj.expires_at)
    user = token_obj.user
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired activation token.")
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User not found.")
    if user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User account is already active.")
    user.is_active = True
    await db.delete(token_obj)
    await db.commit()
    return MessageResponseSchema(message="User account activated successfully.")


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def request_password_reset(input_data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == input_data.email.lower()))
    user = result.scalar_one_or_none()
    if user and user.is_active:
        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
        token = PasswordResetTokenModel(user_id=user.id)
        db.add(token)
        await db.commit()
    return MessageResponseSchema(message="If you are registered, you will receive an email with instructions.")


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def reset_password(reset_payload: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(UserModel)
        .options(joinedload(UserModel.password_reset_token))
        .where(UserModel.email == reset_payload.email.lower())
    )
    raise_exception = HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token.")
    user = result.scalar_one_or_none()
    if user is None or user.password_reset_token is None:
        raise raise_exception
    if not user.is_active:
        raise raise_exception
    token_obj = user.password_reset_token
    if token_obj.token != reset_payload.token:
        await db.delete(token_obj)
        await db.commit()
        raise raise_exception
    expires_at = ensure_utc(token_obj.expires_at)
    if expires_at < datetime.now(timezone.utc):
        await db.delete(token_obj)
        await db.commit()
        raise raise_exception
    try:
        user.password = reset_payload.password
        await db.delete(token_obj)
        await db.commit()
        return MessageResponseSchema(message="Password reset successfully.")
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An error occurred while resetting the password."
        )


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login(
    login_payload: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    auth_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    result = await db.execute(select(UserModel).where(UserModel.email == login_payload.email.lower()))
    user = result.scalar_one_or_none()
    if user is None or not user.verify_password(login_payload.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is not activated.")
    access_token = auth_manager.create_access_token(data={"user_id": user.id})
    try:
        refresh_token = auth_manager.create_refresh_token(data={"user_id": user.id})
        refresh_token_obj = RefreshTokenModel.create(
            user_id=user.id, days_valid=settings.LOGIN_TIME_DAYS, token=refresh_token
        )
        db.add(refresh_token_obj)
        await db.commit()
        return UserLoginResponseSchema(access_token=access_token, refresh_token=refresh_token)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An error occurred while processing the request."
        )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_access_token(
    refresh_payload: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    auth_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        payload = auth_manager.decode_refresh_token(refresh_payload.refresh_token)
    except TokenExpiredError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired.")
    except InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token.")
    token_user_id = payload.get("user_id")
    if token_user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token.")
    result = await db.execute(select(RefreshTokenModel).where(RefreshTokenModel.token == refresh_payload.refresh_token))
    refresh_token_obj = result.scalar_one_or_none()
    if refresh_token_obj is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found.")
    if refresh_token_obj.user_id != token_user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token.")
    expires_at = ensure_utc(refresh_token_obj.expires_at)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired.")
    user = await db.get(UserModel, refresh_token_obj.user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    access_token = auth_manager.create_access_token(data={"user_id": refresh_token_obj.user_id})
    return TokenRefreshResponseSchema(access_token=access_token)
