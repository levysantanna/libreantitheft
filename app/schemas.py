from pydantic import BaseModel, EmailStr, validator
from typing import Optional, List
from datetime import datetime
from decimal import Decimal


# User Schemas
class UserBase(BaseModel):
    username: str
    email: EmailStr


class UserCreate(UserBase):
    password: str
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v


class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    password: Optional[str] = None


class UserResponse(UserBase):
    id: int
    is_active: bool
    is_verified: bool
    mfa_enabled: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


# Device Schemas
class DeviceBase(BaseModel):
    name: str


class DeviceCreate(DeviceBase):
    pass


class DeviceUpdate(BaseModel):
    name: Optional[str] = None
    is_active: Optional[bool] = None


class DeviceResponse(DeviceBase):
    id: int
    device_id: str
    is_active: bool
    last_seen: Optional[datetime]
    created_at: datetime
    
    class Config:
        from_attributes = True


class DeviceWithSecret(DeviceResponse):
    secret_key: str


# Location Schemas
class LocationBase(BaseModel):
    latitude: float
    longitude: float
    altitude: Optional[float] = None
    speed: Optional[float] = None
    heading: Optional[float] = None
    accuracy: Optional[float] = None
    hdop: Optional[float] = None
    timestamp: datetime


class LocationCreate(LocationBase):
    pass


class LocationResponse(LocationBase):
    id: int
    device_id: int
    created_at: datetime
    
    class Config:
        from_attributes = True


# Authentication Schemas
class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_code: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class MfaSetupResponse(BaseModel):
    secret: str
    qr_code_url: str


class MfaVerifyRequest(BaseModel):
    code: str


# OsmAnd Integration Schemas
class OsmAndLocationData(BaseModel):
    lat: float
    lon: float
    timestamp: int
    hdop: Optional[float] = None
    altitude: Optional[float] = None
    speed: Optional[float] = None
    key: str  # Secret key for device authentication


# Dashboard Schemas
class DashboardStats(BaseModel):
    total_devices: int
    active_devices: int
    total_locations: int
    recent_locations: int


class DeviceLocation(BaseModel):
    device: DeviceResponse
    latest_location: Optional[LocationResponse]
    is_online: bool


# Error Schemas
class ErrorResponse(BaseModel):
    detail: str
    error_code: Optional[str] = None
