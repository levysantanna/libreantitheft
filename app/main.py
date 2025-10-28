from fastapi import FastAPI, Depends, HTTPException, status, Request, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from contextlib import asynccontextmanager
import redis
import json
import secrets
from datetime import datetime, timedelta
from typing import List
import os

from app.config import settings
from app.database import get_db, engine, Base
from app.models import User, Device, Location, RefreshToken
from app.schemas import (
    UserCreate, UserResponse, UserUpdate,
    DeviceCreate, DeviceResponse, DeviceUpdate, DeviceWithSecret,
    LocationCreate, LocationResponse,
    LoginRequest, TokenResponse, RefreshTokenRequest,
    MfaSetupResponse, MfaVerifyRequest,
    OsmAndLocationData, DashboardStats, DeviceLocation,
    ErrorResponse
)
from app.auth import (
    authenticate_user, get_current_active_user, create_access_token,
    create_refresh_token, verify_token, log_login_attempt,
    generate_device_secret, hash_device_key, verify_device_key,
    get_password_hash
)
from app.mfa import (
    generate_mfa_secret, generate_mfa_qr_code, verify_mfa_code,
    enable_mfa_for_user, disable_mfa_for_user, is_mfa_required
)

# Redis connection for real-time features
redis_client = redis.from_url(settings.redis_url, decode_responses=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    Base.metadata.create_all(bind=engine)
    yield
    # Shutdown
    redis_client.close()


app = FastAPI(
    title="LibreAntiTheft API",
    description="A secure REST API for OsmAnd device tracking with MFA authentication",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Trusted host middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"]  # Configure appropriately for production
)

# Mount static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")


# Rate limiting decorator
def rate_limit(request: Request):
    """Simple rate limiting based on IP"""
    client_ip = request.client.host
    key = f"rate_limit:{client_ip}"
    
    current = redis_client.get(key)
    if current is None:
        redis_client.setex(key, 60, 1)  # 1 minute window
    else:
        if int(current) >= settings.rate_limit_per_minute:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded"
            )
        redis_client.incr(key)


# Authentication endpoints
@app.post("/auth/register", response_model=UserResponse)
async def register_user(
    user_data: UserCreate,
    db: Session = Depends(get_db)
):
    """Register a new user"""
    # Check if user already exists
    existing_user = db.query(User).filter(
        (User.username == user_data.username) | (User.email == user_data.email)
    ).first()
    
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered"
        )
    
    # Create new user
    hashed_password = get_password_hash(user_data.password)
    db_user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_password
    )
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    return db_user


@app.post("/auth/login", response_model=TokenResponse)
async def login_user(
    login_data: LoginRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """Login user and return JWT tokens"""
    rate_limit(request)
    
    # Authenticate user
    user = authenticate_user(db, login_data.username, login_data.password)
    
    if not user:
        log_login_attempt(
            db, login_data.username, request.client.host,
            False, "Invalid credentials", request.headers.get("user-agent")
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    # Check if MFA is required
    if is_mfa_required(user):
        if not login_data.mfa_code:
            log_login_attempt(
                db, login_data.username, request.client.host,
                False, "MFA required but not provided", request.headers.get("user-agent")
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA code required"
            )
        
        if not verify_mfa_code(user, login_data.mfa_code):
            log_login_attempt(
                db, login_data.username, request.client.host,
                False, "Invalid MFA code", request.headers.get("user-agent")
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid MFA code"
            )
    
    # Create tokens
    access_token = create_access_token(data={"sub": str(user.id)})
    refresh_token = create_refresh_token(data={"sub": str(user.id)})
    
    # Store refresh token
    db_refresh_token = RefreshToken(
        token=refresh_token,
        user_id=user.id,
        expires_at=datetime.utcnow() + timedelta(days=settings.refresh_token_expire_days)
    )
    db.add(db_refresh_token)
    
    log_login_attempt(
        db, login_data.username, request.client.host,
        True, None, request.headers.get("user-agent")
    )
    
    db.commit()
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60
    )


@app.post("/auth/refresh", response_model=TokenResponse)
async def refresh_token(
    token_data: RefreshTokenRequest,
    db: Session = Depends(get_db)
):
    """Refresh access token using refresh token"""
    # Verify refresh token
    payload = verify_token(token_data.refresh_token, "refresh")
    user_id = payload.get("sub")
    
    # Check if refresh token exists in database
    db_token = db.query(RefreshToken).filter(
        RefreshToken.token == token_data.refresh_token,
        RefreshToken.user_id == user_id,
        RefreshToken.is_revoked == False
    ).first()
    
    if not db_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    # Create new access token
    access_token = create_access_token(data={"sub": str(user_id)})
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=token_data.refresh_token,
        expires_in=settings.access_token_expire_minutes * 60
    )


# MFA endpoints
@app.post("/auth/mfa/setup", response_model=MfaSetupResponse)
async def setup_mfa(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Setup MFA for the current user"""
    if current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA already enabled"
        )
    
    secret = generate_mfa_secret()
    current_user.mfa_secret = secret
    db.commit()
    
    qr_code_url = generate_mfa_qr_code(current_user)
    
    return MfaSetupResponse(secret=secret, qr_code_url=qr_code_url)


@app.post("/auth/mfa/verify", response_model=dict)
async def verify_mfa_setup(
    mfa_data: MfaVerifyRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Verify MFA setup and enable it"""
    if not current_user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA not set up"
        )
    
    if not verify_mfa_code(current_user, mfa_data.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid MFA code"
        )
    
    enable_mfa_for_user(db, current_user, current_user.mfa_secret)
    
    return {"message": "MFA enabled successfully"}


@app.delete("/auth/mfa/disable")
async def disable_mfa(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Disable MFA for the current user"""
    if not current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA not enabled"
        )
    
    disable_mfa_for_user(db, current_user)
    
    return {"message": "MFA disabled successfully"}


# Device management endpoints
@app.post("/devices", response_model=DeviceWithSecret)
async def create_device(
    device_data: DeviceCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Create a new device for tracking"""
    # Generate unique device ID and secret
    device_id = f"device_{secrets.token_urlsafe(16)}"
    secret_key = generate_device_secret()
    hashed_secret = hash_device_key(device_id, secret_key)
    
    db_device = Device(
        name=device_data.name,
        device_id=device_id,
        secret_key=hashed_secret,
        owner_id=current_user.id
    )
    
    db.add(db_device)
    db.commit()
    db.refresh(db_device)
    
    # Return device with secret (only shown once)
    return DeviceWithSecret(
        id=db_device.id,
        name=db_device.name,
        device_id=db_device.device_id,
        secret_key=secret_key,
        is_active=db_device.is_active,
        last_seen=db_device.last_seen,
        created_at=db_device.created_at
    )


@app.get("/devices", response_model=List[DeviceResponse])
async def get_devices(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get all devices for the current user"""
    devices = db.query(Device).filter(Device.owner_id == current_user.id).all()
    return devices


@app.get("/devices/{device_id}", response_model=DeviceResponse)
async def get_device(
    device_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get a specific device"""
    device = db.query(Device).filter(
        Device.id == device_id,
        Device.owner_id == current_user.id
    ).first()
    
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )
    
    return device


@app.put("/devices/{device_id}", response_model=DeviceResponse)
async def update_device(
    device_id: int,
    device_data: DeviceUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Update a device"""
    device = db.query(Device).filter(
        Device.id == device_id,
        Device.owner_id == current_user.id
    ).first()
    
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )
    
    if device_data.name is not None:
        device.name = device_data.name
    if device_data.is_active is not None:
        device.is_active = device_data.is_active
    
    db.commit()
    db.refresh(device)
    
    return device


@app.delete("/devices/{device_id}")
async def delete_device(
    device_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Delete a device"""
    device = db.query(Device).filter(
        Device.id == device_id,
        Device.owner_id == current_user.id
    ).first()
    
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )
    
    db.delete(device)
    db.commit()
    
    return {"message": "Device deleted successfully"}


# OsmAnd integration endpoint
@app.post("/osmand/tracker")
async def receive_location_data(
    lat: float,
    lon: float,
    timestamp: int,
    hdop: float = None,
    altitude: float = None,
    speed: float = None,
    key: str = None,
    db: Session = Depends(get_db)
):
    """Receive location data from OsmAnd devices"""
    if not key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Secret key required"
        )
    
    # Find device by secret key
    device = db.query(Device).filter(Device.is_active == True).first()
    if not device:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid device key"
        )
    
    # Verify the key (simplified for this example)
    if not verify_device_key(device.device_id, key, device.secret_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid device key"
        )
    
    # Convert timestamp
    from datetime import datetime
    location_timestamp = datetime.fromtimestamp(timestamp)
    
    # Create location record
    location = Location(
        device_id=device.id,
        latitude=lat,
        longitude=lon,
        altitude=altitude,
        speed=speed,
        hdop=hdop,
        timestamp=location_timestamp
    )
    
    db.add(location)
    
    # Update device last seen
    device.last_seen = datetime.utcnow()
    
    db.commit()
    
    # Publish to Redis for real-time updates
    location_data = {
        "device_id": device.id,
        "device_name": device.name,
        "latitude": lat,
        "longitude": lon,
        "altitude": altitude,
        "speed": speed,
        "timestamp": location_timestamp.isoformat()
    }
    
    redis_client.publish("location_updates", json.dumps(location_data))
    
    return {"status": "success", "message": "Location data received"}


# Dashboard endpoints
@app.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get dashboard statistics"""
    user_devices = db.query(Device).filter(Device.owner_id == current_user.id)
    
    total_devices = user_devices.count()
    active_devices = user_devices.filter(Device.is_active == True).count()
    
    # Get location counts
    device_ids = [d.id for d in user_devices.all()]
    total_locations = db.query(Location).filter(Location.device_id.in_(device_ids)).count()
    
    # Recent locations (last 24 hours)
    from datetime import datetime, timedelta
    recent_cutoff = datetime.utcnow() - timedelta(hours=24)
    recent_locations = db.query(Location).filter(
        Location.device_id.in_(device_ids),
        Location.created_at >= recent_cutoff
    ).count()
    
    return DashboardStats(
        total_devices=total_devices,
        active_devices=active_devices,
        total_locations=total_locations,
        recent_locations=recent_locations
    )


@app.get("/dashboard/devices", response_model=List[DeviceLocation])
async def get_dashboard_devices(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get devices with their latest locations for dashboard"""
    devices = db.query(Device).filter(Device.owner_id == current_user.id).all()
    
    result = []
    for device in devices:
        # Get latest location
        latest_location = db.query(Location).filter(
            Location.device_id == device.id
        ).order_by(Location.timestamp.desc()).first()
        
        # Check if device is online (seen within last 5 minutes)
        from datetime import datetime, timedelta
        is_online = False
        if device.last_seen:
            is_online = device.last_seen > datetime.utcnow() - timedelta(minutes=5)
        
        result.append(DeviceLocation(
            device=DeviceResponse.from_orm(device),
            latest_location=LocationResponse.from_orm(latest_location) if latest_location else None,
            is_online=is_online
        ))
    
    return result


# WebSocket endpoint for real-time updates
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str):
    """WebSocket endpoint for real-time location updates"""
    from app.websocket import websocket_endpoint as ws_endpoint
    await ws_endpoint(websocket, token)


# Serve the dashboard
@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve the main dashboard"""
    with open("app/static/index.html", "r") as f:
        return HTMLResponse(content=f.read())


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "LibreAntiTheft API"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.host, port=settings.port)
