from fastapi import FastAPI, Depends, HTTPException, status, Request, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from contextlib import asynccontextmanager
import json
import secrets
from datetime import datetime, timedelta
from typing import List
import os

from app.config import settings
from app.database import get_db, engine, Base, close_db
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

# Simple in-memory storage for real-time features (replaces Redis)
location_updates = []

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    Base.metadata.create_all(bind=engine)
    yield
    # Shutdown

app = FastAPI(
    title="LibreAntiTheft API",
    description="A secure REST API for OsmAnd device tracking with MFA authentication",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for demo
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Rate limiting decorator
def rate_limit(request: Request):
    """Simple rate limiting based on IP"""
    # Simplified rate limiting for demo
    pass

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

# Device management endpoints
@app.post("/devices", response_model=DeviceWithSecret)
async def create_device(
    device_data: DeviceCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Create a new device for tracking"""
    try:
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
            secret_key=secret_key,  # Return the original secret key, not the hash
            is_active=db_device.is_active,
            last_seen=db_device.last_seen,
            created_at=db_device.created_at
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error creating device: {str(e)}")
    finally:
        close_db()

@app.get("/devices", response_model=List[DeviceResponse])
async def get_devices(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get all devices for the current user"""
    try:
        devices = db.query(Device).filter(Device.owner_id == current_user.id).all()
        return devices
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching devices: {str(e)}")
    finally:
        close_db()

@app.delete("/devices/{device_id}")
async def delete_device(
    device_id: str, 
    current_user: User = Depends(get_current_active_user), 
    db: Session = Depends(get_db)
):
    """Delete a device"""
    try:
        device = db.query(Device).filter(
            Device.device_id == device_id,
            Device.owner_id == current_user.id
        ).first()
        
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        db.delete(device)
        db.commit()
        
        return {"message": "Device deleted successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error deleting device: {str(e)}")
    finally:
        close_db()

# OsmAnd integration endpoint
@app.get("/osmand/tracker")
async def receive_location_data(
    lat: str,
    lon: str,
    timestamp: str,
    hdop: str = None,
    altitude: str = None,
    speed: str = None,
    key: str = None,
    db: Session = Depends(get_db)
):
    """Receive location data from OsmAnd devices"""
    print(f"OsmAnd data received: lat={lat}, lon={lon}, timestamp={timestamp}, key={key}")
    
    if not key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Secret key required"
        )
    
    # Skip if placeholders are still in the URL (OsmAnd hasn't replaced them yet)
    if lat.startswith('{') or lon.startswith('{') or timestamp.startswith('{'):
        print("Skipping request with placeholders")
        return {"status": "skipped", "message": "Placeholders not replaced yet"}
    
    try:
        # Convert string parameters to appropriate types
        lat_float = float(lat)
        lon_float = float(lon)
        timestamp_int = int(timestamp)
        hdop_float = float(hdop) if hdop and hdop != 'None' else None
        altitude_float = float(altitude) if altitude and altitude != 'None' else None
        speed_float = float(speed) if speed and speed != 'None' else None
        print(f"Converted parameters: lat={lat_float}, lon={lon_float}, timestamp={timestamp_int}")
    except (ValueError, TypeError) as e:
        print(f"Error converting parameters: {e}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid parameter format: {str(e)}"
        )
    
    # Find device by secret key (compare with hash)
    from app.auth import hash_device_key, verify_device_key
    
    # Find device by checking all devices
    devices = db.query(Device).filter(Device.is_active == True).all()
    device = None
    for d in devices:
        if verify_device_key(d.device_id, key, d.secret_key):
            device = d
            break
    
    if not device:
        print(f"Device not found for key: {key}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid device key"
        )
    
    # Convert timestamp (handle both seconds and milliseconds)
    if timestamp_int > 10000000000:  # If timestamp is in milliseconds
        timestamp_int = timestamp_int // 1000
    location_timestamp = datetime.fromtimestamp(timestamp_int)
    print(f"Converted timestamp: {location_timestamp}")
    
    # Create location record
    location = Location(
        device_id=device.id,
        latitude=lat_float,
        longitude=lon_float,
        altitude=altitude_float,
        speed=speed_float,
        hdop=hdop_float,
        timestamp=location_timestamp
    )
    
    db.add(location)
    
    # Update device last seen
    device.last_seen = datetime.utcnow()
    
    db.commit()
    
    # Store for real-time updates (simplified)
    location_data = {
        "device_id": device.id,
        "device_name": device.name,
        "latitude": lat,
        "longitude": lon,
        "altitude": altitude,
        "speed": speed,
        "timestamp": location_timestamp.isoformat()
    }
    
    location_updates.append(location_data)
    # Keep only last 100 updates
    if len(location_updates) > 100:
        location_updates.pop(0)
    
    print(f"Location saved: lat={lat_float}, lon={lon_float}, device={device.device_id}")
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
        is_online = False
        if device.last_seen:
            is_online = device.last_seen > datetime.utcnow() - timedelta(minutes=5)
        
        result.append(DeviceLocation(
            device=DeviceResponse.from_orm(device),
            latest_location=LocationResponse.from_orm(latest_location) if latest_location else None,
            is_online=is_online
        ))
    
    return result

# Serve favicon
@app.get("/favicon.ico")
async def favicon():
    return {"message": "No favicon"}

# Serve test page
@app.get("/test.html", response_class=HTMLResponse)
async def serve_test():
    """Serve the test page"""
    with open("test.html", "r") as f:
        return HTMLResponse(content=f.read())

# Serve debug page
@app.get("/debug.html", response_class=HTMLResponse)
async def serve_debug():
    """Serve the debug page"""
    with open("debug.html", "r") as f:
        return HTMLResponse(content=f.read())

# Serve URL test page
@app.get("/url_test.html", response_class=HTMLResponse)
async def serve_url_test():
    """Serve the URL test page"""
    with open("url_test.html", "r") as f:
        return HTMLResponse(content=f.read())

# Serve simple test page
@app.get("/simple_test.html", response_class=HTMLResponse)
async def serve_simple_test():
    """Serve the simple test page"""
    with open("simple_test.html", "r") as f:
        return HTMLResponse(content=f.read())

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
