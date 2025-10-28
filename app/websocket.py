from fastapi import WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from sqlalchemy.orm import Session
import json
import asyncio
import redis
from typing import List, Dict
from app.database import get_db
from app.models import User, Device, Location
from app.auth import get_current_active_user
from app.config import settings
from datetime import datetime, timedelta

# Redis connection for pub/sub
redis_client = redis.from_url(settings.redis_url, decode_responses=True)


class ConnectionManager:
    """Manages WebSocket connections for real-time updates"""
    
    def __init__(self):
        self.active_connections: Dict[int, List[WebSocket]] = {}
    
    async def connect(self, websocket: WebSocket, user_id: int):
        """Accept a WebSocket connection for a user"""
        await websocket.accept()
        if user_id not in self.active_connections:
            self.active_connections[user_id] = []
        self.active_connections[user_id].append(websocket)
    
    def disconnect(self, websocket: WebSocket, user_id: int):
        """Remove a WebSocket connection"""
        if user_id in self.active_connections:
            self.active_connections[user_id].remove(websocket)
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]
    
    async def send_personal_message(self, message: str, user_id: int):
        """Send a message to all connections for a specific user"""
        if user_id in self.active_connections:
            for connection in self.active_connections[user_id]:
                try:
                    await connection.send_text(message)
                except:
                    # Remove broken connections
                    self.active_connections[user_id].remove(connection)
    
    async def broadcast_to_user(self, user_id: int, data: dict):
        """Broadcast location data to a specific user"""
        message = json.dumps(data)
        await self.send_personal_message(message, user_id)


manager = ConnectionManager()


async def websocket_endpoint(
    websocket: WebSocket,
    token: str,
    db: Session = Depends(get_db)
):
    """WebSocket endpoint for real-time location updates"""
    # Verify the JWT token
    from app.auth import verify_token
    try:
        payload = verify_token(token, "access")
        user_id = int(payload.get("sub"))
    except:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    
    # Get user and verify they exist
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    
    # Connect the user
    await manager.connect(websocket, user_id)
    
    try:
        # Send initial device data
        devices = db.query(Device).filter(Device.owner_id == user_id).all()
        initial_data = {
            "type": "initial_data",
            "devices": []
        }
        
        for device in devices:
            # Get latest location for each device
            latest_location = db.query(Location).filter(
                Location.device_id == device.id
            ).order_by(Location.timestamp.desc()).first()
            
            device_data = {
                "id": device.id,
                "name": device.name,
                "device_id": device.device_id,
                "is_active": device.is_active,
                "last_seen": device.last_seen.isoformat() if device.last_seen else None,
                "latest_location": {
                    "latitude": latest_location.latitude,
                    "longitude": latest_location.longitude,
                    "altitude": latest_location.altitude,
                    "speed": latest_location.speed,
                    "timestamp": latest_location.timestamp.isoformat()
                } if latest_location else None
            }
            initial_data["devices"].append(device_data)
        
        await websocket.send_text(json.dumps(initial_data))
        
        # Keep connection alive and listen for messages
        while True:
            try:
                # Wait for any message from client (ping/pong)
                data = await websocket.receive_text()
                
                # Handle ping messages
                if data == "ping":
                    await websocket.send_text("pong")
                
            except WebSocketDisconnect:
                break
                
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(websocket, user_id)


async def location_broadcast_worker():
    """Background worker to broadcast location updates to connected clients"""
    from app.database import SessionLocal
    
    pubsub = redis_client.pubsub()
    pubsub.subscribe("location_updates")
    
    for message in pubsub.listen():
        if message["type"] == "message":
            try:
                location_data = json.loads(message["data"])
                device_id = location_data["device_id"]
                
                # Find the owner of this device
                db = SessionLocal()
                try:
                    device = db.query(Device).filter(Device.id == device_id).first()
                    if device:
                        # Broadcast to the device owner
                        await manager.broadcast_to_user(device.owner_id, {
                            "type": "location_update",
                            "data": location_data
                        })
                finally:
                    db.close()
                    
            except Exception as e:
                print(f"Error broadcasting location update: {e}")


# Start the background worker
async def start_location_broadcaster():
    """Start the location broadcast worker"""
    asyncio.create_task(location_broadcast_worker())
