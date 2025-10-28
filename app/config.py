from pydantic_settings import BaseSettings
from typing import List
import os


class Settings(BaseSettings):
    # Database Configuration
    database_url: str = "postgresql://username:password@localhost:5432/libreantitheft"
    redis_url: str = "redis://localhost:6379/0"
    
    # Security Configuration
    secret_key: str = "your-secret-key-here-change-this-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    
    # MFA Configuration
    mfa_issuer_name: str = "LibreAntiTheft"
    
    # Server Configuration
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = True
    
    # CORS Configuration
    allowed_origins: List[str] = ["http://localhost:3000", "http://localhost:8080"]
    
    # Rate Limiting
    rate_limit_per_minute: int = 60
    
    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
