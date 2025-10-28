#!/usr/bin/env python3
"""
Test script to verify LibreAntiTheft setup
"""

import sys
import os
from pathlib import Path

def test_imports():
    """Test if all required modules can be imported"""
    print("Testing imports...")
    
    try:
        from app.config import settings
        print("✓ Config module imported")
    except ImportError as e:
        print(f"✗ Config import failed: {e}")
        return False
    
    try:
        from app.database import get_db, engine, Base
        print("✓ Database module imported")
    except ImportError as e:
        print(f"✗ Database import failed: {e}")
        return False
    
    try:
        from app.models import User, Device, Location
        print("✓ Models imported")
    except ImportError as e:
        print(f"✗ Models import failed: {e}")
        return False
    
    try:
        from app.auth import authenticate_user, create_access_token
        print("✓ Auth module imported")
    except ImportError as e:
        print(f"✗ Auth import failed: {e}")
        return False
    
    try:
        from app.mfa import generate_mfa_secret, verify_mfa_code
        print("✓ MFA module imported")
    except ImportError as e:
        print(f"✗ MFA import failed: {e}")
        return False
    
    return True

def test_database_connection():
    """Test database connection"""
    print("\nTesting database connection...")
    
    try:
        from app.database import engine
        from sqlalchemy import text
        
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            print("✓ Database connection successful")
            return True
    except Exception as e:
        print(f"✗ Database connection failed: {e}")
        print("Make sure PostgreSQL is running and DATABASE_URL is correct")
        return False

def test_redis_connection():
    """Test Redis connection"""
    print("\nTesting Redis connection...")
    
    try:
        from app.config import settings
        import redis
        
        r = redis.from_url(settings.redis_url)
        r.ping()
        print("✓ Redis connection successful")
        return True
    except Exception as e:
        print(f"✗ Redis connection failed: {e}")
        print("Make sure Redis is running and REDIS_URL is correct")
        return False

def test_environment():
    """Test environment configuration"""
    print("\nTesting environment configuration...")
    
    from app.config import settings
    
    if settings.secret_key == "your-secret-key-here-change-this-in-production":
        print("⚠ Warning: Using default secret key. Change this in production!")
    else:
        print("✓ Secret key configured")
    
    if settings.database_url.startswith("postgresql://"):
        print("✓ Database URL configured")
    else:
        print("✗ Invalid database URL")
        return False
    
    if settings.redis_url.startswith("redis://"):
        print("✓ Redis URL configured")
    else:
        print("✗ Invalid Redis URL")
        return False
    
    return True

def main():
    """Run all tests"""
    print("LibreAntiTheft - Setup Test")
    print("=" * 40)
    
    all_passed = True
    
    # Test imports
    if not test_imports():
        all_passed = False
    
    # Test environment
    if not test_environment():
        all_passed = False
    
    # Test database
    if not test_database_connection():
        all_passed = False
    
    # Test Redis
    if not test_redis_connection():
        all_passed = False
    
    print("\n" + "=" * 40)
    if all_passed:
        print("✓ All tests passed! Setup is ready.")
        print("\nTo start the server, run:")
        print("  python start.py")
        print("\nOr with Docker:")
        print("  docker-compose up -d")
    else:
        print("✗ Some tests failed. Please fix the issues above.")
        sys.exit(1)

if __name__ == "__main__":
    main()
