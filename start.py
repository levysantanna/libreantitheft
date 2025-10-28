#!/usr/bin/env python3
"""
Startup script for LibreAntiTheft
Handles database initialization and starts the server
"""

import os
import sys
import subprocess
import time
from pathlib import Path

def check_dependencies():
    """Check if required dependencies are installed"""
    try:
        import fastapi
        import sqlalchemy
        import redis
        import pyotp
        print("✓ All dependencies are installed")
        return True
    except ImportError as e:
        print(f"✗ Missing dependency: {e}")
        print("Please run: pip install -r requirements.txt")
        return False

def check_environment():
    """Check if environment variables are set"""
    env_file = Path(".env")
    if not env_file.exists():
        print("✗ .env file not found")
        print("Please copy env.example to .env and configure it")
        return False
    
    print("✓ Environment file found")
    return True

def run_migrations():
    """Run database migrations"""
    try:
        print("Running database migrations...")
        result = subprocess.run(
            ["alembic", "upgrade", "head"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print("✓ Database migrations completed")
            return True
        else:
            print(f"✗ Migration failed: {result.stderr}")
            return False
    except FileNotFoundError:
        print("✗ Alembic not found. Please install dependencies first")
        return False

def start_server():
    """Start the FastAPI server"""
    try:
        print("Starting LibreAntiTheft server...")
        print("Dashboard will be available at: http://localhost:8000")
        print("API documentation at: http://localhost:8000/docs")
        print("Press Ctrl+C to stop the server")
        
        subprocess.run([
            "uvicorn", "app.main:app",
            "--host", "0.0.0.0",
            "--port", "8000",
            "--reload"
        ])
    except KeyboardInterrupt:
        print("\nServer stopped")
    except FileNotFoundError:
        print("✗ Uvicorn not found. Please install dependencies first")

def main():
    """Main startup function"""
    print("LibreAntiTheft - Starting up...")
    print("=" * 50)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Check environment
    if not check_environment():
        sys.exit(1)
    
    # Run migrations
    if not run_migrations():
        sys.exit(1)
    
    # Start server
    start_server()

if __name__ == "__main__":
    main()
