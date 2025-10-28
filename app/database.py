from sqlalchemy import create_engine, MetaData
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.config import settings
import threading

# Create database engine with proper SQLite configuration
if settings.database_url.startswith("sqlite"):
    engine = create_engine(
        settings.database_url,
        connect_args={"check_same_thread": False},
        echo=False,
        pool_pre_ping=True,
        pool_recycle=300
    )
else:
    engine = create_engine(settings.database_url)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create declarative base
Base = declarative_base()

# Metadata for migrations
metadata = MetaData()

# Thread-local storage for database sessions
thread_local = threading.local()

def get_db():
    """Dependency to get database session - thread-safe for SQLite"""
    if not hasattr(thread_local, 'db') or thread_local.db is None:
        thread_local.db = SessionLocal()
    return thread_local.db

def close_db():
    """Close the current thread's database session"""
    if hasattr(thread_local, 'db') and thread_local.db is not None:
        thread_local.db.close()
        thread_local.db = None