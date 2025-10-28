import pyotp
import qrcode
from io import BytesIO
import base64
from typing import Optional
from sqlalchemy.orm import Session
from app.models import User
from app.config import settings


def generate_mfa_secret() -> str:
    """Generate a new MFA secret for a user"""
    return pyotp.random_base32()


def generate_mfa_qr_code(user: User) -> str:
    """Generate a QR code for MFA setup"""
    if not user.mfa_secret:
        raise ValueError("User does not have MFA secret")
    
    totp = pyotp.TOTP(user.mfa_secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.email,
        issuer_name=settings.mfa_issuer_name
    )
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    
    # Create image
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    img_str = base64.b64encode(buffer.getvalue()).decode()
    
    return f"data:image/png;base64,{img_str}"


def verify_mfa_code(user: User, code: str) -> bool:
    """Verify an MFA code for a user"""
    if not user.mfa_secret or not user.mfa_enabled:
        return False
    
    totp = pyotp.TOTP(user.mfa_secret)
    return totp.verify(code, valid_window=1)  # Allow 1 window of tolerance


def enable_mfa_for_user(db: Session, user: User, secret: str) -> bool:
    """Enable MFA for a user with the given secret"""
    try:
        user.mfa_secret = secret
        user.mfa_enabled = True
        db.commit()
        return True
    except Exception:
        db.rollback()
        return False


def disable_mfa_for_user(db: Session, user: User) -> bool:
    """Disable MFA for a user"""
    try:
        user.mfa_secret = None
        user.mfa_enabled = False
        db.commit()
        return True
    except Exception:
        db.rollback()
        return False


def is_mfa_required(user: User) -> bool:
    """Check if MFA is required for a user"""
    return user.mfa_enabled and user.mfa_secret is not None
