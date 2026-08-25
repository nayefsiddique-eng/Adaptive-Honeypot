import hmac
import logging
from fastapi import Header, HTTPException, Request
from backend.config import settings

logger = logging.getLogger("api_auth")

def require_management_key(x_management_key: str = Header(default=None), request: Request = None):
    """
    Dependency to require authentication for sensitive management endpoints.
    Uses constant-time comparison via hmac.compare_digest.
    """
    key_to_check = settings.MANAGEMENT_API_KEY
    
    if not x_management_key or not hmac.compare_digest(
        x_management_key.encode("utf-8"),
        key_to_check.encode("utf-8")
    ):
        ip_addr = request.client.host if request and request.client else "unknown"
        logger.warning(f"Unauthorized access attempt to management API from {ip_addr}")
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid or missing X-Management-Key header.")
    
    return True
