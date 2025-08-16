import hmac
import hashlib
import time
import structlog
from typing import Optional
from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from ..config import settings

logger = structlog.get_logger()


class HMACAuthenticationMiddleware(BaseHTTPMiddleware):
    """
    HMAC-SHA256 authentication middleware for FastAPI.
    
    Validates requests using HMAC signature in X-Signature header
    and timestamp in X-Timestamp header.
    
    Message format: timestamp + method + path + body
    """
    
    def __init__(self, app, secret_key: str = None, enabled: bool = True):
        super().__init__(app)
        self.secret_key = secret_key or settings.HMAC_SECRET_KEY
        self.enabled = enabled and settings.HMAC_ENABLED
        self.timestamp_tolerance = settings.HMAC_TIMESTAMP_TOLERANCE_SECONDS
        
    async def dispatch(self, request: Request, call_next):
        # Skip HMAC validation if disabled or for health check endpoints
        if not self.enabled or request.url.path in ["/health", "/docs", "/openapi.json"]:
            return await call_next(request)
            
        try:
            # Validate HMAC signature
            await self._validate_hmac_signature(request)
            
            # Process the request
            response = await call_next(request)
            return response
            
        except HTTPException as e:
            logger.warning(
                "hmac_validation_failed",
                method=request.method,
                path=request.url.path,
                error=e.detail
            )
            # Return proper JSON response instead of re-raising
            from starlette.responses import JSONResponse
            return JSONResponse(
                status_code=e.status_code,
                content={"detail": e.detail}
            )
        except Exception as e:
            logger.error(
                "hmac_middleware_error",
                method=request.method,
                path=request.url.path,
                error=str(e)
            )
            raise HTTPException(
                status_code=500,
                detail="Internal authentication error"
            )
    
    async def _validate_hmac_signature(self, request: Request):
        """Validate the HMAC signature of the request."""
        
        # Get required headers
        received_signature = request.headers.get("X-Signature")
        received_timestamp = request.headers.get("X-Timestamp")
        
        if not received_signature:
            raise HTTPException(
                status_code=401,
                detail="Missing X-Signature header"
            )
            
        if not received_timestamp:
            raise HTTPException(
                status_code=401,
                detail="Missing X-Timestamp header"
            )
        
        # Validate timestamp
        try:
            timestamp = int(received_timestamp)
            current_time = int(time.time())
            
            if abs(current_time - timestamp) > self.timestamp_tolerance:
                raise HTTPException(
                    status_code=401,
                    detail="Request timestamp is too old or too far in the future"
                )
        except ValueError:
            raise HTTPException(
                status_code=401,
                detail="Invalid timestamp format"
            )
        
        # For multipart form data (file uploads), we use empty body for signature
        # This is because multipart boundaries are unpredictable and the client
        # should use empty string for body when signing file upload requests
        content_type = request.headers.get('content-type', '')
        if content_type.startswith('multipart/form-data'):
            body_str = ""
        else:
            # Read request body for other content types
            body = await request.body()
            body_str = body.decode('utf-8', errors='ignore')
        
        # Recreate the message that should have been signed
        # Format: timestamp + method + path + body
        message = received_timestamp + request.method + str(request.url.path) + body_str
        
        # Calculate expected signature
        expected_signature = hmac.new(
            self.secret_key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Compare signatures using secure comparison
        if not hmac.compare_digest(received_signature, expected_signature):
            logger.warning(
                "hmac_signature_mismatch",
                method=request.method,
                path=request.url.path,
                expected_signature=expected_signature[:8] + "...",  # Log partial signature for debugging
                received_signature=received_signature[:8] + "..." if received_signature else None
            )
            raise HTTPException(
                status_code=401,
                detail="Invalid signature"
            )
        
        logger.info(
            "hmac_validation_success",
            method=request.method,
            path=request.url.path
        )


def create_hmac_message(timestamp: str, method: str, path: str, body: str) -> str:
    """
    Create the message string that should be signed.
    
    Args:
        timestamp: Unix timestamp as string
        method: HTTP method (GET, POST, etc.)
        path: Request path
        body: Request body
        
    Returns:
        str: The message string to be signed
    """
    return timestamp + method + path + body


def generate_hmac_signature(secret_key: str, message: str) -> str:
    """
    Generate HMAC-SHA256 signature for a message.
    
    Args:
        secret_key: The secret key for HMAC
        message: The message to sign
        
    Returns:
        str: The hexadecimal HMAC signature
    """
    return hmac.new(
        secret_key.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
