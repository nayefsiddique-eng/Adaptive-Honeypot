import time
import logging
from collections import defaultdict
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from backend.config import settings

logger = logging.getLogger("security_middleware")

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        
        # Apply security headers to API and general management/dashboard responses
        # Avoid breaking the external HTTP decoy since it runs on a different port/service
        path = request.url.path
        if path.startswith("/api") or path in ("/", "/index.html"):
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Referrer-Policy"] = "no-referrer"
            if path.startswith("/api"):
                response.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
        return response

class ContentSizeLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Enforce maximum body size limits
        if request.method == "POST":
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    if int(content_length) > settings.MAX_REQUEST_BODY_BYTES:
                        logger.warning(f"Rejected payload exceeding size limit from {request.client.host if request.client else 'unknown'}")
                        return JSONResponse(
                            status_code=413,
                            content={"error": "Request entity too large"}
                        )
                except ValueError:
                    return JSONResponse(
                        status_code=400,
                        content={"error": "Invalid Content-Length header"}
                    )
        return await call_next(request)

class InMemoryRateLimiterMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        # Store requests as: ip -> list of timestamps
        self.history = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        ip = request.client.host if request.client else "127.0.0.1"
        now = time.time()
        
        # Clean history for this IP
        window_start = now - settings.API_RATE_WINDOW_SECONDS
        self.history[ip] = [t for t in self.history[ip] if t > window_start]
        
        # Check rate limits for management endpoints only
        if request.url.path.startswith("/api") and not request.url.path.endswith("/logs/ingest"):
            if len(self.history[ip]) >= settings.API_RATE_LIMIT:
                logger.warning(f"Rate limit exceeded for IP {ip} on path {request.url.path}")
                return JSONResponse(
                    status_code=429,
                    content={"error": "Too many requests. Please try again later."}
                )
            self.history[ip].append(now)

        return await call_next(request)
