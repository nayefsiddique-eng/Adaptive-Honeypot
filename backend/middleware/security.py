import time
import logging
from collections import deque
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.datastructures import Headers
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

class ContentSizeLimitMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] != "POST":
            await self.app(scope, receive, send)
            return

        limit = settings.MAX_REQUEST_BODY_BYTES
        too_large = JSONResponse({"error": "Request entity too large"}, status_code=413)
        declared_length = Headers(scope=scope).get("content-length")
        if declared_length is not None:
            try:
                size = int(declared_length)
                if size < 0:
                    raise ValueError("Negative body size")
            except ValueError:
                response = JSONResponse({"error": "Invalid Content-Length header"}, status_code=400)
                await response(scope, receive, send)
                return
            if size > limit:
                await too_large(scope, receive, send)
                return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > limit:
                await too_large(scope, receive, send)
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break

        first_message = {"type": "http.request", "body": bytes(body), "more_body": False}
        del body

        async def replay_receive():
            nonlocal first_message
            if first_message is not None:
                message, first_message = first_message, None
                return message
            return await receive()

        await self.app(scope, replay_receive, send)


class InMemoryRateLimiterMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.history: dict[str, deque[float]] = {}
        self.next_cleanup = 0.0

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if not path.startswith("/api") or path.endswith("/logs/ingest"):
            return await call_next(request)

        ip = request.client.host if request.client else "127.0.0.1"
        now = time.monotonic()
        window = settings.API_RATE_WINDOW_SECONDS
        window_start = now - window
        if now >= self.next_cleanup:
            self.history = {
                source: timestamps
                for source, timestamps in self.history.items()
                if timestamps and timestamps[-1] > window_start
            }
            self.next_cleanup = now + window

        timestamps = self.history.setdefault(ip, deque())
        while timestamps and timestamps[0] <= window_start:
            timestamps.popleft()
        if len(timestamps) >= settings.API_RATE_LIMIT:
            logger.warning("Rate limit exceeded for IP %s on path %s", ip, path)
            return JSONResponse(
                status_code=429,
                content={"error": "Too many requests. Please try again later."},
            )

        timestamps.append(now)
        return await call_next(request)
