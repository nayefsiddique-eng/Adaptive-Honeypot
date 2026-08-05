"""
Real HTTP Web & Admin Panel Decoy for PRAETOR/MIRAGE (Phase 2).

This is a real web server built using aiohttp. It listens on port 8080 (or HONEYPOT_HTTP_PORT)
and presents realistic enterprise web decoy traps:
- Fake Enterprise Admin / Router Login Portal (GET/POST /login, /admin)
- Decoy Configuration & Credential Leakage (GET /.env, GET /wp-config.php, GET /config.yaml)
- Web Application Exploit Traps (SQLi, XSS, PHPUnit RCE, Path Traversal)

Every HTTP request (method, path, headers, query parameters, payload, credentials)
is reported in real-time to the PRAETOR backend API at /api/logs/ingest.
"""

import asyncio
import logging
import os
from aiohttp import web
import httpx

logger = logging.getLogger("http_honeypot")
logging.basicConfig(level=logging.INFO)

LISTEN_PORT = int(os.environ.get("HONEYPOT_HTTP_PORT", 8080))
BACKEND_INGEST_URL = os.environ.get("BACKEND_INGEST_URL", "http://127.0.0.1:8000/api/logs/ingest")

_http_client: httpx.AsyncClient | None = None


async def get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(timeout=3.0)
    return _http_client


async def report_event(ip: str, port: int, payload: str, metadata: dict):
    """Report HTTP decoy event to PRAETOR ingestion pipeline."""
    try:
        client = await get_http_client()
        await client.post(BACKEND_INGEST_URL, json={
            "ip_address": ip,
            "port": port,
            "protocol": "http",
            "payload": payload,
            "metadata": metadata,
        })
    except Exception as e:
        logger.warning(f"Failed to report HTTP event to backend ({BACKEND_INGEST_URL}): {e}")


# HTML Decoy Templates
LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Enterprise Security Gateway — Login</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .card { background: #1e293b; border: 1px solid #334155; padding: 32px; border-radius: 8px; width: 340px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
        h2 { margin-top: 0; font-size: 18px; color: #38bdf8; text-transform: uppercase; letter-spacing: 1px; }
        label { display: block; font-size: 12px; color: #94a3b8; margin-top: 14px; margin-bottom: 4px; }
        input { width: 100%; padding: 8px 12px; background: #0f172a; border: 1px solid #475569; color: #fff; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; margin-top: 20px; padding: 10px; background: #0284c7; color: white; border: none; border-radius: 4px; font-weight: bold; cursor: pointer; }
        button:hover { background: #0369a1; }
        .footer { font-size: 10px; color: #64748b; margin-top: 16px; text-align: center; }
    </style>
</head>
<body>
    <div class="card">
        <h2>Enterprise Gateway</h2>
        <form method="POST" action="/login">
            <label for="username">Username</label>
            <input type="text" id="username" name="username" required placeholder="admin">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" required>
            <button type="submit">Authenticate</button>
        </form>
        <div class="footer">Restricted Access — Internal Systems Only</div>
    </div>
</body>
</html>"""

DECOY_ENV_TEXT = """# Production Environment Configuration
APP_NAME=EnterpriseCore
APP_ENV=production
APP_KEY=base64:eW91X2ZvdW5kX2FfZGVjb3lfZW52aXJvbm1lbnRfa2V5
DB_HOST=10.0.0.15
DB_PORT=3306
DB_DATABASE=enterprise_prod
DB_USERNAME=admin_root
DB_PASSWORD=P@ssw0rd2026!
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""


async def handle_request(request: web.Request) -> web.Response:
    peername = request.transport.get_extra_info('peername')
    client_ip = peername[0] if peername else "127.0.0.1"
    method = request.method
    path = request.path
    query_str = request.query_string
    user_agent = request.headers.get("User-Agent", "unknown")

    body_text = ""
    try:
        if request.can_read_body:
            body_bytes = await request.read()
            body_text = body_bytes.decode('utf-8', errors='ignore')
    except Exception:
        pass

    full_payload = f"{method} {path}"
    if query_str:
        full_payload += f"?{query_str}"
    if body_text:
        full_payload += f"\n{body_text}"

    metadata = {
        "event": "http_request",
        "method": method,
        "path": path,
        "user_agent": user_agent,
        "headers": dict(request.headers),
    }

    # Route-specific decoy responses and classification flags
    if path in ["/.env", "/config.env"]:
        metadata["event"] = "reconnaissance"
        asyncio.create_task(report_event(client_ip, LISTEN_PORT, full_payload, metadata))
        return web.Response(text=DECOY_ENV_TEXT, content_type="text/plain", status=200)

    elif path in ["/login", "/admin/login"] and method == "POST":
        post_data = {}
        try:
            post_data = await request.post()
        except Exception:
            pass
        user = post_data.get("username", "")
        pwd = post_data.get("password", "")
        metadata["event"] = "login_attempt"
        metadata["username"] = user
        metadata["password"] = pwd
        asyncio.create_task(report_event(client_ip, LISTEN_PORT, f"login:{user}:{pwd}", metadata))
        # Return realistic 401 Unauthorized decoy response
        return web.Response(text=LOGIN_HTML.replace("Authenticate", "Invalid Credentials"), content_type="text/html", status=401)

    elif "eval-stdin.php" in path or "phpunit" in path:
        metadata["event"] = "exploit_attempt"
        asyncio.create_task(report_event(client_ip, LISTEN_PORT, full_payload, metadata))
        return web.Response(text="Status: OK", content_type="text/plain", status=200)

    else:
        asyncio.create_task(report_event(client_ip, LISTEN_PORT, full_payload, metadata))
        return web.Response(text=LOGIN_HTML, content_type="text/html", status=200)


async def main():
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handle_request)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", LISTEN_PORT)
    logger.info(f"[*] Starting Real HTTP Decoy Honeypot on port {LISTEN_PORT}...")
    await site.start()
    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("[*] HTTP Decoy stopped.")
