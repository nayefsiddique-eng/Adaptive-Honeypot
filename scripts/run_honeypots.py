"""
Multi-Service Honeypot Runner for PRAETOR/MIRAGE.

Launches all genuine honeypot listeners concurrently in a unified async event loop:
1. Real SSH Honeypot (Port 2222) — via asyncssh & FakeFilesystem
2. Real HTTP Web & Admin Panel Decoy (Port 8080) — via aiohttp
3. Real Telnet Router Honeypot (Port 2323) — via asyncio streams & FakeFilesystem

All services report live captured events to the PRAETOR backend at http://127.0.0.1:8000/api/logs/ingest.
"""

import asyncio
import logging
import os
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s"
)
logger = logging.getLogger("honeypot_runner")

# Imports for individual honeypots
try:
    import asyncssh
    from backend.honeypot.ssh_server import HoneypotSSHServer, LISTEN_PORT as SSH_PORT, HOST_KEY_PATH
    from backend.honeypot.http_decoy import handle_request as http_handler, LISTEN_PORT as HTTP_PORT
    from backend.honeypot.telnet_server import handle_telnet_client, LISTEN_PORT as TELNET_PORT
    from aiohttp import web
except ImportError as e:
    logger.error(f"Failed to import honeypot modules: {e}")
    sys.exit(1)


async def start_ssh_service():
    """Start SSH honeypot listener on port 2222."""
    if not os.path.exists(HOST_KEY_PATH):
        logger.info(f"Generating SSH host key at {HOST_KEY_PATH}...")
        key = asyncssh.generate_private_key("ssh-rsa")
        key.write_private_key(HOST_KEY_PATH)

    logger.info(f"[+] Starting SSH Honeypot Service on port {SSH_PORT}...")
    await asyncssh.create_server(
        HoneypotSSHServer,
        "0.0.0.0",
        SSH_PORT,
        server_host_keys=[HOST_KEY_PATH]
    )


async def start_http_service():
    """Start HTTP Decoy listener on port 8080."""
    logger.info(f"[+] Starting HTTP Decoy Service on port {HTTP_PORT}...")
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", http_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", HTTP_PORT)
    await site.start()


async def start_telnet_service():
    """Start Telnet honeypot listener on port 2323."""
    logger.info(f"[+] Starting Telnet Honeypot Service on port {TELNET_PORT}...")
    server = await asyncio.start_server(handle_telnet_client, "0.0.0.0", TELNET_PORT)
    await server.start_serving()


async def main():
    logger.info("=====================================================")
    logger.info("  PRAETOR / MIRAGE Multi-Service Honeypot Platform   ")
    logger.info("=====================================================")
    
    await start_ssh_service()
    await start_http_service()
    await start_telnet_service()

    logger.info("[*] All honeypot services active. Listening for intruder interactions...")
    
    # Run forever
    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("[*] Multi-Service Honeypot Manager shutting down cleanly.")
