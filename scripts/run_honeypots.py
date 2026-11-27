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
import signal
import sys
from contextlib import AsyncExitStack

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s"
)
logger = logging.getLogger("honeypot_runner")

# Imports for individual honeypots
try:
    from backend.honeypot.ssh_server import start_server as start_ssh_service
    from backend.honeypot.http_decoy import handle_request as http_handler, LISTEN_PORT as HTTP_PORT
    from backend.honeypot.telnet_server import handle_telnet_client, LISTEN_PORT as TELNET_PORT
    from aiohttp import web
except ImportError as e:
    logger.error(f"Failed to import honeypot modules: {e}")
    sys.exit(1)


async def main():
    bind_host = os.environ.get("HONEYPOT_BIND_HOST", "127.0.0.1")
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    registered = []
    for signum in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(signum, stopped.set)
            registered.append(signum)
        except NotImplementedError:
            pass

    async def close_server(server):
        server.close()
        await server.wait_closed()

    try:
        async with AsyncExitStack() as stack:
            ssh = await start_ssh_service(bind_host)
            stack.push_async_callback(close_server, ssh)

            app = web.Application()
            app.router.add_route("*", "/{tail:.*}", http_handler)
            runner = web.AppRunner(app)
            await runner.setup()
            stack.push_async_callback(runner.cleanup)
            await web.TCPSite(runner, bind_host, HTTP_PORT).start()

            telnet = await asyncio.start_server(handle_telnet_client, bind_host, TELNET_PORT)
            stack.push_async_callback(close_server, telnet)
            logger.info("SSH, HTTP and Telnet listeners started on %s", bind_host)
            await stopped.wait()
    finally:
        for signum in registered:
            loop.remove_signal_handler(signum)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("[*] Multi-Service Honeypot Manager shutting down cleanly.")
