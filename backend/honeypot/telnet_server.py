"""
Real Telnet Honeypot for PRAETOR/MIRAGE (Phase 3).

This is a genuine asyncio-stream Telnet server listening on port 2323 (or HONEYPOT_TELNET_PORT).
It simulates a classic BusyBox/embedded Linux router shell:
- Displays Telnet login prompts and handles authentication
- Authenticates weak/default credentials (root:root, admin:admin, telecom:telecom)
- Interactively wires inputs to FakeFilesystem (sharing the same shell/file decoy engine as SSH)
- Reports all login retries and commands to the PRAETOR backend API at /api/logs/ingest
"""

import asyncio
import logging
import os
from datetime import datetime, timezone
import httpx

from backend.honeypot.fake_filesystem import FakeFilesystem, HOSTNAME
from backend.honeypot.ssh_server import dispatch_command, WEAK_CREDENTIALS

logger = logging.getLogger("telnet_honeypot")
logging.basicConfig(level=logging.INFO)

LISTEN_PORT = int(os.environ.get("HONEYPOT_TELNET_PORT", 2323))
BACKEND_INGEST_URL = os.environ.get("BACKEND_INGEST_URL", "http://127.0.0.1:8000/api/logs/ingest")

_http_client: httpx.AsyncClient | None = None


async def get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(timeout=3.0)
    return _http_client


async def report_event(ip: str, port: int, payload: str, metadata: dict):
    """Send captured Telnet event to PRAETOR ingestion pipeline."""
    try:
        client = await get_http_client()
        await client.post(BACKEND_INGEST_URL, json={
            "ip_address": ip,
            "port": port,
            "protocol": "telnet",
            "payload": payload,
            "metadata": metadata,
        })
    except Exception as e:
        logger.warning(f"Failed to report Telnet event to backend ({BACKEND_INGEST_URL}): {e}")


async def handle_telnet_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    client_ip = peer[0] if peer else "127.0.0.1"
    client_port = peer[1] if peer else 0

    logger.info(f"[+] Telnet connection from {client_ip}:{client_port}")
    fs = FakeFilesystem()
    login_attempts = 0

    try:
        writer.write(b"\r\nBusyBox v1.31.1 (Ubuntu 1:1.31.1-4ubuntu1) built-in shell (ash)\r\n")
        writer.write(f"{HOSTNAME} login: ".encode("utf-8"))
        await writer.drain()

        username = ""
        password = ""

        # Login authentication loop
        while login_attempts < 3:
            user_line = await reader.readline()
            if not user_line:
                writer.close()
                return
            username = user_line.decode("utf-8", errors="ignore").strip()

            writer.write(b"Password: ")
            await writer.drain()

            pass_line = await reader.readline()
            if not pass_line:
                writer.close()
                return
            password = pass_line.decode("utf-8", errors="ignore").strip()

            login_attempts += 1
            accepted = (username, password) in WEAK_CREDENTIALS or (username == "admin" and password == "admin")

            asyncio.create_task(report_event(
                client_ip, LISTEN_PORT,
                f"{username}:{password}",
                {
                    "event": "login_attempt",
                    "accepted": accepted,
                    "attempt_number": login_attempts,
                    "username": username,
                }
            ))

            if accepted:
                writer.write(b"\r\nAccess granted.\r\n\r\n")
                await writer.drain()
                break
            else:
                writer.write(b"\r\nLogin incorrect\r\n")
                writer.write(f"{HOSTNAME} login: ".encode("utf-8"))
                await writer.drain()

        if login_attempts >= 3 and not ((username, password) in WEAK_CREDENTIALS or (username == "admin" and password == "admin")):
            writer.write(b"\r\nToo many login failures.\r\n")
            await writer.drain()
            writer.close()
            return

        # Shell command execution loop
        while True:
            prompt = f"root@{HOSTNAME}:{fs.pwd()}# "
            writer.write(prompt.encode("utf-8"))
            await writer.drain()

            cmd_line_bytes = await reader.readline()
            if not cmd_line_bytes:
                break

            cmd_line = cmd_line_bytes.decode("utf-8", errors="ignore").strip()
            if not cmd_line:
                continue

            asyncio.create_task(report_event(
                client_ip, LISTEN_PORT, cmd_line,
                {"event": "command", "username": username}
            ))

            output = dispatch_command(fs, cmd_line)
            if output is None:
                writer.write(b"logout\r\n")
                await writer.drain()
                break

            if output:
                writer.write((output.replace("\n", "\r\n") + "\r\n").encode("utf-8"))
                await writer.drain()

    except Exception as e:
        logger.warning(f"Error handling Telnet client {client_ip}: {e}")
    finally:
        logger.info(f"[-] Telnet session closed: {client_ip}")
        writer.close()
        await writer.wait_closed()


async def main():
    server = await asyncio.start_server(handle_telnet_client, "0.0.0.0", LISTEN_PORT)
    logger.info(f"[*] Starting Real Telnet Honeypot on port {LISTEN_PORT}...")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("[*] Telnet Honeypot stopped.")
