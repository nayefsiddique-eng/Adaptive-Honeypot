"""Validate PRAETOR listeners with harmless loopback traffic and disposable state."""
import asyncio
import os
from pathlib import Path
from secrets import token_urlsafe
import socket
import subprocess
import sys
import tempfile
import time

import asyncssh
import httpx


def unused_port():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        return server.getsockname()[1]


async def ssh_session(port):
    async with asyncssh.connect("127.0.0.1", port=port, username="admin",
                                password="admin", known_hosts=None) as connection:
        process = await connection.create_process(term_type="xterm")
        await asyncio.wait_for(process.stdout.readuntil("# "), timeout=5)
        process.stdin.write("pwd\nexit\n")
        await asyncio.wait_for(process.wait_closed(), timeout=5)
        return connection.get_server_host_key().get_fingerprint()


async def telnet_session(port):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await asyncio.wait_for(reader.readuntil(b"login: "), timeout=5)
        writer.write(b"admin\n")
        await writer.drain()
        await asyncio.wait_for(reader.readuntil(b"Password: "), timeout=5)
        writer.write(b"admin\n")
        await writer.drain()
        await asyncio.wait_for(reader.readuntil(b"Access granted."), timeout=5)
        writer.write(b"pwd\nexit\n")
        await writer.drain()
        assert b"logout" in await asyncio.wait_for(reader.read(), timeout=5)
    finally:
        writer.close()
        await writer.wait_closed()


def main():
    root = Path(__file__).resolve().parents[1]
    ssh, telnet, http, management = [unused_port() for _ in range(4)]
    base = f"http://127.0.0.1:{management}"
    with tempfile.TemporaryDirectory(prefix="praetor-loopback-") as folder:
        scratch = Path(folder)
        key = scratch / "host-key"
        asyncssh.generate_private_key("ssh-ed25519").write_private_key(key)
        key.chmod(0o600)
        headers = {"X-Management-Key": token_urlsafe(32)}
        env = dict(os.environ, ENVIRONMENT="development", DATABASE_URL=f"sqlite:///{scratch/'events.db'}",
                   LOG_DIR=str(scratch/"logs"), MANAGEMENT_API_KEY=headers["X-Management-Key"],
                   SSH_HOST_KEY_PATH=str(key), HONEYPOT_BIND_HOST="127.0.0.1",
                   HONEYPOT_SSH_PORT=str(ssh), HONEYPOT_TELNET_PORT=str(telnet),
                   HONEYPOT_HTTP_PORT=str(http), BACKEND_INGEST_URL=f"{base}/api/logs/ingest",
                   GEMINI_API_KEY="", OTX_API_KEY="", ABUSEIPDB_API_KEY="")
        with httpx.Client(timeout=4, trust_env=False) as client:
            def wait_http(url):
                for _ in range(45):
                    try:
                        return client.get(url).raise_for_status()
                    except (httpx.RequestError, httpx.HTTPStatusError):
                        time.sleep(0.2)
                raise AssertionError(f"Local endpoint unavailable: {url}")

            def stop(proc):
                proc.terminate()
                return proc.wait(timeout=15)

            def management_app(log):
                return subprocess.Popen([sys.executable, "-m", "uvicorn", "backend.main:app",
                                         "--host", "127.0.0.1", "--port", str(management)],
                                        cwd=root, env=env, stdout=log, stderr=log)
            with (scratch/"runtime.log").open("w+") as log:
                api = management_app(log)
                decoy = None
                try:
                    wait_http(base+"/health")
                    assert client.get(base+"/api/logs/recent").status_code == 401
                    dashboard = client.get(base+"/", headers={"Accept": "text/html"})
                    assert dashboard.status_code == 200 and "PRAETOR" in dashboard.text
                    for _ in range(2):
                        decoy = subprocess.Popen([sys.executable, "-m", "scripts.run_honeypots"],
                                                 cwd=root, env=env, stdout=log, stderr=log)
                        wait_http(f"http://127.0.0.1:{http}/")

                        async def exercise():
                            fingerprints = await asyncio.gather(ssh_session(ssh), ssh_session(ssh),
                                                                telnet_session(telnet))
                            assert fingerprints[0] == fingerprints[1]
                            return fingerprints[0]
                        fingerprint = asyncio.run(exercise())
                        assert fingerprint == asyncssh.read_private_key(key).get_fingerprint()
                        assert stop(decoy) == 0
                        decoy = None

                    def records():
                        return client.get(base+"/api/logs/recent", headers=headers).raise_for_status().json()

                    before = records()
                    assert {"SSH", "TELNET", "HTTP"} <= {row["protocol"].upper() for row in before}
                    stop(api)
                    api = management_app(log)
                    wait_http(base+"/health")
                    assert len(records()) == len(before)
                    print("Loopback SSH/HTTP/Telnet, parallel connections, stable key, management auth, dashboard and persisted telemetry passed.")
                except Exception:
                    log.seek(0)
                    # Logs contain disposable inputs only. Avoid printing them from the reproduction script.
                    print(f"Loopback process check failed. Listener return code: {decoy.poll() if decoy else 'stopped'}.")
                    raise
                finally:
                    if decoy is not None:
                        stop(decoy)
                    stop(api)


if __name__ == "__main__":
    main()
