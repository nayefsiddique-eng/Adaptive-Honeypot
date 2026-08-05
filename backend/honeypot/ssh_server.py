"""
Real SSH honeypot for PRAETOR/MIRAGE.

This is a genuine asyncssh server - it performs a real SSH handshake with
whoever connects (bots, scanners, manual attackers) and speaks the protocol
correctly. There is no "simulation" here: if you point a real ssh client or
a real botnet at this port, this code is what answers.

Every login attempt (success or failure) and every shell command is
reported to the existing FastAPI pipeline at /api/logs/ingest, which runs
it through the real ML classifier, MITRE mapping, GeoIP, threat-intel
lookups, and the RL adaptive engine - the same pipeline the dashboard
already reads from. This file replaces demo_engine.py as the *source* of
that data; the pipeline itself is untouched.
"""

import asyncio
import logging
import os
from datetime import datetime, timezone

import asyncssh
import httpx

from backend.honeypot.fake_filesystem import FakeFilesystem, HOSTNAME

logger = logging.getLogger("ssh_honeypot")
logging.basicConfig(level=logging.INFO)

# --- Configuration -----------------------------------------------------
LISTEN_PORT = int(os.environ.get("HONEYPOT_SSH_PORT", 2222))
HOST_KEY_PATH = os.path.join(os.path.dirname(__file__), "ssh_host_key")
BACKEND_INGEST_URL = os.environ.get("BACKEND_INGEST_URL", "http://127.0.0.1:8000/api/logs/ingest")

# Credentials that are allowed to "succeed" - mirrors real-world default/
# weak creds attackers actually try. Everything else is logged and
# rejected, same as Cowrie's default userdb behavior. Curate this list
# freely; it's your deception surface.
WEAK_CREDENTIALS = {
    ("root", "root"), ("root", "toor"), ("root", "123456"), ("root", "password"),
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("deploy", "deploy"), ("ubuntu", "ubuntu"), ("test", "test"),
    ("user", "user"), ("guest", "guest"),
}

_http_client: httpx.AsyncClient | None = None


async def get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(timeout=3.0)
    return _http_client


async def report_event(ip: str, port: int, payload: str, metadata: dict):
    """Send a real captured event into the existing detection pipeline.
    Failures here must never crash the honeypot session - if the backend
    API is briefly down, the attacker's connection should still work
    normally so the deception holds."""
    try:
        client = await get_http_client()
        await client.post(BACKEND_INGEST_URL, json={
            "ip_address": ip,
            "port": port,
            "protocol": "ssh",
            "payload": payload,
            "metadata": metadata,
        })
    except Exception as e:
        logger.warning(f"Failed to report event to backend ({BACKEND_INGEST_URL}): {e}")


class HoneypotSSHServer(asyncssh.SSHServer):
    def connection_made(self, conn: asyncssh.SSHServerConnection):
        self.conn = conn
        peer = conn.get_extra_info("peername")
        self.peer_ip = peer[0] if peer else "unknown"
        self.peer_port = peer[1] if peer else 0
        self.attempt_count = 0
        logger.info(f"[+] Incoming SSH connection from {self.peer_ip}:{self.peer_port}")

    def connection_lost(self, exc):
        logger.info(f"[-] Connection closed: {self.peer_ip}")

    def begin_auth(self, username: str) -> bool:
        self.username = username
        return True  # True = auth is required (password prompt shown)

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        self.attempt_count += 1
        accepted = (username, password) in WEAK_CREDENTIALS

        asyncio.create_task(report_event(
            self.peer_ip, LISTEN_PORT,
            f"{username}:{password}",
            {
                "event": "login_attempt",
                "accepted": accepted,
                "attempt_number": self.attempt_count,
            },
        ))

        logger.info(f"[AUTH] {self.peer_ip} tried {username}:{password} -> {'ACCEPTED' if accepted else 'rejected'}")
        return accepted


COMMAND_HELP_ECHO = {
    "whoami": lambda fs: "root",
    "id": lambda fs: "uid=0(root) gid=0(root) groups=0(root)",
    "uname -a": lambda fs: f"Linux {HOSTNAME} 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
    "uname": lambda fs: "Linux",
    "hostname": lambda fs: HOSTNAME,
    "uptime": lambda fs: " 14:23:07 up 62 days,  3:41,  1 user,  load average: 0.08, 0.05, 0.01",
    "ps": lambda fs: "  PID TTY          TIME CMD\n    1 ?        00:00:03 systemd\n  842 ?        00:00:00 sshd\n 1911 pts/0    00:00:00 bash",
    "ps aux": lambda fs: (
        "USER       PID %CPU %MEM COMMAND\n"
        "root         1  0.0  0.1 /sbin/init\n"
        "root       842  0.0  0.2 /usr/sbin/sshd -D\n"
        "www-data  1203  0.1  1.4 nginx: worker process\n"
    ),
    "ifconfig": lambda fs: "eth0: flags=4163  inet 10.0.0.14  netmask 255.255.255.0  broadcast 10.0.0.255",
    "ip a": lambda fs: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> inet 10.0.0.14/24 scope global eth0",
    "history": lambda fs: "",
    "clear": lambda fs: "\x1b[H\x1b[2J",
}


def dispatch_command(fs: FakeFilesystem, line: str) -> str | None:
    """Return output text, or None to signal session close (exit/logout)."""
    line = line.strip()
    if not line:
        return ""
    parts = line.split()
    cmd = parts[0]
    args = parts[1:]

    if cmd in ("exit", "logout", "quit"):
        return None

    if line in COMMAND_HELP_ECHO:
        return COMMAND_HELP_ECHO[line](fs)
    if cmd in COMMAND_HELP_ECHO and not args:
        return COMMAND_HELP_ECHO[cmd](fs)

    if cmd == "pwd":
        return fs.pwd()
    if cmd == "cd":
        return fs.cd(args[0] if args else "")
    if cmd == "ls":
        show_all = any(a in ("-a", "-la", "-al", "-al") for a in args)
        path_args = [a for a in args if not a.startswith("-")]
        return fs.ls(path_args[0] if path_args else "", show_all=show_all)
    if cmd == "cat":
        if not args:
            return "cat: missing operand"
        return fs.cat(args[0])
    if cmd in ("wget", "curl"):
        url = args[-1] if args else ""
        # This is the payload-delivery moment real botnets use to drop
        # malware. We record the exact URL, "succeed" the download, but
        # never actually fetch anything - the honeypot must never make
        # outbound requests to attacker infrastructure.
        return f"Saving to: 'download'\n{url} ... 100% downloaded"
    if cmd == "sudo":
        return f"{fs.pwd()}: sudo: effective uid is not 0, is /usr/bin/sudo on a file system with the 'nosuid' option set?"
    if cmd == "echo":
        return " ".join(args)

    return f"-bash: {cmd}: command not found"


async def handle_session(process: asyncssh.SSHServerProcess):
    peer = process.get_extra_info("peername")
    ip = peer[0] if peer else "unknown"
    username = process.get_extra_info("username") or "unknown"
    fs = FakeFilesystem()

    process.stdout.write(f"Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n")
    process.stdout.write(f"Last login: {datetime.now(timezone.utc).strftime('%a %b %d %H:%M:%S %Y')} from {ip}\r\n")

    try:
        while True:
            prompt = f"root@{HOSTNAME}:{fs.pwd()}# "
            process.stdout.write(prompt)
            line = await process.stdin.readline()
            if not line:
                break
            line = line.rstrip("\r\n")

            # Report the raw command to the same pipeline used for login
            # attempts - this is what feeds attack_type classification
            # (command_injection, malware_delivery, etc.) with real input.
            asyncio.create_task(report_event(
                ip, LISTEN_PORT, line,
                {"event": "command", "username": username},
            ))

            output = dispatch_command(fs, line)
            if output is None:
                process.stdout.write("logout\r\n")
                break
            if output:
                process.stdout.write(output + "\r\n")
    except asyncssh.BreakReceived:
        pass
    except Exception as e:
        logger.warning(f"Session error for {ip}: {e}")
    finally:
        process.exit(0)


async def start_server():
    if not os.path.exists(HOST_KEY_PATH):
        raise FileNotFoundError(
            f"Host key not found at {HOST_KEY_PATH}. Generate it first (see Step 2)."
        )

    await asyncssh.create_server(
        HoneypotSSHServer,
        host="",
        port=LISTEN_PORT,
        server_host_keys=[HOST_KEY_PATH],
        process_factory=handle_session,
        server_version="SSH-2.0-OpenSSH_8.9p1",  # matches a real Ubuntu 22.04 banner
    )
    logger.info(f"PRAETOR SSH honeypot listening on 0.0.0.0:{LISTEN_PORT}")


def main():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(start_server())
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()