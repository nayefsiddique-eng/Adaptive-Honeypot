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

# asyncssh and httpx are optional at import time so that tests can import
# dispatch_command (a pure function) without requiring these heavy packages.
try:
    import asyncssh
    _HAS_ASYNCSSH = True
except ImportError:
    _HAS_ASYNCSSH = False

try:
    import httpx
    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False

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

_http_client = None


async def get_http_client():
    global _http_client
    if _http_client is None:
        import httpx
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


# The SSH server class is only defined when asyncssh is available.
# Tests that only import dispatch_command will skip this block.
if _HAS_ASYNCSSH:
    class HoneypotSSHServer(asyncssh.SSHServer):
        def connection_made(self, conn):
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
    "uname -r": lambda fs: "5.15.0-91-generic",
    "uname": lambda fs: "Linux",
    "hostname": lambda fs: HOSTNAME,
    "hostnamectl": lambda fs: (
        f" Static hostname: {HOSTNAME}\n"
        "       Icon name: computer-vm\n"
        "         Chassis: vm\n"
        "      Machine ID: d8a9e2f41b2c4d5e6f7a8b9c0d1e2f3a\n"
        "       Boot ID: 3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d\n"
        "Virtualization: kvm\n"
        "Operating System: Ubuntu 22.04.4 LTS\n"
        "          Kernel: Linux 5.15.0-91-generic\n"
        "    Architecture: x86-64"
    ),
    "uptime": lambda fs: " 14:23:07 up 62 days,  3:41,  1 user,  load average: 0.08, 0.05, 0.01",
    "date": lambda fs: "Mon Aug 24 14:23:07 UTC 2026",
    "df -h": lambda fs: (
        "Filesystem      Size  Used Avail Use% Mounted on\n"
        "/dev/sda1        40G   14G   25G  36% /\n"
        "tmpfs           1.9G     0  1.9G   0% /dev/shm\n"
        "/dev/sda15      124M   11M  114M   9% /boot/efi"
    ),
    "df": lambda fs: (
        "Filesystem     1K-blocks     Used Available Use% Mounted on\n"
        "/dev/sda1       41251136 14210452  24921444  37% /\n"
        "tmpfs            1987524        0   1987524   0% /dev/shm"
    ),
    "free -h": lambda fs: (
        "               total        used        free      shared  buff/cache   available\n"
        "Mem:           3.8Gi       1.1Gi       1.4Gi        12Mi       1.3Gi       2.4Gi\n"
        "Swap:          2.0Gi          0B       2.0Gi"
    ),
    "free": lambda fs: (
        "               total        used        free      shared  buff/cache   available\n"
        "Mem:         3975048     1153436     1468012       12288     1353600     2514300\n"
        "Swap:        2097148           0     2097148"
    ),
    "ip addr": lambda fs: (
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
        "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
        "    inet 127.0.0.1/8 scope host lo\n"
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n"
        "    link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff\n"
        "    inet 10.0.0.14/24 brd 10.0.0.255 scope global eth0"
    ),
    "ip a": lambda fs: (
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n"
        "    inet 127.0.0.1/8 scope host lo\n"
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\n"
        "    inet 10.0.0.14/24 brd 10.0.0.255 scope global eth0"
    ),
    "ip route": lambda fs: (
        "default via 10.0.0.1 dev eth0 proto dhcp src 10.0.0.14 metric 100\n"
        "10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.14 metric 100"
    ),
    "ss -tulpn": lambda fs: (
        "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n"
        "tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*     users:((\"sshd\",pid=842,fd=3))\n"
        "tcp   LISTEN 0      511          0.0.0.0:80         0.0.0.0:*     users:((\"nginx\",pid=1203,fd=6))"
    ),
    "ss": lambda fs: (
        "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
        "tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*\n"
        "tcp   LISTEN 0      511          0.0.0.0:80         0.0.0.0:*"
    ),
    "ps": lambda fs: "  PID TTY          TIME CMD\n    1 ?        00:00:03 systemd\n  842 ?        00:00:00 sshd\n 1911 pts/0    00:00:00 bash",
    "ps aux": lambda fs: (
        "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
        "root         1  0.0  0.1 168240  9612 ?        Ss   Jun23   0:03 /sbin/init\n"
        "root       842  0.0  0.2  15816  8204 ?        Ss   Jun23   0:00 /usr/sbin/sshd -D\n"
        "www-data  1203  0.1  1.4  55280 14210 ?        S    Jun23   1:12 nginx: worker process\n"
        "root      1911  0.0  0.1  10072  5124 pts/0    Ss+  14:20   0:00 -bash"
    ),
    "env": lambda fs: (
        "SHELL=/bin/bash\n"
        "PWD=" + fs.pwd() + "\n"
        "LOGNAME=root\n"
        "HOME=/root\n"
        "LANG=en_US.UTF-8\n"
        "USER=root\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        "TERM=xterm-256color"
    ),
    "ifconfig": lambda fs: "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.0.14  netmask 255.255.255.0  broadcast 10.0.0.255",
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
    if cmd == "mkdir":
        return fs.mkdir(args[0] if args else "")
    if cmd == "touch":
        return fs.touch(args[0] if args else "")
    if cmd == "chmod":
        if len(args) >= 2:
            return fs.chmod(args[0], args[1])
        return "chmod: missing operand"
    if cmd == "ls":
        show_all = any(a in ("-a", "-la", "-al", "-l") or "a" in a for a in args if a.startswith("-"))
        long_format = any("l" in a for a in args if a.startswith("-"))
        path_args = [a for a in args if not a.startswith("-")]
        return fs.ls(path_args[0] if path_args else "", show_all=show_all, long_format=long_format)
    if cmd == "cat":
        if not args:
            return "cat: missing operand"
        return fs.cat(args[0])
    if cmd in ("wget", "curl"):
        url = args[-1] if args else ""
        filename = url.split("/")[-1] if "/" in url else "download"
        if not filename or filename.startswith("-"):
            filename = "download"
        fs.write_marker(filename, f"# Simulated download content from {url}\n")
        return f"Saving to: '{filename}'\n{url} ... 100% downloaded"
    if cmd == "sudo":
        return f"{fs.pwd()}: sudo: effective uid is not 0, is /usr/bin/sudo on a file system with the 'nosuid' option set?"
    if cmd == "echo":
        return " ".join(args)

    return f"-bash: {cmd}: command not found"


async def handle_session(process):
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
    except (asyncssh.BreakReceived if _HAS_ASYNCSSH else Exception):
        pass
    except Exception as e:
        logger.warning(f"Session error for {ip}: {e}")
    finally:
        process.exit(0)


async def start_server():
    if not _HAS_ASYNCSSH:
        raise ImportError("asyncssh is required to run the SSH honeypot server. Install it with: pip install asyncssh")

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
        session_factory=handle_session,
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