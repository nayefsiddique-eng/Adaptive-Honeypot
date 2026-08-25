"""
Fake Linux filesystem for the PRAETOR SSH honeypot.

This gives a connecting attacker a plausible directory tree to explore
(ls, cd, cat, pwd, find, etc.) instead of blank/error output. It is
intentionally NOT a real filesystem - nothing here touches the host disk.
Every read is served from this in-memory tree, and it's per-session so
one attacker's `rm` or `echo >>` never affects another session or the
real machine.
"""

import copy
from datetime import datetime, UTC

HOSTNAME = "prod-web-03"

# A directory is a dict. A file is a dict with "__content__".
# Keep this realistic but not overloaded - enough that `ls -la` and
# `cat` on common paths gives a believable Ubuntu-server-ish system.
_BASE_TREE = {
    "bin": {}, "sbin": {}, "dev": {}, "proc": {}, "mnt": {}, "media": {}, "opt": {},
    "srv": {}, "tmp": {},
    "etc": {
        "passwd": {"__content__": (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "sshd:x:104:65534::/run/sshd:/usr/sbin/nologin\n"
            "deploy:x:1000:1000:deploy,,,:/home/deploy:/bin/bash\n"
            "ubuntu:x:1001:1001:Ubuntu:/home/ubuntu:/bin/bash\n"
        )},
        "shadow": {"__content__": "-- permission denied --"},
        "hostname": {"__content__": HOSTNAME + "\n"},
        "hosts": {"__content__": "127.0.0.1\tlocalhost\n127.0.1.1\t" + HOSTNAME + "\n"},
        "issue": {"__content__": "Ubuntu 22.04.4 LTS \\n \\l\n\n"},
        "os-release": {"__content__": (
            'NAME="Ubuntu"\nVERSION="22.04.4 LTS (Jammy Jellyfish)"\nID=ubuntu\n'
            'ID_LIKE=debian\nVERSION_ID="22.04"\n'
        )},
        "nginx": {"nginx.conf": {"__content__": "user www-data;\nworker_processes auto;\n..."}},
        "ssh": {"sshd_config": {"__content__": "Port 22\nPermitRootLogin no\nPasswordAuthentication yes\n"}},
        "crontab": {"__content__": ""},
    },
    "var": {
        "log": {
            "auth.log": {"__content__": "-- log rotated, no entries --\n"},
            "syslog": {"__content__": "-- log rotated, no entries --\n"},
            "nginx": {"access.log": {"__content__": ""}, "error.log": {"__content__": ""}},
        },
        "www": {"html": {"index.html": {"__content__": "<html><body><h1>It works!</h1></body></html>"}}},
        "backups": {
            "db_backup_2025.sql.gz": {"__content__": "\x1f\x8b\x08\x00binary-gzip-stub"},
        },
    },
    "root": {
        ".bash_history": {"__content__": "ls\ncd /var/www\nsystemctl status nginx\nexit\n"},
        ".ssh": {"authorized_keys": {"__content__": ""}},
    },
    "home": {
        "deploy": {
            ".bash_history": {"__content__": "git pull\nnpm install\nsudo systemctl restart app\n"},
            ".ssh": {"id_rsa": {"__content__": "-- permission denied --"}},
            "app": {
                "config.yaml": {"__content__": "db:\n  host: 10.0.0.5\n  user: appuser\n  password: REDACTED\n"},
                "app.py": {"__content__": "# production application entrypoint\n"},
            },
        },
        "ubuntu": {".bash_history": {"__content__": "sudo apt update\nsudo apt upgrade\n"}},
    },
}


class FakeFilesystem:
    """Per-session virtual filesystem with cwd tracking and stateful operations."""

    def __init__(self):
        self.tree = copy.deepcopy(_BASE_TREE)
        self.cwd = ["root"]  # default login lands in /root, like a real root shell

    def _resolve_parts(self, path: str):
        # Security hardening: reject Windows/UNC/env-var/null escapes immediately
        path_lower = path.lower()
        if (
            "c:\\" in path_lower or
            "c:/" in path_lower or
            "d:\\" in path_lower or
            "d:/" in path_lower or
            "\\\\" in path or
            "%" in path or
            "\x00" in path
        ):
            # Safe fail: resolve to an invalid/nonexistent path to force file not found
            return ["nonexistent_escaped_path"]

        if not path or path == ".":
            return list(self.cwd)
        if path == "~":
            return ["root"]
        if path.startswith("~"):
            path = "/home/" + path[1:].lstrip("/")

        if path.startswith("/"):
            parts = [p for p in path.split("/") if p and p != "."]
        else:
            parts = self.cwd + [p for p in path.split("/") if p and p != "."]

        resolved = []
        for part in parts:
            if part == "..":
                if resolved:
                    resolved.pop()
            else:
                resolved.append(part)
        return resolved

    def _node_at(self, path: str):
        resolved = self._resolve_parts(path)
        node = self.tree
        for part in resolved:
            if not isinstance(node, dict) or part not in node:
                return None
            node = node[part]
        return node

    def pwd(self) -> str:
        return "/" + "/".join(self.cwd) if self.cwd else "/"

    def cd(self, path: str) -> str:
        if not path or path == "~":
            self.cwd = ["root"]
            return ""
        resolved = self._resolve_parts(path)
        node = self.tree
        for part in resolved:
            if not isinstance(node, dict) or part not in node or "__content__" in node[part]:
                return f"-bash: cd: {path}: No such file or directory"
            node = node[part]
        self.cwd = resolved
        return ""

    def mkdir(self, path: str) -> str:
        if not path:
            return "mkdir: missing operand"
        resolved = self._resolve_parts(path)
        if not resolved:
            return "mkdir: cannot create directory '': File exists"
        node = self.tree
        for part in resolved[:-1]:
            if not isinstance(node, dict) or part not in node or "__content__" in node[part]:
                return f"mkdir: cannot create directory '{path}': No such file or directory"
            node = node[part]
        dirname = resolved[-1]
        if dirname in node:
            return f"mkdir: cannot create directory '{path}': File exists"
        node[dirname] = {"__mode__": "drwxr-xr-x", "__owner__": "root root", "__ts__": datetime.now(UTC).strftime("%b %d %H:%M")}
        return ""

    def touch(self, path: str) -> str:
        if not path:
            return "touch: missing file operand"
        resolved = self._resolve_parts(path)
        if not resolved:
            return ""
        node = self.tree
        for part in resolved[:-1]:
            if not isinstance(node, dict) or part not in node or "__content__" in node[part]:
                return f"touch: cannot touch '{path}': No such file or directory"
            node = node[part]
        filename = resolved[-1]
        if filename in node:
            if isinstance(node[filename], dict) and "__content__" in node[filename]:
                node[filename]["__ts__"] = datetime.now(UTC).strftime("%b %d %H:%M")
        else:
            node[filename] = {"__content__": "", "__mode__": "-rw-r--r--", "__owner__": "root root", "__ts__": datetime.now(UTC).strftime("%b %d %H:%M")}
        return ""

    def chmod(self, mode: str, path: str) -> str:
        if not path:
            return "chmod: missing operand"
        node = self._node_at(path)
        if node is None:
            return f"chmod: cannot access '{path}': No such file or directory"
        is_dir = "__content__" not in node
        current_mode = node.get("__mode__", "drwxr-xr-x" if is_dir else "-rw-r--r--")
        if "+x" in mode:
            # Add executable bits
            mode_chars = list(current_mode)
            mode_chars[3] = 'x'
            mode_chars[6] = 'x'
            mode_chars[9] = 'x'
            node["__mode__"] = "".join(mode_chars)
        elif "-x" in mode:
            mode_chars = list(current_mode)
            mode_chars[3] = '-'
            mode_chars[6] = '-'
            mode_chars[9] = '-'
            node["__mode__"] = "".join(mode_chars)
        return ""

    def ls(self, path: str = "", show_all: bool = False, long_format: bool = False) -> str:
        target = self._node_at(path) if path else self._current_node()
        if target is None:
            return f"ls: cannot access '{path}': No such file or directory"
        if "__content__" in target:
            if long_format:
                mode = target.get("__mode__", "-rw-r--r--")
                owner = target.get("__owner__", "root root")
                size = len(target.get("__content__", ""))
                ts = target.get("__ts__", "Aug 24 12:00")
                name = path or "file"
                return f"{mode} 1 {owner} {size:4d} {ts} {name}"
            return path or ""
        
        entries = [e for e in sorted(target.keys()) if not e.startswith("__")]
        if not show_all:
            entries = [e for e in entries if not e.startswith(".")]
        
        if not long_format:
            return "  ".join(entries)

        lines = [f"total {len(entries) * 4}"]
        for name in entries:
            child = target[name]
            is_dir = isinstance(child, dict) and "__content__" not in child
            default_mode = "drwxr-xr-x" if is_dir else "-rw-r--r--"
            mode = child.get("__mode__", default_mode) if isinstance(child, dict) else default_mode
            owner = child.get("__owner__", "root root") if isinstance(child, dict) else "root root"
            size = len(child.get("__content__", "")) if isinstance(child, dict) and "__content__" in child else 4096
            ts = child.get("__ts__", "Aug 24 12:00") if isinstance(child, dict) else "Aug 24 12:00"
            lines.append(f"{mode} 1 {owner} {size:5d} {ts} {name}")
        return "\n".join(lines)

    def _current_node(self):
        node = self.tree
        for part in self.cwd:
            if isinstance(node, dict):
                node = node.get(part, {})
        return node

    def cat(self, path: str) -> str:
        node = self._node_at(path)
        if node is None:
            return f"cat: {path}: No such file or directory"
        if not isinstance(node, dict) or "__content__" not in node:
            return f"cat: {path}: Is a directory"
        return node["__content__"]

    def write_marker(self, path: str, content: str):
        """Used when an attacker uploads/creates a file (e.g. via wget/echo) -
        stored per-session so we capture exactly what they dropped, without
        anything touching the real host filesystem."""
        filename = path.split("/")[-1] if "/" in path else path
        parent = self._current_node()
        if isinstance(parent, dict):
            parent[filename] = {
                "__content__": content,
                "__uploaded__": True,
                "__mode__": "-rw-r--r--",
                "__owner__": "root root",
                "__ts__": datetime.now(UTC).strftime("%b %d %H:%M")
            }