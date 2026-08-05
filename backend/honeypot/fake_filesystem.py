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
from datetime import datetime

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
    """Per-session virtual filesystem with cwd tracking."""

    def __init__(self):
        self.tree = copy.deepcopy(_BASE_TREE)
        self.cwd = ["root"]  # default login lands in /root, like a real root shell

    def _resolve(self, path: str):
        """Resolve a path (absolute or relative) to (parent_dict, name, node)."""
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

        node = self.tree
        for part in resolved[:-1]:
            if not isinstance(node, dict) or part not in node:
                return None, None, None
            node = node[part]
        name = resolved[-1] if resolved else None
        parent = node
        target = node.get(name) if name and isinstance(node, dict) else (self.tree if name is None else None)
        return parent, name, target

    def pwd(self) -> str:
        return "/" + "/".join(self.cwd) if self.cwd else "/"

    def cd(self, path: str) -> str:
        if not path or path == "~":
            self.cwd = ["root"]
            return ""
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

        node = self.tree
        for part in resolved:
            if not isinstance(node, dict) or part not in node or "__content__" in node[part]:
                return f"-bash: cd: {path}: No such file or directory"
            node = node[part]
        self.cwd = resolved
        return ""

    def ls(self, path: str = "", show_all: bool = False) -> str:
        _, _, target = (None, None, self._node_at(path)) if path else (None, None, self._current_node())
        if target is None:
            return f"ls: cannot access '{path}': No such file or directory"
        if "__content__" in target:
            return path or ""
        entries = sorted(target.keys())
        if not show_all:
            entries = [e for e in entries if not e.startswith(".")]
        return "  ".join(entries)

    def _current_node(self):
        node = self.tree
        for part in self.cwd:
            node = node.get(part, {})
        return node

    def _node_at(self, path: str):
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
        node = self.tree
        for part in resolved:
            if not isinstance(node, dict) or part not in node:
                return None
            node = node[part]
        return node

    def cat(self, path: str) -> str:
        node = self._node_at(path)
        if node is None:
            return f"cat: {path}: No such file or directory"
        if "__content__" not in node:
            return f"cat: {path}: Is a directory"
        return node["__content__"]

    def write_marker(self, path: str, content: str):
        """Used when an attacker uploads/creates a file (e.g. via wget/echo) -
        stored per-session so we capture exactly what they dropped, without
        anything touching the real host filesystem."""
        parent = self._current_node()
        parent[path] = {"__content__": content, "__uploaded__": True, "__ts__": datetime.utcnow().isoformat()}