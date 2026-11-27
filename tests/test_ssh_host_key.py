import asyncio

import pytest

from backend.honeypot import ssh_server


def test_missing_default_host_key_generates_new_runtime_key(monkeypatch, tmp_path):
    monkeypatch.delenv("SSH_HOST_KEY_PATH", raising=False)
    monkeypatch.setattr(ssh_server, "HOST_KEY_PATH", str(tmp_path / "missing-key"))
    fingerprints = []

    async def capture_key(_factory, **kwargs):
        fingerprints.append(kwargs["server_host_keys"][0].get_fingerprint())

    monkeypatch.setattr(ssh_server.asyncssh, "create_server", capture_key)
    asyncio.run(ssh_server.start_server())
    asyncio.run(ssh_server.start_server())
    assert len(set(fingerprints)) == 2


def test_explicit_missing_host_key_does_not_silently_rotate(monkeypatch, tmp_path):
    monkeypatch.setenv("SSH_HOST_KEY_PATH", str(tmp_path / "missing-key"))
    with pytest.raises(FileNotFoundError):
        asyncio.run(ssh_server.start_server())
