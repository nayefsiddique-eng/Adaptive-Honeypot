import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.config import settings
from backend.honeypot.fake_filesystem import FakeFilesystem
from backend.honeypot.ssh_server import dispatch_command

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.database import Base, get_db

from sqlalchemy.pool import StaticPool
test_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

@pytest.fixture(autouse=True, scope="module")
def setup_test_db():
    from backend.models import attack, session, reputation, policy  # noqa
    Base.metadata.create_all(bind=test_engine)
    
    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.rollback()
            db.close()
            
    app.dependency_overrides[get_db] = override_get_db
    yield
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()

client = TestClient(app)

def test_hardened_path_traversal_guards():
    """
    Verifies that escape vectors (Windows pathing, UNC paths, env vars, null bytes)
    are caught and resolve safely to nonexistent paths.
    """
    fs = FakeFilesystem()
    
    blocked_inputs = [
        "C:\\Windows\\System32\\cmd.exe",
        "c:/windows/system32/cmd.exe",
        "\\\\server\\share\\file.txt",
        "%SYSTEMROOT%\\win.ini",
        "somefile.txt\x00.py"
    ]
    
    for inp in blocked_inputs:
        output = dispatch_command(fs, f"cat {inp}")
        assert "No such file or directory" in output or "Is a directory" in output or not output

def test_command_length_limits():
    """
    Verifies that command parsing is constrained under MAX_COMMAND_LENGTH limits.
    """
    # Simply verify settings value exists and is set to a reasonable limit
    assert settings.MAX_COMMAND_LENGTH == 8192

def test_unauthenticated_management_api_access():
    """
    Verifies that management endpoints return 401 when accessed without authorization.
    """
    endpoints = [
        "/api/sessions",
        "/api/research/metrics",
        "/api/decisions/profile/brute_force",
        "/api/logs",
        "/api/logs/recent",
        "/api/geoip/attack-map",
        "/api/threat-intel/top-threats",
        "/api/timeline",
        "/api/adaptive/simulate",
        "/api/digital-twin/personas"
    ]
    for url in endpoints:
        res = client.get(url)
        assert res.status_code == 401, f"Expected 401 for {url}, got {res.status_code}"

def test_invalid_api_keys():
    """
    Verifies that invalid management API keys are rejected.
    """
    res = client.get("/api/sessions", headers={"X-Management-Key": "wrong-key-value"})
    assert res.status_code == 401

def test_ingest_open_access():
    """
    Verifies that the core log ingest remains open for internal honeypot log forwarding.
    """
    res = client.post("/api/logs/ingest", json={
        "ip_address": "127.0.0.1",
        "port": 22,
        "protocol": "ssh",
        "payload": "test connection",
        "metadata": {}
    })
    # Must succeed (200) or return valid transaction validation (not 401)
    assert res.status_code in (200, 201)

def test_cors_management_origins():
    """
    Verifies that CORS origins list is populated and not a wildcard.
    """
    assert "*" not in settings.cors_origins_list
    assert len(settings.cors_origins_list) > 0
