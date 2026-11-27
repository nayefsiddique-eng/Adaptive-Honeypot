#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
for file in .env.management .env.honeypot; do
  if [[ -e "$file" ]]; then
    echo "Use a disposable checkout without existing environment files."
    exit 1
  fi
done
scratch="$(mktemp -d)"
project="praetor-isolation-${GITHUB_RUN_ID:-$$}"
probe="$project-unrelated"
compose() {
  docker compose -p "$project" -f docker-compose.prod.yml -f "$scratch/compose.yml" "$@"
}
cleanup() {
  docker rm -f "$probe" >/dev/null 2>&1 || true
  docker network rm "$probe" >/dev/null 2>&1 || true
  compose down --volumes >/dev/null 2>&1 || true
  rm -f -- .env.management .env.honeypot
  rm -rf -- "$scratch"
}
trap cleanup EXIT
umask 077
{
  for key in SECRET_KEY ADMIN_API_KEY MANAGEMENT_API_KEY; do
    value="$(openssl rand -hex 32)"
    printf '::add-mask::%s\n' "$value" >&2
    printf '%s=%s\n' "$key" "$value"
  done
} > .env.management
: > .env.honeypot
cat > "$scratch/compose.yml" <<'YAML'
services:
  praetor-management:
    ports: !reset []
  praetor-honeypot:
    ports: !reset []
YAML
compose up --build --detach --wait --wait-timeout 150
container="$(compose ps -q praetor-honeypot)"
test "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$container")" = true
docker inspect --format '{{json .Mounts}}' "$container" | python -c 'import json, sys; mounts=json.load(sys.stdin); assert all(m["Type"]=="volume" for m in mounts)'
docker network create --internal "$probe" >/dev/null
docker run -d --name "$probe" --network "$probe" python:3.12-slim python -m http.server 8009 >/dev/null
probe_ip="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$probe")"
docker exec "$probe" python -c 'from urllib.request import urlopen; urlopen("http://127.0.0.1:8009",timeout=3).close()'
compose exec -T -e "VERIFY_PROBE_IP=$probe_ip" praetor-honeypot python - <<'PY'
import os
from pathlib import Path
import socket
from urllib.request import urlopen

assert os.getuid() != 0
assert not Path("/var/run/docker.sock").exists()
assert not any(line.split()[1] == "00000000" for line in Path("/proc/net/route").read_text().splitlines()[1:])
with urlopen("http://praetor-management:8000/health", timeout=4) as response:
    assert response.status == 200
for port in (2222, 8080, 2323):
    with socket.create_connection(("127.0.0.1", port), timeout=3):
        pass
try:
    connection = socket.create_connection((os.environ["VERIFY_PROBE_IP"], 8009), timeout=3)
except OSError:
    pass
else:
    connection.close()
    raise AssertionError("Deception plane reached an unrelated disposable network")
print("Read-only non-root deception plane, local protocol ports, telemetry path and cross-network denial passed.")
PY
