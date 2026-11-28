"""Bounded mixed-protocol throughput and server resources on localhost."""
import asyncio
import importlib.util
import json
import os
from pathlib import Path
from secrets import token_urlsafe
import statistics
import subprocess
import sys
import tempfile
import time

import asyncssh
import httpx

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('loopback', root/'scripts/verify_loopback.py')
loopback = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loopback)

def resources(processes):
    rss = ticks = 0
    for proc in processes:
        status = Path(f'/proc/{proc.pid}/status').read_text()
        rss += int(next(line.split()[1] for line in status.splitlines() if line.startswith('VmRSS:')))
        fields = Path(f'/proc/{proc.pid}/stat').read_text().rsplit(')', 1)[1].split()
        ticks += int(fields[11]) + int(fields[12])
    return rss, ticks

async def trial(workers, ports, processes):
    ssh, telnet, http = ports
    latencies = []
    peak = [0]
    async with httpx.AsyncClient(timeout=8, trust_env=False) as client:
        async def job():
            for _ in range(3):
                for call in (lambda: client.get(f'http://127.0.0.1:{http}/'),
                             lambda: loopback.ssh_session(ssh), lambda: loopback.telnet_session(telnet)):
                    start = time.perf_counter()
                    result = await call()
                    if isinstance(result, httpx.Response):
                        result.raise_for_status()
                    latencies.append((time.perf_counter()-start)*1000)
        async def sample():
            while True:
                peak[0] = max(peak[0],resources(processes)[0])
                await asyncio.sleep(.05)
        sampler = asyncio.create_task(sample())
        start = time.perf_counter()
        start_ticks = resources(processes)[1]
        try:
            await asyncio.wait_for(asyncio.gather(*(job() for _ in range(workers))),timeout=60)
        finally:
            sampler.cancel()
        elapsed = time.perf_counter()-start
        rss, ticks = resources(processes)
        return {'workers':workers, 'operations':len(latencies),
            'operations_per_second':round(len(latencies)/elapsed,2), 'median_ms':round(statistics.median(latencies),2),
            'p95_ms':round(statistics.quantiles(latencies,n=100,method='inclusive')[94],2),
            'peak_combined_rss_mib':round(max(peak[0],rss)/1024,2),
            'cpu_core_percent':round(100*(ticks-start_ticks)/os.sysconf('SC_CLK_TCK')/elapsed,2)}

def wait_http(url):
    for _ in range(60):
        try:
            httpx.get(url, timeout=.4,trust_env=False).raise_for_status()
            return
        except (httpx.RequestError,httpx.HTTPStatusError):
            time.sleep(.15)
    raise RuntimeError('Loopback service not ready')

with tempfile.TemporaryDirectory(prefix='praetor-bench-') as temporary, tempfile.TemporaryFile(mode='w+') as log:
    scratch = Path(temporary)
    ssh,telnet,http,management = [loopback.unused_port() for _ in range(4)]
    key = scratch/'ssh-key'
    asyncssh.generate_private_key('ssh-ed25519').write_private_key(key)
    key.chmod(0o600)
    base = f'http://127.0.0.1:{management}'
    env = dict(os.environ, ENVIRONMENT='development', DATABASE_URL=f"sqlite:///{scratch/'events.db'}",
        LOG_DIR=str(scratch/'log'), MANAGEMENT_API_KEY=token_urlsafe(32), SSH_HOST_KEY_PATH=str(key),
        HONEYPOT_BIND_HOST='127.0.0.1', HONEYPOT_SSH_PORT=str(ssh), HONEYPOT_TELNET_PORT=str(telnet),
        HONEYPOT_HTTP_PORT=str(http), BACKEND_INGEST_URL=base+'/api/logs/ingest',
        GEMINI_API_KEY='', OTX_API_KEY='', ABUSEIPDB_API_KEY='')
    commands = [
        ['uvicorn','backend.main:app','--host','127.0.0.1','--port',str(management)],
        ['scripts.run_honeypots'],
    ]
    processes = []
    try:
        for command,url in zip(commands,[base+'/health',f'http://127.0.0.1:{http}/']):
            processes.append(subprocess.Popen([sys.executable,'-m',*command],cwd=root,env=env,stdout=log,stderr=log))
            wait_http(url)
        asyncio.run(trial(1,(ssh,telnet,http),processes))
        results = [asyncio.run(trial(workers,(ssh,telnet,http),processes)) for workers in (1,4,8) for _ in range(3)]
        print(json.dumps({'logical_cpus':len(os.sched_getaffinity(0)),'results':results},indent=2))
    finally:
        for process in reversed(processes):
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
