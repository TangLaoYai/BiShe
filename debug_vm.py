import subprocess, config, uuid, os, json

sol_path = os.path.join(config.UPLOAD_DIR, '8_VulnBank.sol')
remote_name = f'{uuid.uuid4().hex}.sol'
remote_path = f'{config.VM_TEMP_DIR.rstrip("/")}/{remote_name}'

print('=== Test _run_vm_slither manually ===')
print('sol_path:', sol_path, 'size:', os.path.getsize(sol_path))
print('remote_path:', remote_path)

# 1. scp
scp = subprocess.run(
    ['scp', '-P', str(config.VM_SSH_PORT), '-o', 'StrictHostKeyChecking=no',
     '-o', 'UserKnownHostsFile=NUL',
     sol_path, f'{config.VM_USER}@{config.VM_IP}:{remote_path}'],
    capture_output=True, text=True, timeout=60)
print('1. scp rc:', scp.returncode, 'stderr:', scp.stderr.strip()[:100])

# 2. SSH 执行（和 slither_detector.py 里一样的命令）
cmd = (f"source /home/{config.VM_USER}/venv/bin/activate && "
       f"SOLC_VERSION=0.8.0 {config.VM_SLITHER_CMD} {remote_path} --json -; "
       f"rm -f {remote_path}")
print('2. cmd:', cmd[:150], '...')

ssh = subprocess.run(
    ['ssh', '-p', str(config.VM_SSH_PORT), '-o', 'StrictHostKeyChecking=no',
     '-o', 'UserKnownHostsFile=NUL',
     f'{config.VM_USER}@{config.VM_IP}', 'bash', '-c', cmd],
    capture_output=True, text=True, timeout=300, encoding='utf-8', errors='replace')

print('3. ssh rc:', ssh.returncode, 'stdout_len:', len(ssh.stdout), 'stderr_len:', len(ssh.stderr))
print('   stdout[:200]:', (ssh.stdout or '')[:200])
print('   stderr[:200]:', (ssh.stderr or '')[:200])

# 解析
for text in (ssh.stdout, ssh.stderr):
    text = (text or '').strip()
    if not text:
        continue
    print(f'4. trying parse (len={len(text)})...')
    if not text.startswith('{'):
        print('   does not start with {, skip')
        continue
    try:
        data = json.loads(text)
        dets = data.get('results', {}).get('detectors', []) or data.get('detectors', [])
        print('5. SUCCESS! detectors:', len(dets))
        for d in dets[:5]: print('   -', d.get('check',''), d.get('impact',''))
    except Exception as e:
        print('   parse err:', e)
