import requests, json, time, sys
sys.path.insert(0, '.')

s = requests.Session()

# 登录
r = s.post('http://127.0.0.1:5000/api/auth/login', json={'username':'admin','password':'123456'})
print('1. 登录:', r.json().get('message'))

# 上传 VulnBank 合约
with open('vuln_samples/VulnBank.sol', 'rb') as f:
    r = s.post('http://127.0.0.1:5000/api/contracts', files={'file': ('VulnBank.sol', f)})
cid = r.json().get('id')
print('2. 上传合约 id:', cid)

# 执行审计
r = s.post('http://127.0.0.1:5000/api/audits', json={'contract_id': cid})
aid = r.json().get('audit_id')
print('3. 审计发起, audit_id:', aid)

# 轮询等待完成
for i in range(24):
    time.sleep(5)
    r = s.get(f'http://127.0.0.1:5000/api/audits/{aid}')
    j = r.json()
    st = j.get('status')
    n = len(j.get('vulnerabilities', []))
    print(f'   [{i*5}s] status={st} vulns={n}')
    if st in ('完成','失败'): break

vulns = j.get('vulnerabilities', [])
print(f'4. Slither 检出 {len(vulns)} 个漏洞')
for v in vulns[:5]:
    print(f'   - [{v.get("vul_level")}] {v.get("vul_type")}')

# 上链存证
r = s.post(f'http://127.0.0.1:5000/api/evidence', json={'audit_id': aid})
print('5. 存证接口:', r.status_code, r.text[:100])

# 用另一个接口
r = s.post('http://127.0.0.1:5000/api/evidence/save', json={'audit_id': aid})
print('6. 存证/save:', r.status_code, r.text[:150])
if r.ok:
    ev = r.json()
    real = ev.get('tx_hash','').startswith('0x') and len(ev.get('tx_hash','')) > 30
    print('   真实链哈希:', real)
    print('   tx_hash:', ev.get('tx_hash'))
