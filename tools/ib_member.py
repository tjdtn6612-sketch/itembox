#!/usr/bin/env python3
"""아이템박스 회원 관리 도구 — members.json 을 고칩니다.

  승인:  python3 tools/ib_member.py add < 신청서.txt      (카카오톡으로 받은 신청서 전체 붙여넣기)
  삭제:  python3 tools/ib_member.py remove <아이디>
  목록:  python3 tools/ib_member.py count
  관리자 비밀번호 변경 반영: python3 tools/ib_member.py admin '<사이트에서 받은 코드(JSON)>'

회원 정보는 공개키로 암호화되어 저장되고, 관리자 비밀번호로만 사이트의 회원목록에서 열립니다.
"""
import sys, json, os, re, base64, hashlib, datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATH = os.path.join(ROOT, 'members.json')
b64 = lambda b: base64.b64encode(b).decode()

def load():
    with open(PATH, encoding='utf-8') as f: return json.load(f)
def save(m):
    with open(PATH, 'w', encoding='utf-8') as f: json.dump(m, f, ensure_ascii=False, separators=(',', ':'))
def idh(i): return hashlib.sha256(('id:' + i.strip().lower()).encode()).hexdigest()

FIELDS = {'이름': 'name', '업체명(상호)': 'co', '업체명': 'co', '상호': 'co', '아이디': 'id', '연락처': 'tel', '이메일': 'mail', '주소': 'addr', '가입코드': 'code'}
def parse(text):
    d = {}
    for line in text.splitlines():
        m = re.match(r'^\s*([^:：]+?)\s*[:：]\s*(.+?)\s*$', line)
        if m and m.group(1) in FIELDS: d[FIELDS[m.group(1)]] = m.group(2)
    return d

def add(text):
    d = parse(text)
    need = ['name', 'co', 'id', 'tel', 'mail', 'addr', 'code']
    miss = [k for k in need if not d.get(k)]
    if miss: sys.exit('신청서에 빠진 항목이 있습니다: ' + ', '.join(miss))
    if not re.fullmatch(r'[0-9a-f]{64}', d['code']): sys.exit('가입코드 형식이 올바르지 않습니다 (64자리 영문·숫자)')
    if not re.fullmatch(r'[A-Za-z0-9_]{4,20}', d['id']): sys.exit('아이디 형식이 올바르지 않습니다')
    m = load()
    h = idh(d['id'])
    if any(x['idh'] == h for x in m['members']): sys.exit('이미 등록된 아이디입니다: ' + d['id'])
    rec = {k: d[k] for k in ['name', 'co', 'id', 'tel', 'mail', 'addr']}
    rec['at'] = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=9))).strftime('%Y.%m.%d %H:%M')
    pub = serialization.load_der_public_key(base64.b64decode(m['pub']))
    key, iv = AESGCM.generate_key(256), os.urandom(12)
    ct = AESGCM(key).encrypt(iv, json.dumps(rec, ensure_ascii=False).encode(), None)
    wk = pub.encrypt(key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    m['members'].append({'idh': h, 'c': d['code'], 'k': b64(wk), 'i': b64(iv), 'd': b64(ct)})
    save(m)
    print(f"승인 완료: {rec['name']} / {rec['co']} / 아이디 {rec['id']}  (전체 {len(m['members'])}명)")

def remove(i):
    m = load(); h = idh(i); n = len(m['members'])
    m['members'] = [x for x in m['members'] if x['idh'] != h]
    if len(m['members']) == n: sys.exit('해당 아이디가 없습니다: ' + i)
    save(m); print(f'삭제 완료: {i}  (전체 {len(m["members"])}명)')

def admin(code):
    c = json.loads(code)
    if not re.fullmatch(r'[0-9a-f]{64}', c.get('h', '')) or not all(k in c.get('p', {}) for k in 'sid'): sys.exit('관리자 코드 형식이 올바르지 않습니다')
    m = load(); m['admin'] = {'hash': c['h'], 'priv': c['p']}; save(m); print('관리자 비밀번호 변경을 반영했습니다')

if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    if cmd == 'add': add(sys.stdin.read())
    elif cmd == 'remove' and len(sys.argv) > 2: remove(sys.argv[2])
    elif cmd == 'count': print(f"회원 {len(load()['members'])}명")
    elif cmd == 'admin' and len(sys.argv) > 2: admin(sys.argv[2])
    else: print(__doc__)
