# -*- coding: utf-8 -*-
"""
CTF 全自动暴力分析引擎 (super)
================================
把任何题目文件/一段文字丢进来, 所有能试的自动全试一遍, 最后汇总 flag 候选。

设计原则:
  1) 永不卡住    —— 每个分析器独立 try/except + 超时, 一个挂了不影响别的
  2) 不用你选    —— 类型自动识别, 该跑的全跑
  3) 不需要管理员 —— 全程纯用户态, 只写自己的输出目录
  4) 顺手写 Writeup
"""
import base64, binascii, codecs, hashlib, io, itertools, json, math, os, re, string
import subprocess, sys, tarfile, tempfile, time, urllib.parse, zipfile
from collections import Counter, OrderedDict
try:
    import advanced as ADV
except Exception:
    ADV = None

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.environ.get('COMMANDER_TOOLKIT_DIR') or os.path.join(HERE, 'toolkit'))
if HERE not in sys.path:
    sys.path.insert(0, HERE)   # 修复: 原来多算了一层目录, 导致所有外部工具都找不到

# ---------------- 全局状态 ----------------
FLAGS = OrderedDict()
REJECTED = set()          # 被判别函数筛掉的"疑似flag"，供你参考
NOTES = []                     # Writeup 记录
OUTDIR = None                  # 输出目录
DIAG = None                    # commander 注入的诊断记录器

def diag(phase, status, title, **kwargs):
    """记录一个可审查步骤；没有诊断器时是安全的 no-op。"""
    if DIAG is None:
        return
    try:
        if len(DIAG.steps) >= 500:
            return
        DIAG.add(phase, status, title, **kwargs)
    except Exception:
        pass
START_T = time.time()

# ---- 输出编码自适应：控制台即使是 GBK 也不会崩 ----
for _st in (sys.stdout, sys.stderr):
    try:
        _st.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
try:
    import cv2 as _cv2
    _cv2.utils.logging.setLogLevel(_cv2.utils.logging.LOG_LEVEL_SILENT)
except Exception:
    pass

def _safe_print(s):
    try:
        print(s, flush=True)
        return
    except UnicodeEncodeError:
        pass
    except Exception:
        return
    enc = getattr(sys.stdout, 'encoding', None) or 'utf-8'
    try:
        sys.stdout.buffer.write((str(s) + '\n').encode(enc, 'replace'))
        sys.stdout.flush()
    except Exception:
        try:
            print(str(s).encode('ascii', 'replace').decode('ascii'), flush=True)
        except Exception:
            pass
def C(s, c):
    return s

def say(msg='', color=''):
    _safe_print(msg)
    NOTES.append(msg)

def head(title):
    diag('stage', 'start', title)
    say('')
    say('  ┌─ ' + title + ' ' + '─' * max(0, 56 - len(title)))

def note(msg):
    say('     ' + msg)

def why(msg):
    diag('assumption', 'info', '分析假设/原理', why=msg, confidence='medium')
    say('     (为什么: ' + msg + ')')

# ===== flag 真假判别（补进来的）=====
# 为什么要这个：有些文件里会偶然出现 xxx{...} 形状的字符串（代码片段、报错信息、
# 二进制里的随机数据），不筛掉的话会报一堆假 flag 带偏你。
KNOWN_PREFIX = ('flag','ctf','fleg','c404','nss','buu','hgame','ctfshow','dasctf','n1ctf','moectf','geek','xnuca','xctf','nssctf','buuctf','ciscn','qwb','starctf','de1ctf','suctf','0ctf','bctf','rwctf','actf','iscc','wctf','sctf','zctf','nepctf','tctf')

def plausible_flag(v):
    """判断一个 xxx{...} 到底像不像真 flag"""
    import re as _re
    if not v or len(v) < 6 or len(v) > 200:
        return False
    m = _re.match(r'^([A-Za-z][A-Za-z0-9_\-]{1,20})\{([^}\n]{2,150})\}$', v)
    if not m:
        return False
    pre, body = m.group(1), m.group(2)
    if any(ord(ch) < 32 or ord(ch) > 126 for ch in pre + body):
        return False
    if len(set(body)) < max(4, min(8, len(body) // 3)):
        return False
    if _re.search(r'(.)\1{5,}', body):
        return False
    weird = sum(1 for ch in body if not (ch.isalnum() or ch in '_-!@#$%^&*+=.,:;/ \u4e00-\u9fff'))
    if weird > (1 if len(body) <= 16 else max(2, len(body) * 0.15)):
        return False
    if _re.search(r'[~\"\'`\\|]', body):
        return False
    if pre.lower() not in KNOWN_PREFIX and not _re.fullmatch(r'[A-Za-z]{2,20}', pre):
        return False
    low = body.lower()
    for bad in ('invalid syntax','not found','no such file','undefined','traceback',
                'assertion','panic','error:','http://','https://','javascript'):
        if bad in low:
            return False
    return True

def _is_final_flag(t):
    """文本里已经有"已知前缀"的完整 flag -> 视为终点，不再继续做变换"""
    if not t:
        return False
    for m in FLAG_RE.finditer(t):
        v = m.group(0)
        try:
            if plausible_flag(v) and v.split('{')[0].lower() in KNOWN_PREFIX:
                return True
        except Exception:
            pass
    return False

def flag_rank(v):
    """给 flag 候选排序：越像真的分越高"""
    try:
        pre = v.split('{')[0].lower()
    except Exception:
        return 0
    s = 0
    if pre in ('flag','ctf','c404','fleg'): s += 100
    elif pre in KNOWN_PREFIX: s += 60
    elif re.fullmatch(r'[a-z]{3,12}', pre): s += 20
    s += min(len(v), 60) / 10.0
    return s
NOISY_SRC = ('凯撒', '键盘', 'Atbash', '栅栏', 'Bacon', '摩斯', 'morse', '维吉尼亚', 'ROT13', 'rot13', '反转')

def add_flag(v, where):
    """记录一个 flag 候选（先用 plausible_flag 过滤掉垃圾串，减少误报）"""
    if not v or len(v) > 200:
        return
    try:
        if not plausible_flag(v):
            REJECTED.add(v)
            return
        # 凯撒/键盘/栅栏这类"变形"会产生大量形似 flag 的串：只收已知前缀的
        if any(_x in str(where) for _x in NOISY_SRC):
            if v.split('{')[0].lower() not in KNOWN_PREFIX:
                REJECTED.add(v)
                return
    except Exception:
        pass
    if v not in FLAGS:
        FLAGS[v] = set()
    FLAGS[v].add(str(where))
    diag('result', 'found', '发现 flag 候选', evidence='%s <- %s' % (v, where), confidence='high')

# ---------------- 通用工具 ----------------
HINTS = []          # (优先级, 具体动作)
EXTRA_PW = []       # 用户用 --password 传进来的密码

def hint(level, text):
    for L, t in HINTS:
        if t == text:
            return
    HINTS.append((level, text))
RESULTS = OrderedDict()

def add_result(v, where):
    """记录不是 flag 格式、但可能有用的解出内容"""
    if not v:
        return
    v = str(v).strip()
    if not (1 <= len(v) <= 400):
        return
    if v not in RESULTS:
        RESULTS[v] = set()
    RESULTS[v].add(str(where))

def scan_base64_blobs(text, where):
    """在任意文本里找长 base64 串并解码（很多题就把 flag 明文以 base64 塞在文件里）"""
    if not text:
        return
    for m in re.finditer(r'[A-Za-z0-9+/]{16,}={0,2}', text):
        t = m.group(0)
        if len(t) % 4 == 1:
            continue
        try:
            b = base64.b64decode(t + '=' * (-len(t) % 4), validate=False)
            s = b.decode('utf-8')
        except Exception:
            continue
        if not s.strip():
            continue
        if '{' in s and '}' in s:
            scan_flags(s, where + '(内嵌base64)')
            add_result(s, where + '(内嵌base64)')
def run(cmd, timeout=60, cwd=None):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, cwd=cwd)
        out = (r.stdout or b'').decode('utf-8', 'replace')
        err = (r.stderr or b'').decode('utf-8', 'replace')
        return out + ('\n' + err if err.strip() else '')
    except subprocess.TimeoutExpired:
        return '[超时 %d 秒, 跳过]' % timeout
    except FileNotFoundError:
        return '[找不到命令: %s]' % cmd[0]
    except Exception as e:
        return '[执行失败: %s]' % e

def tool(rel, *names):
    """在工具箱里找一个外部程序"""
    cands = [os.path.join(ROOT, rel)] + [os.path.join(ROOT, n) for n in names]
    for c in cands:
        if os.path.isfile(c):
            return c
    return None

def outpath(name):
    global OUTDIR
    if OUTDIR:
        os.makedirs(OUTDIR, exist_ok=True)
        return os.path.join(OUTDIR, name)
    return os.path.join(tempfile.gettempdir(), name)

def save(name, data):
    p = outpath(name)
    mode = 'wb' if isinstance(data, (bytes, bytearray)) else 'w'
    with open(p, mode, **({} if mode == 'wb' else {'encoding': 'utf-8'})) as f:
        f.write(data)
    diag('artifact', 'saved', '已写入中间产物', artifacts=[p])
    return p

def read_bytes(path, limit=None):
    with open(path, 'rb') as f:
        return f.read() if limit is None else f.read(limit)

def read_text(path, limit=8 * 1024 * 1024):
    try:
        b = read_bytes(path, limit)
        for enc in ('utf-8', 'gbk', 'latin-1'):
            try:
                return b.decode(enc)
            except Exception:
                continue
    except Exception:
        pass
    return ''

# ---------------- flag 扫描 ----------------
FLAG_RE = re.compile(r'[A-Za-z][A-Za-z0-9_\-]{1,18}\{[^{}\n\r\t]{2,120}\}')

def _plausible_flag(v):
    """过滤掉代码/随机数据里形如 xxx{...} 的误报（宁可少报也不能刷屏）"""
    m = re.match(r'^([A-Za-z][A-Za-z0-9_\-]{0,18})\{([^{}\n\r\t]{2,120})\}$', v)
    if not m:
        return False
    pre, inner = m.group(1), m.group(2)
    if any(ch in inner for ch in '[]()$<>\\=;'):
        return False
    if '->' in inner or '::' in inner or '..' in inner:
        return False
    if re.search(r'(?i)\b(elem|argv|topic|publish|master|next|hash|ref|split|exists)\b', inner):
        return False
    if len(inner) < 3:
        return False
    if len(inner) < 5 and pre.lower() not in ('flag', 'ctf', 'c404', 'fleg', 'key', 'nss', 'buu', 'hgame', 'flag1', 'rjsb', 'f14g'):
        return False
    alnum = sum(1 for ch in inner if ch.isalnum() or ch in '_-')
    if alnum / len(inner) < 0.75:
        return False
    return True

FAKE_HINT = re.compile(r'(?i)fake|dont_trust|not_the_flag|example|sample|test_flag|placeholder|hint')

_ZW_POLY = None
def _zw_check(text, where):
    """文本里若有零宽字符，自动尝试解码（零宽字符隐写题）"""
    global _ZW_POLY
    if not text:
        return
    if not any(ord(ch) in (0x200B,0x200C,0x200D,0x2060,0xFEFF,0x202A,0x202B,0x202C,0x202D,0x202E,0x00AD) for ch in text[:20000]):
        return
    try:
        if _ZW_POLY is None:
            import poly as _p
            _ZW_POLY = _p
        res = _ZW_POLY.decode_zero_width(text)
    except Exception as e:
        note('  零宽字符解码出错: %s' % e)
        return
    if res:
        note('')
        note('★ 发现零宽字符隐写！解出 %d 个候选:' % len(res))
        for s, how in res[:6]:
            note('   %r   (%s)' % (s[:120], how))
            if '{' in s and '}' in s:
                scan_flags_direct(s, where + '/零宽隐写')

# ---- 不完整的 flag（缺右花括号）：题目常把 flag 拆成几段 ----------
PARTIAL_RE = re.compile(r'([A-Za-z][A-Za-z0-9_\-]{1,20})\{([^}\s]{3,150})')
PARTIALS = OrderedDict()


def add_partial(v, where):
    """记录一个"像 flag 但没写完"的片段（补个右括号看像不像）"""
    if not v or len(v) > 200:
        return
    try:
        if not plausible_flag(v + '}'):
            return
    except Exception:
        return
    if v not in PARTIALS:
        PARTIALS[v] = set()
    PARTIALS[v].add(str(where))


def scan_flags_direct(text, where):
    """不触发零宽检测的直接扫描，避免递归"""
    if not text:
        return
    for m in FLAG_RE.finditer(text):
        if _plausible_flag(m.group(0)):
            add_flag(m.group(0), where)
    try:
        _zw_check(text, where)
    except Exception:
        pass
def scan_flags(text, where):
    if not text:
        return
    for m in FLAG_RE.finditer(text):
        if _plausible_flag(m.group(0)):
            add_flag(m.group(0), where)
    # 摩斯/培根/维吉尼亚常输出全大写：额外登记"前缀大写 + 正文小写"的规范化形式
    if ('{' in text and '}' in text) and not any(c.islower() for c in text):
        for m in FLAG_RE.finditer(text):
            v = m.group(0)
            try:
                pre, body = v.split('{', 1)
                nv = pre.upper() + '{' + body[:-1].lower() + '}'
            except Exception:
                continue
            if nv != v and _plausible_flag(nv):
                add_flag(nv, where + '(规范化大小写)')
    try:
        for m in PARTIAL_RE.finditer(text):
            if m.end() < len(text) and text[m.end()] == '}':
                continue          # 这是完整的 flag，上面已经收过了
            add_partial(m.group(0), where)
    except Exception:
        pass
    try:
        _zw_check(text, where)
    except Exception:
        pass

# ---------------- 类型识别 ----------------
MAGIC = [
    (b'\x89PNG\r\n\x1a\n', 'png', 'PNG 图片'),
    (b'\xff\xd8\xff',       'jpg', 'JPG 图片'),
    (b'GIF8',               'gif', 'GIF 图片'),
    (b'BM',                 'bmp', 'BMP 图片'),
    (b'PK\x03\x04',         'zip', 'ZIP 压缩包'),
    (b'PK\x01\x02',         'zip', 'ZIP 压缩包(空/尾部)'),
    (b'Rar!\x1a\x07',       'rar', 'RAR 压缩包'),
    (b'7z\xbc\xaf\x27\x1c', '7z',  '7z 压缩包'),
    (b'\x1f\x8b',           'gz',  'gzip 压缩'),
    (b'BZh',                'bz2', 'bzip2 压缩'),
    (b'\xfd7zXZ\x00',       'xz',  'xz 压缩'),
    (b'\x7fELF',            'elf', 'Linux 程序 (ELF)'),
    (b'MZ',                 'exe', 'Windows 程序 (exe/dll)'),
    (b'%PDF',               'pdf', 'PDF 文档'),
    (b'\xd0\xcf\x11\xe0',   'doc', '老版 Office 文档'),
    (b'\x50\x4b\x05\x06',   'zip', 'ZIP(空)'),
    (b'\xd4\xc3\xb2\xa1',   'pcap','网络流量包 (pcap)'),
    (b'\xa1\xb2\xc3\xd4',   'pcap','网络流量包 (pcap)'),
    (b'\x0a\x0d\x0d\x0a',   'pcap','网络流量包 (pcapng)'),
    (b'RIFF',               'riff','RIFF (wav/avi)'),
    (b'ID3',                'mp3', 'MP3 音频'),
    (b'OggS',               'ogg', 'OGG 音频'),
    (b'fLaC',               'flac','FLAC 音频'),
    (b'\x00\x00\x01\x00',   'ico', 'ICO 图标'),
    (b'\x1a\x45\xdf\xa3',   'mkv', 'Matroska (mkv/webm)'),
    (b'\x49\x49\x2a\x00',   'tiff','TIFF 图片'),
    (b'\x4d\x4d\x00\x2a',   'tiff','TIFF 图片'),
    (b'PACK',               'git', 'Git pack 文件'),
]

def sniff(data):
    if len(data) > 262 and data[257:262] == b'ustar':
        return 'tar', 'tar 归档包'
    for sig, key, name in MAGIC:
        if data.startswith(sig):
            return key, name
    # 文本类特判
    try:
        t = data[:2000].decode('utf-8')
        if t.lstrip().startswith('data:'):
            return 'datauri', 'Data URI (文件被伪装成文本)'
        if re.fullmatch(r'[01\s]{200,}', t):
            return 'bits', '0/1 数据 (像素画/二维码)'
        import unicodedata as _ud
        def _ok(ch):
            o = ord(ch)
            if ch in '\r\n\t': return True
            return _ud.category(ch) not in ('Cc', 'Cs', 'Co', 'Cn')
        printable = sum(1 for ch in t if _ok(ch))
        if printable / max(1, len(t)) > 0.9:
            return 'text', '纯文本'
    except Exception:
        pass
    return 'unknown', '未知类型'

# ============================================================
#                   文 本 / 编 码 类 分 析
# ============================================================
B64_ALPHABET = string.ascii_uppercase + string.ascii_lowercase + string.digits + '+/'

def _decoders(s, allow_rot13=False):
    """返回一堆 (名字, 解码函数)。覆盖初级赛常见的编码/古典密码/文本隐写。"""
    s2 = s.strip()
    if _is_final_flag(s2):
        return []
    def b64(x):
        t = re.sub(r'\s', '', x); t += '=' * (-len(t) % 4)
        return base64.b64decode(t, validate=False)
    def b64url(x):
        t = re.sub(r'\s', '', x); t += '=' * (-len(t) % 4)
        return base64.urlsafe_b64decode(t)
    def b32(x):
        t = re.sub(r'\s', '', x.upper()); t += '=' * (-len(t) % 8)
        return base64.b32decode(t)
    def b16(x):
        t = re.sub(r'[^0-9a-fA-F]', '', x)
        return binascii.unhexlify(t)
    B58A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    def b58(x):
        t = ''.join(ch for ch in x if ch in B58A)
        if len(t) < 4: return b''
        n = 0
        for ch in t: n = n * 58 + B58A.index(ch)
        body = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n else b''
        return b'\x00' * (len(t) - len(t.lstrip('1'))) + body
    def b85(x):
        t = re.sub(r'\s', '', x)
        return base64.b85decode(t)
    def a85(x):
        t = re.sub(r'\s', '', x)
        return base64.a85decode(t, adobe=False)
    def uenc(x):
        return urllib.parse.unquote(x).encode()
    def rot13(x):
        return codecs.decode(x, 'rot_13').encode()
    def rev(x):
        return x[::-1].encode()
    def binstr(x):
        t = re.sub(r'[^01]', '', x)
        if len(t) % 8: return b''
        return bytes(int(t[i:i+8], 2) for i in range(0, len(t), 8))
    def decstr(x):
        nums = re.findall(r'\d+', x)
        if len(nums) < 2: return b''
        try:
            vals = [int(n) for n in nums]
        except Exception:
            return b''
        if any(v < 0 or v > 255 for v in vals): return b''
        return bytes(vals)
    MORSE = {'.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G','....':'H',
             '..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N','---':'O','.--.':'P',
             '--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X',
             '-.--':'Y','--..':'Z','-----':'0','.----':'1','..---':'2','...--':'3','....-':'4',
             '.....':'5','-....':'6','--...':'7','---..':'8','----.':'9','..--..':'?','-.-.--':'!',
             '.-.-.-':'.','--..--':',','-..-.':'/','-...-':'=','.-.-.':'+','-....-':'-','..--.-':'_',
             '-.--.':'{','-.--.-':'}','-.--.':'{','.-..-.':'"','...-..-':'$','.--.-.':'@'}
    def morse(x):
        t = x.translate(str.maketrans({'－':'-','．':'.','。':'.','—':'-','–':'-','　':' ','／':'/'}))
        if not re.fullmatch(r'[.\-\s/]+', t): return b''
        res = []
        for w in t.split('/'):
            for c in w.split():
                res.append(MORSE.get(c, '?'))
            res.append(' ')
        return ''.join(res).strip().encode()
    def atbash(x):
        out = []
        for c in x:
            if 'A' <= c <= 'Z': out.append(chr(ord('Z') - (ord(c) - ord('A'))))
            elif 'a' <= c <= 'z': out.append(chr(ord('z') - (ord(c) - ord('a'))))
            else: out.append(c)
        return ''.join(out).encode()
    def bacon(x):
        t = re.sub(r'[^A-Za-z01]', '', x).upper()
        if len(t) < 10: return b''
        if set(t) <= set('AB'):
            bits = ''.join('0' if c == 'A' else '1' for c in t)
        elif set(t) <= set('01'):
            bits = t
        else:
            return b''
        bits = bits[:len(bits) // 5 * 5]
        out = []
        for i in range(0, len(bits), 5):
            v = int(bits[i:i+5], 2)
            out.append(chr(ord('A') + v) if v < 26 else '?')
        return ''.join(out).encode()
    def rail(n):
        def f(x):
            t = re.sub(r'\s', '', x)
            if len(t) < n * 2: return b''
            pat, r, d = [], 0, 1
            for _ in t:
                pat.append(r)
                if r == 0: d = 1
                elif r == n - 1: d = -1
                r += d
            counts = [pat.count(k) for k in range(n)]
            rows, idx = [], 0
            for c in counts:
                rows.append(list(t[idx:idx + c])); idx += c
            out = []
            for r in pat:
                out.append(rows[r].pop(0))
            return ''.join(out).encode()
        return f
    ZW = {'\u200b': '0', '\u200c': '1', '\u200d': '1', '\ufeff': '1', '\u2060': '1'}
    def zerowidth(x):
        bits = ''.join(ZW.get(c, '') for c in x)
        bits = bits[:len(bits) // 8 * 8]
        if len(bits) < 8: return b''
        return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
    def whitespace(x):
        bits = ''.join('0' if c == ' ' else ('1' if c == '\t' else '') for c in x)
        bits = bits[:len(bits) // 8 * 8]
        if len(bits) < 8: return b''
        return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
    def varselect(x):
        vals = []
        for c in x:
            o = ord(c)
            if 0xFE00 <= o <= 0xFE0F: vals.append(o - 0xFE00)       # 4 bit
            elif 0xE0100 <= o <= 0xE01EF: vals.append(o - 0xE0100)   # 8 bit
        if not vals: return b''
        # 统一按 8bit 尝试：4bit 的两个拼一个字节
        if max(vals) <= 15:
            bits = ''.join(format(v, '04b') for v in vals)
            bits = bits[:len(bits) // 8 * 8]
            return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8)) if bits else b''
        return bytes(v & 0xFF for v in vals)
    def brainfuck(x):
        code = ''.join(c for c in x if c in '><+-.,[]')
        if len(code) < 20 or len(code) / max(1, len(x)) < 0.8: return b''
        mem = [0] * 30000; ptr = 0; out = bytearray(); pc = 0
        stack = []; jump = {}
        for i, c in enumerate(code):
            if c == '[': stack.append(i)
            elif c == ']':
                if not stack: return b''
                j = stack.pop(); jump[j] = i; jump[i] = j
        steps = 0
        while pc < len(code):
            steps += 1
            if steps > 200000: return b''
            c = code[pc]
            if c == '>': ptr = min(29999, ptr + 1)
            elif c == '<': ptr = max(0, ptr - 1)
            elif c == '+': mem[ptr] = (mem[ptr] + 1) & 0xFF
            elif c == '-': mem[ptr] = (mem[ptr] - 1) & 0xFF
            elif c == '.': out.append(mem[ptr])
            elif c == '[' and mem[ptr] == 0: pc = jump[pc]
            elif c == ']' and mem[ptr] != 0: pc = jump[pc]
            pc += 1
        return bytes(out)
    ROWS = ['`1234567890-=', 'qwertyuiop[]\\', "asdfghjkl;'", 'zxcvbnm,./']
    def kbshift(dx, dy):
        def f(x):
            out = []
            for c in x:
                low = c.lower(); hit = False
                for r, row in enumerate(ROWS):
                    if low in row:
                        nr, ni = r + dy, row.index(low) + dx
                        if 0 <= nr < len(ROWS) and 0 <= ni < len(ROWS[nr]):
                            nc = ROWS[nr][ni]
                            out.append(nc.upper() if c.isupper() else nc)
                        else: out.append(c)
                        hit = True; break
                if not hit: out.append(c)
            return ''.join(out).encode()
        return f
    def dna_goldman(x):
        # Goldman 2013：相邻碱基查旋转表 -> 三进制位，6 位 -> 1 字节
        runs = re.findall(r'[ACGT]{24,}', x.upper())
        if not runs:
            return b''
        t = max(runs, key=len)
        idx = {'A': 0, 'C': 1, 'G': 2, 'T': 3}
        trits = [(idx[b] - idx[a] - 1) % 4 for a, b in zip(t, t[1:])]
        out = bytearray()
        for i in range(0, len(trits) - 5, 6):
            v = 0
            for d in trits[i:i + 6]:
                v = v * 3 + d
            out.append(v & 0xFF)
        return bytes(out)
    def dna_2bit(x):
        # A=00 C=01 G=10 T=11，4 个碱基 -> 1 字节
        runs = re.findall(r'[ACGT]{16,}', x.upper())
        if not runs:
            return b''
        t = max(runs, key=len)
        bits = ''.join({'A': '00', 'C': '01', 'G': '10', 'T': '11'}[c] for c in t)
        bits = bits[:len(bits) // 8 * 8]
        return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
    def dna_base4(x):
        runs = re.findall(r'[ACGT]{24,}', x.upper())
        if not runs:
            return b''
        t = max(runs, key=len)
        v = 0
        for c in t:
            v = v * 4 + {'A': 0, 'C': 1, 'G': 2, 'T': 3}[c]
        return v.to_bytes((v.bit_length() + 7) // 8, 'big') if v else b''
    def kbmirror(x):
        m = {}
        for row in ROWS:
            for i, c in enumerate(row): m[c] = row[len(row) - 1 - i]
        return ''.join((m.get(c.lower(), c).upper() if c.isupper() else m.get(c, c)) for c in x).encode()
    out = [('Base64', b64), ('Base64URL', b64url), ('Base32', b32), ('Hex', b16),
           ('Base58', b58), ('Base85', b85), ('Base85-Ascii85', a85),
           ('URL编码', uenc), ('二进制串', binstr), ('十进制ASCII', decstr),
           ('摩斯电码', morse), ('Atbash', atbash), ('Bacon', bacon),
           ('零宽字符', zerowidth), ('空白字符', whitespace), ('变体选择符', varselect),
           ('Brainfuck', brainfuck), ('DNA-Goldman', dna_goldman),
           ('DNA-2bit', dna_2bit), ('DNA-base4', dna_base4)]
    for n in range(2, 13):
        out.append(('栅栏%d栏' % n, rail(n)))
    for nm, dx, dy in (('左移一格', -1, 0), ('右移一格', 1, 0), ('上移一行', 0, -1), ('下移一行', 0, 1),
                       ('左上', -1, -1), ('右上', 1, -1), ('左下', -1, 1), ('右下', 1, 1)):
        out.append(('键盘' + nm, kbshift(dx, dy)))
    out.append(('键盘镜像', kbmirror))
    if allow_rot13 and (s.isalpha() or ' ' in s):
        out.append(('ROT13', rot13))
    out.append(('反转', rev))
    return out

def _texty(b):
    if not b or len(b) < 2:
        return None
    try:
        t = b.decode('utf-8')
    except UnicodeDecodeError:
        return None
    if not t.strip():
        return None
    ok = sum(1 for ch in t if 32 <= ord(ch) < 127 or '\u4e00' <= ch <= '\u9fff' or ch in '\r\n\t')
    return t if ok / len(t) > 0.95 else None

def decode_chain(s, max_rounds=6):
    """自动多层解码（BFS：每一层所有候选都扫 flag，避免选错路）"""
    head('编码链自动解码 (最多套 6 层)')
    start = s if s.strip() else s   # 保留首尾空白：空白字符隐写需要原始长度
    frontier = [(None, start)]
    seen = {start}
    found = False

    def score(item):
        name, t = item
        sc = 0
        if '{' in t and '}' in t: sc += 100
        low = t.lower()
        if 'flag' in low or 'c404' in low: sc += 50
        if t.strip() and sum(1 for ch in t[:200] if 32 <= ord(ch) < 127 or ch in '\r\n\t') / min(200, len(t)) > 0.95: sc += 5
        return sc

    for r in range(1, max_rounds + 1):
        nxt = []
        for _, cur in frontier:
            for name, fn in _decoders(cur, allow_rot13=(r == 1)):
                try:
                    b = fn(cur)
                except Exception:
                    continue
                t = _texty(b)
                if not t:
                    continue
                t = t.strip()
                if not t or t == cur.strip() or t in seen:
                    continue
                seen.add(t)
                final = _is_final_flag(t)
                if not final:
                    nxt.append((name, t))
                try:
                    scan_flags(t, '编码链%d层:%s' % (r, name))
                    if not any(c.islower() for c in t):
                        scan_flags(t.lower(), '编码链%d层:%s(小写)' % (r, name))
                except Exception:
                    pass
                if final:
                    found = True
        if not nxt:
            note('第 %d 层: 没有能再解的了' % r)
            break
        nxt.sort(key=lambda x: -score(x))
        # 展示本层最像结果的几个
        for i, (n, v) in enumerate(nxt[:6], 1):
            note('  第%d层[%d] %-12s -> %s' % (r, i, n, v[:90]))
        if len(nxt) > 20:
            note('  ...（本层共 %d 个候选，只保留最像的 20 个继续）' % len(nxt))
        frontier = nxt[:20]
    if found:
        note('★ 编码链里出现了带花括号的结果，见上面的 flag 列表')
    why('一层层解，每层都把所有可能解码列出来并扫一遍 flag —— 多数字符串题就是编码套娃')
def _l2b(n):
    if n == 0:
        return b'\x00'
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

def rsa_analyze(text, path=None):
    """自动识别 RSA 参数，能算的算，算不了的交给 RsaCtfTool 全攻击"""
    if _RSA_DONE[0]:
        return
    vals = {}
    for name in ('n', 'e', 'c', 'p', 'q', 'd', 'dp', 'dq', 'phi'):
        m = re.search(r'(?i)(?:^|[^a-zA-Z0-9_])%s\s*[:=]\s*([0-9]{2,})' % name, text)
        if m:
            vals[name] = m.group(1)
    is_pem = path and os.path.splitext(path)[1].lower() in ('.pem', '.pub', '.key', '.crt')
    # 严格触发：必须至少两个带标签的参数（n=… e=…），或者是公钥文件。
    # 不再用"一堆大数字"瞎猜 —— 那会在二进制/仓库里反复误触发，拖慢整轮分析。
    if not is_pem and len(vals) < 2:
        return
    _RSA_DONE[0] = True
    note('（识别到 RSA 参数: %s）' % ', '.join(sorted(vals.keys())))
    head('RSA 分析')

    # ---- 已知 p/q/e/c 直接算 ----
    if all(k in vals for k in ('p', 'q', 'e')):
        try:
            p, q, e = int(vals['p']), int(vals['q']), int(vals['e'])
            n = p * q
            d = pow(e, -1, (p - 1) * (q - 1))
            note('已知 p/q/e → 算出私钥 d')
            if 'c' in vals:
                m = pow(int(vals['c']), d, n)
                note('★ 解密结果: ' + repr(_l2b(m)))
                try:
                    t = _l2b(m).decode('utf-8')
                    note('★ 当文本读: ' + t)
                    scan_flags(t, 'RSA直接解密')
                    add_result(t, 'RSA直接解密')
                except Exception:
                    pass
            return
        except Exception as e:
            note('直接计算失败: %s' % e)

    # ---- 交给 RsaCtfTool 全攻击 ----
    base = [sys.executable, '-m', 'RsaCtfTool']
    args = []
    if is_pem and path:
        args += ['--publickey', path]
    else:
        if 'n' in vals:
            args += ['--n', vals['n']]
        if 'e' in vals:
            args += ['--e', vals['e']]
        if 'p' in vals and 'q' in vals:
            args += ['--p', vals['p'], '--q', vals['q']]
        if 'c' in vals:
            args += ['--uncipher', vals['c']]
    if not args:
        note('没提取到足够的 RSA 参数')
        suggest('RSA 题：把 n/e/c（或公钥文件）单独存成文件，再丢给插件')
        return
    if '--uncipher' not in args and '--publickey' not in args:
        args += ['--private']
    args += ['--timeout', '45', '--attack', 'all']
    note('调用 RsaCtfTool 全攻击（低指数/共模/维纳/费马/分解...）')
    note('  参数: ' + ' '.join(args[:6]) + (' ...' if len(args) > 6 else ''))
    o = run(base + args, timeout=240)
    keep = []
    for line in o.splitlines():
        if re.search(r'(?i)private key|results|attack success|n =|e =|d =|p =|q =|b\'|bytes|flag|C404|\{', line):
            keep.append(line.strip())
    if keep:
        note('RsaCtfTool 输出（关键行）:')
        for l in keep[:20]:
            note('   ' + l[:150])
        scan_flags(o, 'RsaCtfTool')
        scan_base64_blobs(o, 'RsaCtfTool')
    else:
        note('RsaCtfTool 没有明显输出（前 300 字）:')
        for l in o.splitlines()[:8]:
            note('   ' + l[:140])
    why('RSA 的常见攻击: e 很小(低指数)、同一个 n 多组密文(共模)、d 很小(维纳)、'
        'p/q 接近(费马)、n 能被小素数整除。RsaCtfTool 会把这些全试一遍')

def vigenere_break(ct):
    """维吉尼亚自动破译：用重合指数(IC)猜密钥长度，用卡方检验猜每个移位"""
    from collections import Counter
    EN = [0.08167,0.01492,0.02782,0.04253,0.12702,0.02228,0.02015,0.06094,0.06966,0.00153,
          0.00772,0.04025,0.02406,0.06749,0.07507,0.01929,0.00095,0.05987,0.06327,0.09056,
          0.02758,0.00978,0.02360,0.00150,0.01974,0.00074]
    letters = [ch.lower() for ch in ct if ch.isalpha()]
    if len(letters) < 40:
        return None

    def ic(seq):
        n = len(seq)
        if n < 2:
            return 0.0
        f = Counter(seq)
        return sum(v * (v - 1) for v in f.values()) / (n * (n - 1))

    base_ic = ic(letters)
    if base_ic > 0.055:
        return None          # 本来就接近英文，可能不是维吉尼亚
    best_len, best_sc = 1, -1.0
    for L in range(2, 21):
        if len(letters) < L * 12:
            break
        cols = [letters[i::L] for i in range(L)]
        avg = sum(ic(c) for c in cols) / L
        if avg > best_sc:
            best_sc, best_len = avg, L
    if best_len < 2:
        return None
    key = []
    for i in range(best_len):
        col = letters[i::best_len]
        best, bs = 0, 1e18
        for s in range(26):
            cnt = [0] * 26
            for ch in col:
                cnt[(ord(ch) - 97 - s) % 26] += 1
            n = len(col)
            chi = sum((cnt[j] - EN[j] * n) ** 2 / (EN[j] * n + 1e-9) for j in range(26))
            if chi < bs:
                bs, best = chi, s
        key.append(chr(best + 97))
    key = ''.join(key)
    out, ki = [], 0
    for ch in ct:
        if ch.isalpha():
            b = 97 if ch.islower() else 65
            out.append(chr((ord(ch) - b - (ord(key[ki % len(key)]) - 97)) % 26 + b))
            ki += 1
        else:
            out.append(ch)
    return key, ''.join(out)

def try_vigenere(text):
    """只在文本像长串字母时试维吉尼亚；如果题目给了 key，就直接用"""
    if _VIG_DONE[0]:
        return
    _km = re.search(r'(?:key|密钥|key\s*is)\s*[:：=]?\s*([A-Za-z]{2,20})', text, re.I)
    if _km:
        _key = _km.group(1).upper()
        _out = []
        _j = 0
        for _c in text:
            if _c.isalpha():
                _out.append(chr((ord(_c.upper()) - 65 - (ord(_key[_j % len(_key)]) - 65)) % 26 + 65))
                _j += 1
            else:
                _out.append(_c)
        _plain = ''.join(_out)
        note('★ 文本里给了维吉尼亚密钥 %s，直接解密' % _key)
        note('   -> %s' % _plain[:160])
        scan_flags(_plain, '维吉尼亚(题目给key)')
        scan_flags(_plain.lower(), '维吉尼亚(题目给key,小写)')
        add_result(_plain[:200], '维吉尼亚(密钥=%s)' % _key)
        _VIG_DONE[0] = True
        return
    letters = sum(1 for ch in text if ch.isalpha())
    if letters < 60 or letters / max(1, len(text)) < 0.6:
        return
    head('维吉尼亚自动破译（统计法猜密钥）')
    r = vigenere_break(text)
    if not r:
        note('不符合维吉尼亚特征（或者太短），跳过')
        return
    _VIG_DONE[0] = True
    key, plain = r
    note('★ 猜出密钥: %s' % key)
    note('★ 解密结果: %s' % plain[:200])
    scan_flags(plain, '维吉尼亚')
    add_result(plain[:200], '维吉尼亚(密钥=%s)' % key)
    why('维吉尼亚的破法: 先用"重合指数"猜密钥长度，再用"卡方检验"逐位猜移位。'
        '密钥长度 < 20、密文够长时基本必中')

def caesar_bruteforce(s, limit=26):
    if _is_final_flag(s):
        return
    head('凯撒密码暴力破解 (26 种位移全试)')
    best = []
    for sh in range(limit):
        out = []
        for ch in s:
            if 'a' <= ch <= 'z':
                out.append(chr((ord(ch) - 97 + sh) % 26 + 97))
            elif 'A' <= ch <= 'Z':
                out.append(chr((ord(ch) - 65 + sh) % 26 + 65))
            else:
                out.append(ch)
        t = ''.join(out)
        if '{' in t and '}' in t:
            _pre = t.split('{')[0].lower()
            if _pre not in KNOWN_PREFIX and not (sh == 0 and plausible_flag(t)):
                continue
            scan_flags(t, '凯撒 位移%d' % sh)
            note('★ 位移 %-2d -> %s' % (sh, t[:100]))
            best.append(t)
    if not best:
        note('26 种位移里没有看到花括号, 列出前 5 种看看:')
        for sh in range(5):
            out = ''.join(chr((ord(c) - 97 + sh) % 26 + 97) if 'a' <= c <= 'z' else c for c in s)
            note('  位移 %-2d -> %s' % (sh, out[:80]))
    else:
        note('(小结: 凯撒就是把字母表整体平移, 试 26 次总能试出来)')

def xor_bruteforce(data):
    if isinstance(data, str) and _is_final_flag(data):
        return
    head('异或 (XOR) 暴力破解')
    raw = data if isinstance(data, bytes) else data.encode('utf-8', 'ignore')
    if not raw:
        return
    note('数据长度 %d 字节' % len(raw))
    # 单字节
    scored = []
    printable = set(bytes(string.printable, 'ascii'))
    letters = set(b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ')
    for k in range(256):
        x = bytes(b ^ k for b in raw)
        pr = sum(1 for c in x if c in printable) / len(x)
        lr = sum(1 for c in x if c in letters) / len(x)
        p = pr * 2 + lr
        try:
            sx = x.decode('utf-8')
        except UnicodeDecodeError:
            sx = x.decode('latin-1')
        if FLAG_RE.search(sx):
            p += 8
        low = sx.lower()
        if 'flag' in low or 'ctf' in low:
            p += 4
        scored.append((p, k, x, sx))
    scored.sort(reverse=True, key=lambda z: z[0])
    for p, k, x, sx in scored[:6]:
        note('  密钥 0x%02x (%3d) 匹配度 %.2f -> %s' % (k, k, p, re.sub(r'[\x00-\x1f]', '.', sx)[:90]))
    _topk = set(z[1] for z in scored[:8])
    for p, k, x, sx in scored:
        low = sx.lower()
        if 'flag' in low or 'ctf' in low:
            scan_flags(sx, 'XOR单字节 0x%02x' % k)
        elif len(raw) <= 2048 and k in _topk:
            scan_flags(sx, 'XOR单字节 0x%02x' % k)
    # ---- 已知明文 crib drag：假设开头是 C404{ / flag{ / ctf{ ----
    crib_found = False
    for crib in (b'C404{', b'flag{', b'ctf{', b'FLAG{'):
        for off in range(0, min(64, max(1, len(raw) - len(crib) + 1))):
            key = bytes(raw[off + i] ^ crib[i] for i in range(len(crib)))
            # 检查这个 key 是否以 <=32 的周期重复
            for klen in range(1, min(33, len(key) + 1)):
                if all(key[i] == key[i % klen] for i in range(len(key))):
                    kk = key[:klen]
                    dec = bytes(b ^ kk[i % klen] for i, b in enumerate(raw))
                    try:
                        s2 = dec.decode('utf-8')
                    except UnicodeDecodeError:
                        continue
                    if sum(1 for c in s2 if c in string.printable) / max(1, len(s2)) > 0.9:
                        note('  ★ crib-drag: 明文偏移 %d 像 %r, 推出重复密钥 %r (len=%d)' % (off, crib, kk, klen))
                        note('     -> %s' % s2[:120])
                        scan_flags(s2, 'XOR-crib')
                        save('xor_crib.txt', dec)
                        crib_found = True
                        break
            if crib_found: break
        if crib_found: break
    if crib_found:
        note('  （crib-drag 已解出，跳过后面的统计猜密钥）')
        why('已知明文攻击：如果你猜明文开头是 C404{，密文 XOR 明文 = 密钥；再验证密钥是否循环')
        return

    # 重复密钥 (猜长度 2..12)
    found = False
    for klen in range(2, 13):
        if len(raw) < klen * 8:
            continue
        # 用频率法猜每个位置的密钥字节
        key = bytearray()
        for i in range(klen):
            col = raw[i::klen]
            bestk, bestsc = 0, -1
            for k in range(256):
                x = bytes(b ^ k for b in col)
                p = sum(1 for c in x if c in printable) / max(1, len(x))
                if p > bestsc:
                    bestsc, bestk = p, k
            key.append(bestk)
        dec = bytes(b ^ key[i % klen] for i, b in enumerate(raw))
        try:
            s = dec.decode('utf-8')
        except UnicodeDecodeError:
            continue
        if any(ch in s for ch in '{}') and sum(1 for c in s if c in string.printable) / len(s) > 0.9:
            note('  ★ 重复密钥长度 %d, 密钥 = %r' % (klen, bytes(key)))
            note('     -> %s' % s[:120])
            scan_flags(s, 'XOR重复密钥 len=%d' % klen)
            save('xor_key%d.txt' % klen, dec)
            found = True
            break
    if not found:
        note('  重复密钥没找到明显的 flag (先看上面单字节的结果)')
    why('异或就是把每个字节和一个密钥做 XOR。单字节只有 256 种可能, 全试; '
        '重复密钥先用"哪个值让这一列最像正常文字"来猜')

def hash_analyze(s):
    head('哈希识别 + 爆破')
    hits = re.findall(r'\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b|\b[0-9a-fA-F]{128}\b', s)
    if not hits:
        # 也许整个输入就是一个哈希
        t = s.strip()
        if re.fullmatch(r'[0-9a-fA-F]+', t) and len(t) in (32, 40, 64, 96, 128):
            hits = [t]
    if not hits:
        note('没发现哈希值 (长度 32/40/64/96/128 的十六进制串)')
        return
    ALGO = {32: 'md5', 40: 'sha1', 64: 'sha256', 96: 'sha384', 128: 'sha512'}
    dic = []
    for f in ('pass-top10000.txt', 'pass-xato-10000.txt', 'pass-shortlist.txt',
              'pass-2025-top200.txt', 'user-shortlist.txt'):
        p = os.path.join(ROOT, '07-字典', f)
        if os.path.isfile(p):
            dic.append(p)
    for h in set(hits):
        algo = ALGO.get(len(h))
        if not algo:
            continue
        note('发现 %s: %s' % (algo.upper(), h))
        fn = getattr(hashlib, algo)
        common = ['123456','password','admin','123456789','12345678','qwerty','abc123','111111',
                  '123123','admin123','root','letmein','iloveyou','welcome','monkey','flag','test',
                  'guest','666666','888888','000000','1234','12345','password1','passw0rd','hello']
        got = None
        for w in common:
            for c in (w, w.capitalize(), w.upper()):
                if fn(c.encode()).hexdigest() == h.lower():
                    got = c; break
            if got: break
        if not got:
            for p in dic:
                try:
                    with open(p, encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            w = line.strip()
                            if w and fn(w.encode('utf-8', 'ignore')).hexdigest() == h.lower():
                                got = w; break
                except Exception:
                    continue
                if got: break
        if got:
            note('  ★ 爆破成功! 明文 = %s' % got)
            scan_flags(got, '哈希明文')
            add_result(got, '哈希明文(%s)' % algo.upper())
        else:
            note('  字典里没找到 (可以试 cmd5.com / crackstation.net 在线查)')
    why('哈希是单向的, 只能拿字典一个个试。MD5 32位、SHA1 40位、SHA256 64位')

def jwt_analyze(s):
    if not re.search(r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.', s):
        return
    head('JWT (登录令牌) 解析')
    for m in re.finditer(r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*', s):
        parts = m.group(0).split('.')
        note('原始: ' + m.group(0)[:120])
        for i, nm in enumerate(('头部', '载荷', '签名')):
            if i >= len(parts) or not parts[i]:
                continue
            try:
                d = base64.urlsafe_b64decode(parts[i] + '=' * (-len(parts[i]) % 4))
                note('  %s = %s' % (nm, d.decode('utf-8', 'replace')[:200]))
            except Exception:
                pass
        note('  (JWT 常考: 把 alg 改成 none、弱密钥爆破、还有 jwt.io 直接看)')
        why('JWT 是 base64 拼的, 不是加密。改内容不加签名就能骗过没校验的服务器')
# ============================================================
#                    图 片 类 分 析
# ============================================================
def _imread(path):
    """读图片（用 np.fromfile 避免中文路径问题；先看文件头，非图片直接返回 None）"""
    import numpy as np
    try:
        with open(path, 'rb') as _f:
            _h = _f.read(16)
    except Exception:
        return None
    if not any(_h.startswith(_x) for _x in (b'\x89PNG', b'\xff\xd8\xff', b'GIF8', b'BM', b'RIFF',
                                            b'\x00\x00\x01\x00', b'II*\x00', b'MM\x00*')):
        return None
    import cv2
    buf = np.fromfile(path, dtype=np.uint8)
    return cv2.imdecode(buf, cv2.IMREAD_UNCHANGED)

def png_try_fix(path, data):
    """PNG 宽高被改过时：反推真实尺寸并生成修复版（返回修复版路径，不需要修就返回 None）"""
    import struct, zlib
    if not data.startswith(b'\x89PNG'):
        return None
    pos, ihdr, idat, crc_bad, segs = 8, None, b'', False, []
    while pos + 12 <= len(data):
        ln = struct.unpack('>I', data[pos:pos+4])[0]
        typ = data[pos+4:pos+8]
        body = data[pos+8:pos+8+ln]
        stored = data[pos+8+ln:pos+12+ln]
        calc = struct.pack('>I', zlib.crc32(typ + body) & 0xFFFFFFFF)
        if stored != calc and typ == b'IHDR':
            crc_bad = True
        segs.append((typ, body))
        if typ == b'IHDR':
            ihdr = struct.unpack('>IIBBBBB', body)
        elif typ == b'IDAT':
            idat += body
        elif typ == b'IEND':
            break
        pos += 12 + ln
    if not crc_bad or not ihdr:
        return None
    w0, h0, bd, ct, comp, filt, inter = ihdr
    CH = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(ct, 1)
    try:
        raw = zlib.decompress(idat)
    except Exception:
        note('  IDAT 解不开，无法反推尺寸')
        return None
    cands = []
    stride = 1 + (w0 * CH * bd + 7) // 8
    if stride and len(raw) % stride == 0:
        cands.append((w0, len(raw) // stride))
    for hh in range(1, 6001):
        need = len(raw) // hh
        for ww in (need - 1, need, need + 1):
            if ww < 8:
                continue
            s = 1 + (ww * CH * bd + 7) // 8
            if hh * s == len(raw) and (ww, hh) not in cands:
                cands.append((ww, hh))
    if not cands:
        note('  反推不出真实尺寸')
        return None
    note('  ★ IHDR 的 CRC 不对 → 宽高被改过！')
    note('  声明 %d x %d，但数据量对应不上' % (w0, h0))
    note('  可能的真实尺寸（前 6 个）: ' + ', '.join('%dx%d' % t for t in cands[:6]))
    outs = []
    base = os.path.splitext(os.path.basename(path))[0]
    for i, (w1, h1) in enumerate(cands[:6], 1):
        buf = bytearray(b'\x89PNG\r\n\x1a\n')
        for typ, body in segs:
            if typ == b'IHDR':
                body = struct.pack('>IIBBBBB', w1, h1, bd, ct, comp, filt, inter)
            buf += struct.pack('>I', len(body)) + typ + body + struct.pack('>I', zlib.crc32(typ + body) & 0xFFFFFFFF)
        fp = outpath('%s_修复版%d_%dx%d.png' % (base, i, w1, h1))
        with open(fp, 'wb') as fh:
            fh.write(bytes(buf))
        outs.append(fp)
        note('     修复版%d: %d x %d -> %s' % (i, w1, h1, fp))
    add_result('真实尺寸可能是: ' + ', '.join('%dx%d' % t for t in cands[:6]), 'PNG宽高还原')
    suggest('★★ 打开修复版图片，看被裁掉的下半部分: ' + outs[0])
    suggest('    出题人常把 flag 藏在被裁掉的那一截里 —— 图里能看到就直接抄')
    why('出题人把高度改小 = 把图底部裁掉。PNG 每块都有 CRC 校验，改了宽高却没重算 CRC 就露馅了')
    return outs[0] if outs else None


def png_structure(path, data):
    """PNG 结构检查 + 宽高篡改暴力还原"""
    import struct, zlib
    head('PNG 结构检查（宽高有没有被改）')
    if not data.startswith(b'\x89PNG\r\n\x1a\n'):
        return None
    pos = 8
    ihdr = None
    idat = b''
    chunks = []
    try:
        while pos < len(data):
            ln = struct.unpack('>I', data[pos:pos+4])[0]
            typ = data[pos+4:pos+8]
            body = data[pos+8:pos+8+ln]
            crc = data[pos+8+ln:pos+12+ln]
            chunks.append((typ.decode('latin-1'), ln))
            want = zlib.crc32(typ + body) & 0xFFFFFFFF
            bad = (crc != struct.pack('>I', want)) if len(crc) == 4 else True
            if typ == b'IHDR':
                ihdr = struct.unpack('>IIBBBBB', body)
                w, h, bd, ct = ihdr[0], ihdr[1], ihdr[2], ihdr[3]
                note('声明的宽高 = %d x %d, 位深 = %d, 颜色类型 = %d' % (w, h, bd, ct))
                if bad:
                    note('  ⚠ IHDR 的 CRC 校验不通过 —— 宽高被改过！')
            elif typ in (b'tEXt', b'zTXt', b'iTXt'):
                try:
                    txt = body.decode('latin-1', 'replace')
                    note('  [PNG文本块 %s] %s' % (typ.decode(), txt[:200]))
                    scan_flags(txt, 'PNG文本块')
                    scan_base64_blobs(txt, 'PNG文本块')
                except Exception:
                    pass
            elif typ == b'IDAT':
                idat += body
            elif typ == b'IEND':
                break
            pos += 12 + ln
        note('分块: ' + ', '.join('%s(%d)' % c for c in chunks[:12]))
    except Exception as e:
        note('解析出错: %s' % e)
        return None
    if not ihdr or not idat:
        return None
    try:
        raw = zlib.decompress(idat)
    except Exception as e:
        note('IDAT 解压失败: %s' % e)
        return None
    bd, ct = ihdr[2], ihdr[3]
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(ct, 1)
    bpp = max(1, channels * bd // 8)
    note('解压后原始数据 = %d 字节' % len(raw))
    w0, h0 = ihdr[0], ihdr[1]
    stride = 1 + (w0 * channels * bd + 7) // 8
    if h0 * stride == len(raw):
        note('  数据长度和声明的宽高一致 —— 宽高没被改')
        return None
    note('  ⚠ 数据长度对不上！正在暴力推算真实宽高...')
    cands = []
    for h in range(1, 4001):
        need = len(raw) / h
        wi = int(need)
        if wi < 1 or wi > 8000:
            continue
        for w in range(max(1, wi - 2), wi + 3):
            s = 1 + (w * channels * bd + 7) // 8
            if h * s == len(raw):
                cands.append((w, h))
    if cands:
        note('  ★ 可能的真实宽高 (前 10 个):')
        for w, h in cands[:10]:
            note('      %d x %d' % (w, h))
        scan_flags('%d x %d' % (w0, h0), 'png尺寸')
        note('')
        note('★ 正在用推算出的宽高重建图片...')
        fixed = []
        for (cw, chh) in cands[:3]:
            fp = png_rebuild(path, data, cw, chh, 'auto')
            if fp:
                note('   已生成可打开的图: %s' % fp)
                fixed.append(fp)
        return fixed if fixed else cands[0]
    note('  没推算出来（试试用 ImHex 手动看 IHDR）')
    return None

def lsb_deep(path, arr):
    """LSB 深度提取：多种读取顺序 + 位序，尽量不漏"""
    import numpy as np
    if arr.ndim == 2:
        arr = arr[:, :, None]
    h, w, cc = arr.shape
    variants = []
    if cc >= 3:
        variants.append(('通道顺序RGB', np.concatenate([(arr[:, :, i] & 1).flatten() for i in (0, 1, 2)])))
        variants.append(('通道顺序BGR', np.concatenate([(arr[:, :, i] & 1).flatten() for i in (2, 1, 0)])))
        variants.append(('逐像素顺序', (arr[:, :, :3] & 1).flatten()))
        variants.append(('逐像素反序', (arr[:, :, [2, 1, 0]] & 1).flatten()))
    for i, nm in enumerate('RGBA'[:cc]):
        variants.append(('仅%s通道' % nm, (arr[:, :, i] & 1).flatten()))
    hit = False
    for name, bits in variants:
        if len(bits) < 64:
            continue
        for order in ('big', 'little'):
            try:
                by = np.packbits(bits.astype('uint8'), bitorder=order).tobytes()
            except Exception:
                continue
            txt = ''.join(chr(b) if 32 <= b < 127 or b in (10, 13) else '.' for b in by)
            # 关键：整段可打印率低 → 是随机噪声，直接丢弃，不做"抹点拼接"（那会凭空造出假 flag）
            # 只看"开头一段"像不像正常文字：真 payload 总在开头，照片的随机 LSB 开头就是乱的
            head_txt = txt[:400]
            low = txt.lower()
            head_ok = head_txt.count('.') / max(1, len(head_txt)) <= 0.1
            if not head_ok and 'flag' not in low and 'ctf' not in low:
                continue
            scan_flags(txt, 'LSB深度:' + name)
            scan_base64_blobs(head_txt, 'LSB深度:' + name)
            if not hit and ('flag' in txt.lower() or 'ctf' in txt.lower()):
                i2 = txt.lower().find('flag')
                if i2 < 0:
                    i2 = txt.lower().find('ctf')
                note('  ★ LSB深度(%s/%s) 有内容: %s' % (name, order, txt[max(0, i2-10):i2+70]))
                hit = True
    return hit
def qr_scan_all(path, label='二维码'):
    """把图当二维码全方位试一遍（结果记进全局 flag 表）"""
    found = []
    try:
        import cv2
        base = _imread(path)
        if base is None:
            return found
        # QRCodeDetector 在数兆像素噪声图上会长时间扫不动。先生成缩略图，
        # 二维码本身有冗余，整体缩小后通常仍可解码。
        _pixels = int(base.shape[0] * base.shape[1])
        if _pixels > 500000:
            note('  二维码扫描：原图过大（%d 像素），跳过自动多方向扫描，改用 tools\\qr.py 手工处理' % _pixels)
            diag('qr', 'skipped', '跳过大图自动 QR 扫描',
                 why='十六种旋转/缩放组合在超大噪声图上耗时过高',
                 assumption='如果图里确实有二维码，手工裁局部再扫更可靠',
                 evidence='%d pixels' % _pixels, next_action='打开图片裁出二维码区域，或运行 tools\\qr.py')
            return found
        if _pixels > 250000:
            import math as _m
            _scale = _m.sqrt(250000.0 / _pixels)
            _nh = max(32, int(base.shape[0] * _scale))
            _nw = max(32, int(base.shape[1] * _scale))
            base = cv2.resize(base, (_nw, _nh), interpolation=cv2.INTER_AREA)
            note('  二维码扫描：大图 %d 像素 -> 缩略到 %dx%d 再试' % (_pixels, _nw, _nh))
            diag('qr', 'guarded', '大图 QR 扫描降采样',
                 why='QR 检测器在超大噪声图上可能长时间占用 CPU',
                 assumption='二维码通常仍能在缩略图中保留结构；失败则手工裁局部',
                 evidence='%d pixels -> %dx%d' % (_pixels, _nw, _nh), confidence='medium')
        tries = [('原图', base)]
        try:
            tries.append(('反色', 255 - base))
            g = cv2.cvtColor(base, cv2.COLOR_BGR2GRAY)
            tries.append(('灰度', cv2.cvtColor(g, cv2.COLOR_GRAY2BGR)))
            tries.append(('灰度反色', 255 - cv2.cvtColor(g, cv2.COLOR_GRAY2BGR)))
        except Exception:
            pass
        _base = list(tries)
        for _nm, _im in _base:
            try:
                tries.append((_nm + '+转90', cv2.rotate(_im, cv2.ROTATE_90_CLOCKWISE)))
                tries.append((_nm + '+转180', cv2.rotate(_im, cv2.ROTATE_180)))
                tries.append((_nm + '+转270', cv2.rotate(_im, cv2.ROTATE_90_COUNTERCLOCKWISE)))
                tries.append((_nm + '+翻转', cv2.flip(_im, 1)))
            except Exception:
                pass
        det = cv2.QRCodeDetector()
        for nm, im in tries:
            for scale in (1, 2):
                try:
                    im2 = cv2.resize(im, None, fx=scale, fy=scale, interpolation=cv2.INTER_NEAREST) if scale > 1 else im
                except Exception:
                    continue
                vals = []
                try:
                    ok, dec, _, _ = det.detectAndDecodeMulti(im2)
                    vals = [x for x in (dec or []) if x]
                except Exception:
                    vals = []
                if not vals:
                    try:
                        one = det.detectAndDecode(im2)[0]
                        vals = [one] if one else []
                    except Exception:
                        vals = []
                for v in vals:
                    if v not in found:
                        found.append(v)
                        note('  ★ [%s x%d] 扫出来了: %s' % (nm, scale, v))
                        add_flag(v, label)
    except Exception as e:
        note('二维码识别出错: %s' % e)
    return found


# ---------------- 图像增强：真修复 / 通道分离 / 分帧 / 隐写特征 ----------------
def png_rebuild(path, data, w, h, tag='fix'):
    """用指定宽高重建 PNG（并修正 IHDR 的 CRC），得到一张能正常打开的图"""
    import struct, zlib
    if not data.startswith(b'\x89PNG\r\n\x1a\n'):
        return None
    pos, out = 8, bytearray(b'\x89PNG\r\n\x1a\n')
    while pos < len(data):
        try:
            ln = struct.unpack('>I', data[pos:pos+4])[0]
        except Exception:
            break
        typ = data[pos+4:pos+8]
        body = data[pos+8:pos+8+ln]
        if typ == b'IHDR':
            nb = struct.pack('>IIBBBBB', w, h, body[8], body[9], body[10], body[11], body[12])
            crc = zlib.crc32(b'IHDR' + nb) & 0xFFFFFFFF
            out += struct.pack('>I', len(nb)) + b'IHDR' + nb + struct.pack('>I', crc)
        else:
            out += struct.pack('>I', ln) + typ + body + data[pos+8+ln:pos+12+ln]
        if typ == b'IEND':
            break
        pos += 12 + ln
    p = outpath('修复_%dx%d_%s.png' % (w, h, tag))
    with open(p, 'wb') as fh:
        fh.write(bytes(out))
    return p

def channel_split(path, arr):
    """把 R/G/B/A 各通道拆出来，并做差分/异或 —— StegSolve 的核心玩法"""
    import numpy as np
    from PIL import Image
    made = []
    h, w, cc = arr.shape
    nm_ch = 'BGRA'[:cc]          # cv2 解码出来是 BGR
    for i in range(cc):
        p = outpath('通道_%s.png' % nm_ch[i])
        Image.fromarray(arr[:, :, i].astype('uint8'), 'L').save(p)
        made.append(('通道 ' + nm_ch[i], p))
    if cc >= 3:
        b, g, r = (arr[:, :, 0].astype('int32'), arr[:, :, 1].astype('int32'), arr[:, :, 2].astype('int32'))
        combos = [('R-G', r - g), ('G-B', g - b), ('R-B', r - b),
                  ('R^G', r ^ g), ('R^B', r ^ b), ('G^B', g ^ b),
                  ('R^G^B', r ^ g ^ b), ('R+G+B', r + g + b)]
        for nm, v in combos:
            v = v - v.min()
            mx = v.max() or 1
            v = (v * 255 // mx).astype('uint8')
            p = outpath('通道_%s.png' % nm)
            Image.fromarray(v, 'L').save(p)
            made.append(('通道 ' + nm, p))
    return made

def gif_frames(path):
    """把 GIF 逐帧拆出来"""
    out = []
    try:
        from PIL import Image, ImageSequence
        im = Image.open(path)
        for i, frame in enumerate(ImageSequence.Iterator(im)):
            if i >= 80:
                break
            p = outpath('GIF帧_%02d.png' % i)
            frame.convert('RGBA').save(p)
            out.append(p)
            # 逐帧 LSB（GIF 常把数据藏在某一帧的像素最低位）
            try:
                import numpy as _np
                _a = _np.array(frame.convert('RGB'))
                for _nm, _chs in (('R', [0]), ('G', [1]), ('B', [2]), ('RGB', [0, 1, 2]), ('BGR', [2, 1, 0])):
                    _bits = _np.concatenate([(_a[:, :, _c] & 1).flatten() for _c in _chs])
                    _n = len(_bits) // 8
                    _by = _np.packbits(_bits[:_n * 8]).tobytes()
                    scan_flags(_by.decode('utf-8', 'replace'), 'GIF帧%d-LSB-%s' % (i, _nm))
            except Exception:
                pass
    except Exception:
        pass
    return out

STEGO_MARKS = [
    (b'steghide', 'steghide'),
    (b'OutGuess', 'OutGuess'),
    (b'*OutGuess*', 'OutGuess 标记'),
    (b'OpenStego', 'OpenStego'),
    (b'JPHS', 'JPHS'),
    (b'stegano', 'stegano'),
    (b'\xff\xd9\x00\x00', 'JPEG 尾部附加数据'),
]

def image_diff(p1, p2):
    """两张图做差 / 异或，生成对比图并扫二维码"""
    import numpy as np
    from PIL import Image
    head('两张图做差（找不同 / 盲水印）')
    a = np.array(Image.open(p1).convert('RGB')).astype('int16')
    b = np.array(Image.open(p2).convert('RGB')).astype('int16')
    if a.shape != b.shape:
        note('尺寸不同: %s vs %s' % (a.shape, b.shape))
        return []
    outs = []
    d = np.abs(a - b).astype('uint8')
    p = outpath('差分图.png'); Image.fromarray(d).save(p); outs.append(p)
    note('  差分图: %s' % p)
    x = ((a ^ b) & 0xFF).astype('uint8')
    p2o = outpath('异或图.png'); Image.fromarray(x).save(p2o); outs.append(p2o)
    note('  异或图: %s' % p2o)
    for q in outs:
        try:
            qr_scan_all(q, '对比图')
        except Exception:
            pass
    why('两张几乎一样的图：逐像素相减/异或会消掉相同背景，只留下被改动的地方（文字/二维码/水印）')
    return outs

def stego_marks(data):
    hits = []
    for sig, nm in STEGO_MARKS:
        if sig in data:
            hits.append((nm, data.find(sig)))
    return hits

def image_analyze(path, data):
    import numpy as np
    # ---- 通用 JPEG 结构/MCU 修复 ----
    if ADV and data.startswith(b'\xff\xd8'):
        try:
            head('JPEG 结构分析 / MCU 对齐修复')
            segs = ADV.jpeg_segments(data)
            for seg in segs:
                if 'width' in seg:
                    note('SOF %s: %dx%d, components=%d, sampling=%s' % (
                        seg.get('marker_hex'), seg['width'], seg['height'],
                        seg.get('components'), seg.get('sampling')))
            reps = ADV.jpeg_repair_candidates(path, data, OUTDIR)
            for rep in reps[:12]:
                note('  ★ MCU 对齐候选: %dx%d -> %dx%d' % (
                    rep['old_width'], rep['height'], rep['new_width'], rep['height']))
                note('    修复图: %s' % rep['png'])
                try:
                    _rep_arr = _imread(rep['png'])
                    if _rep_arr is not None:
                        _rep_gray = _rep_arr if _rep_arr.ndim == 2 else _rep_arr[:, :, 1]
                        ocr_and_harvest(_rep_gray, 'JPEG修复候选%d' % rep['new_width'], force=True)
                except Exception:
                    pass
            if reps:
                suggest('JPEG 尺寸可能被裁过：打开 MCU 对齐修复图，重点看右侧/底部；对修复图再跑 OCR/人工读字')
        except Exception as _e:
            note('JPEG 结构分析失败: %s' % _e)
    # ---- EXIF ----
    head('图片元数据 (EXIF) —— flag 常直接写在这里')
    exif = tool(r'03-杂项与取证\ExifTool\ExifTool.exe')
    got_exif = False
    if exif:
        o = run([exif, '-a', '-G', path], timeout=60)
        lines = [l for l in o.splitlines() if l.strip() and 'locale' not in l]
        for l in lines[:35]:
            note(l)
        scan_flags(o, 'EXIF')
        if any(k in o.lower() for k in ('comment', 'author', 'description', 'flag')):
            got_exif = True
    else:
        try:
            import exifread
            with open(path, 'rb') as f:
                tags = exifread.process_file(f, details=False)
            for k, v in list(tags.items())[:25]:
                note('%s = %s' % (k, v))
            scan_flags(str(tags), 'EXIF')
        except Exception as e:
            note('读不到 EXIF: %s' % e)
    if not got_exif:
        why('元数据是最省事的一步, 出题人有时直接写在图片属性里')

    # ---- zsteg（专业 LSB 扫描工具，向导那边装的）----
    head('zsteg —— PNG/BMP 的 LSB 全通道扫描（专业工具）')
    _z = tool(r'03-杂项与取证\图片隐写\zsteg\zsteg.exe')
    if _z and (data.startswith(b'\x89PNG') or data.startswith(b'BM')):
        o = run([_z, '-a', path], timeout=25)
        _ls = [l for l in o.splitlines() if l.strip()]
        _show = [l for l in _ls if 'text:' in l or 'flag' in l.lower()] or _ls
        for l in _show[:25]:
            note(l)
        if len(_ls) > 25:
            note('  ...（还有 %d 行）' % (len(_ls) - 25))
        scan_flags(o, 'zsteg')
        if not _ls:
            note('  （没扫到东西）')
    elif not _z:
        note('  （没找到 zsteg.exe。它装在 03-杂项与取证/图片隐写/zsteg/ 下）')
    else:
        note('  （只对 PNG/BMP 有效，跳过）')

    # ---- PNG 结构 ----
    if data.startswith(b'\x89PNG'):
        _fx = png_structure(path, data)
        if isinstance(_fx, list):
            for _p in _fx[:3]:
                try:
                    analyze(_p, depth + 1)
                except Exception:
                    pass
            return

    # ---- 尾部附加数据 ----
    head('文件尾部检查（有没有附加别的文件）')
    tail = data[-4096:]
    for sig, key, nm in MAGIC:
        if sig in tail and not data.startswith(sig):
            idx = data.rfind(sig)
            note('  ★ 发现尾部有 %s 特征, 位置 %d' % (nm, idx))
            save('尾部_%s.bin' % key, data[idx:])
            note('     已切出 -> 尾部_%s.bin' % key)

    # ---- JPEG 拼接 ----
    if data.startswith(b'\xff\xd8'):
        head('JPEG 拼接图检查（一张图里缝了多张）')
        cnt = data.count(b'\xff\xd8\xff')
        note('发现 %d 个 JPEG 起始标记' % cnt)
        if 1 < cnt <= 8:
            offs = []
            i = data.find(b'\xff\xd8\xff')
            while i != -1:
                offs.append(i); i = data.find(b'\xff\xd8\xff', i + 3)
            for n, o in enumerate(offs):
                end = offs[n+1] if n + 1 < len(offs) else len(data)
                save('JPEG_第%d张.jpg' % (n+1), data[o:end])
            note('  ★ 已切出 %d 张图 (JPEG_第N张.jpg)' % len(offs))
            note('     继续分析每一张...')
            for n in range(len(offs)):
                try:
                    analyze(outpath('JPEG_第%d张.jpg' % (n + 1)), depth + 1)
                except Exception:
                    pass
            why('"两个图拼一起"是常见套路: 上面一张骗你, 下面一张才有 flag')

    # ---- 先整图 OCR 一次（只对原始图片做，避免深层递归耗时）----
    if CUR_DEPTH == 0:
        try:
            _g = _imread(path)
            if _g is not None:
                import cv2 as _cv
                _gg = _cv.cvtColor(_g, _cv.COLOR_BGR2GRAY) if _g.ndim == 3 else _g
                ocr_and_harvest(_gg, '原图')
        except Exception:
            pass

    # ---- 通道分离（StegSolve 核心）----
    head('颜色通道分离 + 差分 + 异或')
    try:
        _arr = _imread(path)
        if _arr is not None:
            made = channel_split(path, _arr)
            note('已生成 %d 张通道图:' % len(made))
            for nm, p in made:
                note('   %-10s %s' % (nm, p))
            note('   → ★ 双击打开这些图看看，很多题的 flag 直接"画"在某个通道里')
            for nm, p in made:
                try:
                    _a2 = _imread(p)
                    if _a2 is not None and int(_a2.shape[0] * _a2.shape[1]) > 250000:
                        note('  通道「%s」较大，跳过自动二维码扫描（先看 LSB/位平面）' % nm)
                    else:
                        qr_scan_all(p, '通道图' + nm)
                except Exception:
                    pass
                try:
                    if _a2 is not None and int(_a2.shape[0] * _a2.shape[1]) <= 800000:
                        if lsb_deep(p, _a2):
                            note('   ★ 通道「%s」的 LSB 里有内容!' % nm)
                    elif _a2 is not None:
                        note('  通道「%s」较大，保留通道图但跳过深度 LSB 循环' % nm)
                except Exception:
                    pass
    except Exception as e:
        note('通道分离失败: %s' % e)

    # ---- GIF 分帧 ----
    if data.startswith(b'GIF8'):
        head('GIF 分帧')
        frames = gif_frames(path)
        note('拆出 %d 帧' % len(frames))
        for i, p in enumerate(frames[:20]):
            note('   帧%02d %s' % (i, p))
            try:
                analyze(p, depth + 1)
            except Exception:
                pass

    # ---- 隐写工具特征 ----
    head('隐写工具特征 / 尾部附加数据')
    hits = stego_marks(data)
    if hits:
        for nm, off in hits:
            note('   ★ 发现 %s 特征，偏移 %d' % (nm, off))
        suggest('这张图可能被 steghide/OutGuess/OpenStego 处理过，试试对应工具解密')
    else:
        note('   没发现常见隐写工具的特征标记')

    # ---- 位平面 + LSB ----
    head('位平面分析 + LSB 提取（像素最低位藏数据）')
    try:
        arr = _imread(path)
        if arr is None:
            note('OpenCV 读不了这张图, 跳过')
        else:
            if arr.ndim == 2:
                arr = np.stack([arr]*3, axis=-1)
            if arr.shape[2] == 4:
                arr = arr[:, :, :3]
            from PIL import Image
            for bit in range(8):
                m = ((arr >> bit) & 1).max(axis=2) * 255
                Image.fromarray(m.astype('uint8'), 'L').save(outpath('位平面_%d.png' % bit))
            note('已导出 8 张位平面图 (位平面_0.png ~ 位平面_7.png)')
            note('  → 重点看 位平面_0.png, 常直接看到隐藏的文字或图案')
            hint(7, '打开「位平面_0.png」看像素最低位有没有藏文字/图案')
            if CUR_DEPTH == 0:
                try:
                    ocr_and_harvest((((arr >> 0) & 1).max(axis=2) * 255).astype('uint8'), '位平面0')
                except Exception:
                    pass
            # LSB 提取：多种顺序
            orders = [('RGB', [0,1,2]), ('BGR', [2,1,0])]
            hit = False
            for name, ch in orders:
                bits = np.concatenate([((arr[:, :, c] & 1).flatten()) for c in ch])
                n = len(bits) // 8
                by = np.packbits(bits[:n*8]).tobytes()
                save('LSB_%s.bin' % name, by)
                txt = ''.join(chr(b) if 32 <= b < 127 or b in (10,13) else '.' for b in by)
                head_txt = txt[:400]
                low2 = txt.lower()
                if (head_txt.count('.') / max(1, len(head_txt)) > 0.1) and 'flag' not in low2 and 'ctf' not in low2:
                    continue
                scan_flags(txt, 'LSB_' + name)
                m = FLAG_RE.search(txt)
                if m:
                    note('  ★ LSB(%s) 里读到可疑内容!' % name)
                    hit = True
                idx = txt.find('flag')
                if idx < 0:
                    idx = txt.find('{')
                if idx >= 0:
                    note('  LSB(%s) 片段: %s' % (name, txt[max(0,idx-20):idx+80]))
                    hit = True
            if not hit:
                note('LSB 里没直接读到文字（数据可能是先压缩/加密过的）')
            # ---- 通用镜像像素隐写：左右半边差分 ----
            try:
                if ADV:
                    mirrors = ADV.mirror_stego_candidates(arr)
                    if mirrors:
                        head('镜像像素隐写检测（左右半边差分）')
                        for cand in mirrors[:12]:
                            note('  ★ 镜像差分命中: channel=%s skip=%d flag=%s' % (
                                cand['channel'], cand['skip'], cand['flag']))
                            add_flag(cand['flag'], '镜像像素差分')
                        why('一张图左右镜像时，微小的通道差值可以逐位编码；不要只看普通 LSB')
            except Exception as _e:
                note('镜像像素分析失败: %s' % _e)
            if int(arr.shape[0] * arr.shape[1]) <= 800000:
                lsb_deep(path, arr)
            else:
                note('原图像素较大，保留位平面/通道产物，但跳过深度 LSB 循环；需要时用 tools\\stego.py 单独跑')
                diag('lsb', 'skipped', '跳过超大图深度 LSB 循环',
                     why='逐位字符串拼装在百万级噪声图上开销过高',
                     assumption='大图若没有明显 LSB 线索，应优先做镜像/通道/裁剪定位',
                     evidence='%d pixels' % int(arr.shape[0] * arr.shape[1]),
                     next_action='先打开位平面_0.png 或裁剪可疑区域，再对局部运行 LSB')
            why('每个像素颜色值的最后 1 位改动最小, 肉眼看不出来, 适合藏数据')
    except Exception as e:
        note('位平面分析出错: %s' % e)

    # ---- 二维码 ----
    head('扫二维码（原图 / 反色 / 灰度 / 放大 全试）')
    if not qr_scan_all(path, '二维码'):
        note('没扫出二维码内容（可能不是二维码，或者对比度太低）')

def apk_analyze(path, data):
    """APK 题：本质是 zip，先看结构、捞 dex 字符串、解 assets"""
    note('* APK（安卓应用）—— 它本质就是个 zip 包')
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        names = z.namelist()
    except Exception as e:
        note('  打不开（不是标准 zip）: %s' % e)
        binary_analyze(path, data)
        return
    note('  里面有 %d 个文件' % len(names))
    for nm in names:
        if nm == 'AndroidManifest.xml' or nm.endswith('.dex') or nm.startswith('assets/'):
            note('    ' + nm)
    # assets 里的明文
    for nm in names:
        if nm.startswith('assets/') and not nm.endswith('/'):
            try:
                t = z.read(nm).decode('utf-8', 'replace')
            except Exception:
                continue
            scan_flags(t, 'APK:' + nm)
            if re.search(r'(?i)flag|secret|password|key', t):
                note('  * %s 里有可疑内容' % nm)
                save('apk_' + nm.replace('/', '_')[-60:], t)
    # dex 里捞字符串
    dex_txt = []
    for nm in names:
        if nm.endswith('.dex'):
            try:
                for s in re.findall(rb'[\x20-\x7e]{5,}', z.read(nm)):
                    dex_txt.append(s.decode('latin-1'))
            except Exception:
                pass
    if dex_txt:
        blob = '\n'.join(dex_txt)
        scan_flags(blob, 'APK-dex')
        save('apk_strings.txt', blob)
        hit = [s for s in dex_txt if re.search(r'(?i)flag|\{|\}|C404|correct|password|secret', s)]
        note('  dex 里的可疑字符串（前 20 条）:')
        for s in hit[:20]:
            note('    ' + s[:140])
    # 把 assets 解出来
    try:
        ex = outpath('apk_assets')
        os.makedirs(ex, exist_ok=True)
        n = 0
        for nm in names:
            if nm.startswith('assets/') and not nm.endswith('/'):
                with open(os.path.join(ex, os.path.basename(nm)), 'wb') as f:
                    f.write(z.read(nm))
                n += 1
        if n:
            note('  * assets/ 里 %d 个文件已解出 -> %s' % (n, ex))
    except Exception as e:
        note('  解 assets 失败: %s' % e)
    why('APK 采用 ZIP 容器。可用 jadx 查看代码，用 apktool 查看资源。')


def wasm_analyze(path, data):
    """WebAssembly(.wasm)：反编译成文本再看，比看二进制容易一万倍"""
    note('* WebAssembly 程序（.wasm）')
    import shutil
    cand = [shutil.which('wasm2wat') or '', os.path.join(ROOT, '01-通用工具', 'wabt', 'wabt-1.0.42', 'bin', 'wasm2wat.exe')]
    w2w = next((c for c in cand if os.path.isfile(c)), None)
    od = None
    for c in cand:
        o = c.replace('wasm2wat.exe', 'wasm-objdump.exe')
        if os.path.isfile(o):
            od = o
            break
    base = os.path.splitext(os.path.basename(path))[0]
    if w2w:
        note('  用 wasm2wat 反编译成可读文本（.wat）...')
        o = outpath(base + '.wat')
        r = run([w2w, path, '-o', o], timeout=120)
        if os.path.isfile(o):
            note('  * 已生成: %s （用记事本 / VS Code 打开看）' % o)
            try:
                t = open(o, encoding='utf-8', errors='replace').read()
                scan_flags(t, 'wasm2wat')
                for s in re.findall(r'data \([^)]*\) "([^"]{4,})"', t)[:20]:
                    note('    内嵌字符串: ' + s[:120])
            except Exception as e:
                note('  读 .wat 失败: %s' % e)
        else:
            note('  wasm2wat 没成功: ' + r[:200])
    else:
        note('  没找到 wasm2wat.exe（应该在 01-通用工具\\wabt\\wabt-1.0.42\\bin）')
    if od:
        note('  再用 wasm-objdump 看段结构和符号 ...')
        o2 = run([od, '-x', path], timeout=120)
        save(base + '.objdump.txt', o2)
        scan_flags(o2, 'wasm-objdump')
        for l in [x for x in o2.splitlines() if 'func' in x or 'name' in x.lower()][:12]:
            note('    ' + l.strip()[:130])
    ss = re.findall(rb'[\x20-\x7e]{5,}', data)
    blob = b'\n'.join(ss).decode('latin-1')
    scan_flags(blob, 'wasm strings')
    save('wasm_strings.txt', blob)
    why('wasm 是浏览器里的编译型字节码。wasm2wat 把它翻成文本指令（类似汇编），比直接看二进制好读得多')


# ============================================================
#                    压 缩 包 类
# ============================================================
def zip_fake_encrypt(path, data):
    """ZIP 伪加密检测与修复"""
    head('ZIP 伪加密检测')
    fixed = bytearray(data)
    changed = 0
    i = 0
    while True:
        i = data.find(b'PK\x01\x02', i)
        if i == -1:
            break
        if i + 10 <= len(fixed):
            flag = fixed[i+8] | (fixed[i+9] << 8)
            if flag & 1:
                fixed[i+8] &= 0xFE
                changed += 1
        i += 4
    if changed:
        note('  ★ 发现 %d 个条目带"加密标志", 但可能是伪加密（实际没密码）' % changed)
        p = save('修复伪加密.zip', bytes(fixed))
        note('     已生成修复版: %s' % p)
        try:
            z = zipfile.ZipFile(io.BytesIO(bytes(fixed)))
            names = z.namelist()
            note('     修复后里面的文件: %s' % ', '.join(names[:10]))
            for n in names[:20]:
                try:
                    c = z.read(n)
                    try:
                        t = c.decode('utf-8')
                        scan_flags(t, 'zip修复后:' + n)
                    except Exception:
                        pass
                except Exception as e:
                    note('     读取 %s 失败: %s' % (n, e))
        except Exception as e:
            note('     修复后仍打不开: %s' % e)
        why('ZIP 每个文件头有个"加密标志位"。出题人手动把它改成 1, 就会出现'
            '"明明没密码却提示要密码"——把它改回 0 就好了')
    else:
        note('没有伪加密特征')

def archive_analyze(path, data):
    # ---- 列举内容 ----
    head('压缩包内容')
    names = []
    if data.startswith(b'PK'):
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
            for i in z.infolist():
                note('%-40s %8d 字节%s' % (i.filename, i.file_size,
                     ('  [加密]' if i.flag_bits & 1 else '')))
                names.append(i.filename)
                if i.comment:
                    note('    注释: %s' % i.comment.decode('utf-8', 'replace')[:200])
            zc = getattr(z, 'comment', b'')
            if zc:
                note('  压缩包注释: %s' % zc.decode('utf-8', 'replace')[:300])
                scan_flags(zc.decode('utf-8', 'replace'), 'zip注释')
        except Exception as e:
            note('读取失败: %s' % e)
    else:
        sz = r'C:\Program Files\7-Zip\7z.exe'
        if os.path.isfile(sz):
            o = run([sz, 'l', '-slt', path], timeout=60)
            for l in o.splitlines()[:60]:
                note(l)
            scan_flags(o, '7z列表')
        else:
            note('需要 7-Zip 才能列出 rar/7z 内容（你机器上没找到）')
    scan_flags('\n'.join(names), '压缩包文件名')

    # ---- 伪加密 ----
    if data.startswith(b'PK'):
        zip_fake_encrypt(path, data)

    # ---- 弱口令爆破 ----
    if data.startswith(b'PK'):
        head('ZIP 弱口令爆破')
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
            enc = [i for i in z.infolist() if i.flag_bits & 1]
            if not enc:
                note('没有加密条目, 不用爆破')
            else:
                cands = list(EXTRA_PW) + ['123456','password','admin','1234','12345','111111','000000','admin123',
                         'root','qwerty','abc123','666666','888888','1','0','flag','test','']
                dicf = [os.path.join(ROOT, '07-字典', f) for f in
                        ('pass-shortlist.txt','pass-2025-top200.txt','pass-top10000.txt')]
                def try_one(w):
                    try:
                        z.read(enc[0].filename, pwd=w.encode())
                        return True
                    except Exception:
                        return False
                got = None
                for w in cands:
                    if try_one(w):
                        got = w; break
                if not got:
                    for dp in dicf:
                        if not os.path.isfile(dp):
                            continue
                        note('  正在查字典 %s ...' % os.path.basename(dp))
                        try:
                            with open(dp, encoding='utf-8', errors='ignore') as f:
                                for line in f:
                                    w = line.strip()
                                    if w and try_one(w):
                                        got = w; break
                        except Exception:
                            pass
                        if got:
                            break
                if got is not None:
                    note('  ★ 密码 = %r' % got)
                    try:
                        z2 = zipfile.ZipFile(io.BytesIO(data))
                        for n in z2.namelist():
                            c = z2.read(n, pwd=got.encode())
                            t = None
                            try:
                                t = c.decode('utf-8')
                            except Exception:
                                pass
                            if t:
                                note('  --- %s ---' % n)
                                for l in t.splitlines()[:20]:
                                    note('    ' + l)
                                scan_flags(t, 'zip内容')
                            else:
                                save('解出_' + os.path.basename(n), c)
                                note('  二进制文件已存出: 解出_' + os.path.basename(n))
                    except Exception as e:
                        note('  解压出错: %s' % e)
                else:
                    note('  字典里没爆破出来（可以试 ARCHPR / bkcrack 做明文攻击）')
                    hint(8, 'ZIP 有密码但字典没破出来 → 密码很可能藏在音频频谱 / 图片通道 / 频谱图里。找到后重新跑：python super.py 文件名 --password 你找到的密码')
        except Exception as e:
            note('爆破出错: %s' % e)
# ============================================================
#                    流 量 包
# ============================================================
def pdf_analyze(path, data):
    """PDF 分析：解压 FlateDecode 流 + 扫文本/元数据"""
    import zlib
    head('PDF：解压流 + 找文本')
    txt = data.decode('latin-1', 'replace')
    try:
        scan_flags(txt, 'PDF原文')
    except Exception:
        pass
    n = 0
    for m in re.finditer(rb'\nstream\r?\n(.*?)\r?\nendstream', data, re.S):
        raw = m.group(1)
        outs = []
        for fn in (lambda b: zlib.decompress(b),
                   lambda b: zlib.decompress(b, -15),
                   lambda b: zlib.decompressobj().decompress(b)):
            try:
                outs.append(fn(raw)); break
            except Exception:
                pass
        for i, b in enumerate(outs):
            n += 1
            t = b.decode('utf-8', 'replace')
            scan_flags(t, 'PDF解压流%d' % n)
            scan_base64_blobs(t, 'PDF解压流%d' % n)
            if FLAG_RE.search(t):
                note('  ★ PDF 解压流 %d 里发现 flag 特征' % n)
            fp = save('pdf_stream_%d.bin' % n, b)
            # 内嵌文件：PDF/ZIP/图片 -> 递归分析
            if b[:4] in (b'%PDF', b'PK\x03\x04') or b[:8].startswith(b'\x89PNG') or b[:3] == b'\xff\xd8\xff' or b[:4] == b'GIF8':
                note('  ★ PDF 流 %d 其实是个内嵌文件（%r），递归分析...' % (n, b[:8]))
                try:
                    analyze(fp, 1)
                except Exception as _e:
                    note('    递归分析失败: %s' % _e)
    note('  共尝试解压 %d 个 stream（解出来的在中间文件目录）' % n)
    if b'/Encrypt' in data:
        note('  ★ 这个 PDF 是加密的（/Encrypt）—— 初级赛常见"弱口令 + RC4"')
        try:
            from pypdf import PdfReader
            _cands = ['', 'password', '123456', '12345678', 'admin', 'letmein', 'qwerty', 'Binks',
                      'security', 'report', '2025', 'confidential']
            _d = os.path.join(ROOT, '07-字典', 'pass-2025-top200.txt')
            if os.path.isfile(_d):
                _cands += [x.strip() for x in open(_d, encoding='utf-8', errors='ignore') if x.strip()]
            for _pw in dict.fromkeys(_cands):
                try:
                    _r = PdfReader(io.BytesIO(data))
                    _ok = _r.decrypt(_pw) if _r.is_encrypted else 1
                except Exception:
                    continue
                if _ok:
                    note('  ★ PDF 密码破解成功: %r' % _pw)
                    _t = '\n'.join((_p.extract_text() or '') for _p in _r.pages)
                    scan_flags(_t, 'PDF解密文本')
                    save('pdf_decrypted.txt', _t)
                    break
            else:
                note('     小字典没试出来 → 用 rockyou / hashcat PDF 模式继续爆')
        except Exception as _e:
            note('     PDF 解密尝试跳过: %s' % _e)
        suggest('加密 PDF：先用小字典，再用 rockyou；解开后看内嵌文件/正文')
    # 简单文本抽取（BT/ET 之间的 Tj/TJ）
    try:
        for tm in re.finditer(r'\((?:\\.|[^\\)])*\)\s*Tj', txt):
            scan_flags(tm.group(0), 'PDF文本')
    except Exception:
        pass
    why('PDF 正文通常是 Flate 压缩的；把 stream 解压就能看到文字/flag')

def pcap_analyze(path, data):
    ts = r'C:\Program Files\Wireshark\tshark.exe'
    if not os.path.isfile(ts):
        head('流量包分析')
        note('没找到 tshark.exe（需要装 Wireshark）')
        return
    head('流量包：导出所有传输过的文件')
    ex = outpath('pcap导出')
    os.makedirs(ex, exist_ok=True)
    o = run(ts.wrap if False else [ts, '-r', path, '--export-objects', 'http,' + ex, '-q'], timeout=180)
    files = []
    for r, d, fs in os.walk(ex):
        for f in fs:
            fp = os.path.join(r, f)
            files.append(fp)
    if files:
        note('★ 导出 %d 个文件:' % len(files))
        for fp in files[:30]:
            note('   %-45s %d 字节' % (os.path.basename(fp), os.path.getsize(fp)))
            try:
                c = read_bytes(fp)
                try:
                    scan_flags(c.decode('utf-8', 'replace'), 'pcap导出:' + os.path.basename(fp))
                except Exception:
                    pass
            except Exception:
                pass
    else:
        note('没有 HTTP 传输的文件（可能不是 HTTP 流量）')

    head('流量包：协议统计 / 明文找 flag')
    o = run([ts, '-r', path, '-q', '-z', 'io,phs'], timeout=120)
    for l in o.splitlines()[:25]:
        note(l)
    o2 = run([ts, '-r', path, '-Y', 'frame contains "flag"', '-T', 'fields', '-e', 'frame.number', '-e', 'http.request.uri', '-e', 'http.file_data'], timeout=120)
    if o2.strip():
        note('★ 含 "flag" 关键字的包:')
        for l in o2.splitlines()[:20]:
            note('   ' + l[:160])
            scan_flags(l, 'pcap-frame')
    else:
        note('没有包内容里含 "flag"（试试在 Wireshark 里看 tcp.stream）')
    o3 = run([ts, '-r', path, '-T', 'fields', '-e', 'dns.qry.name'], timeout=120)
    dns = sorted(set(x.strip() for x in o3.splitlines() if x.strip()))
    if dns:
        note('DNS 查询过的域名 (前 20 个):')
        for d in dns[:20]:
            note('   ' + d[:120])
        scan_flags('\n'.join(dns), 'DNS')
        # DNS 外带：子域常常是 base32/base64/hex 编码
        for _d in dns[:200]:
            _sub = _d.split('.')[0]
            if len(_sub) < 8:
                continue
            for _nm, _dec in (
                ('base32', lambda t: base64.b32decode(t + '=' * (-len(t) % 8))),
                ('base64', lambda t: base64.b64decode(t + '=' * (-len(t) % 4))),
                ('base64url', lambda t: base64.urlsafe_b64decode(t + '=' * (-len(t) % 4))),
                ('hex', lambda t: bytes.fromhex(t if len(t) % 2 == 0 else t[:-1])),
            ):
                try:
                    _b = _dec(_sub.upper() if _nm == 'base32' else _sub)
                    _t = _b.decode('utf-8')
                except Exception:
                    continue
                if _t.strip():
                    note('  ★ DNS 子域 %s 用 %s 解出: %r' % (_sub[:40], _nm, _t[:100]))
                    scan_flags(_t, 'DNS子域-%s' % _nm)
                    add_result(_t, 'DNS子域-%s' % _nm)

    # ---- ICMP / 原始数据外带 ----
    try:
        o4 = run([ts, '-r', path, '-Y', 'icmp', '-T', 'fields', '-e', 'data.data'], timeout=120)
        raw_hex = ''.join(x.strip().replace(':', '') for x in o4.splitlines() if x.strip())
        if len(raw_hex) >= 16:
            note('  ★ ICMP 里有 %d 个十六进制字符，尝试还原' % len(raw_hex))
            try:
                _b = bytes.fromhex(raw_hex[:len(raw_hex)//2*2])
                _t = _b.decode('utf-8', 'replace')
                note('     -> %r' % _t[:120])
                scan_flags(_t, 'ICMP数据')
                scan_base64_blobs(_t, 'ICMP数据')
                save('icmp_data.bin', _b)
            except Exception:
                pass
    except Exception:
        pass

    # ---- USB HID 键盘流量 ----
    try:
        o5 = run([ts, '-r', path, '-Y', 'usb', '-T', 'fields', '-e', 'usb.capdata', '-e', 'usbhid.data'], timeout=120)
        hid = []
        for line in o5.splitlines():
            line = line.strip()
            if not line: continue
            part = line.split('\t')[0] if '\t' in line else line
            hx = part.replace(':', '').replace(' ', '')
            if len(hx) < 6: continue
            try: b = bytes.fromhex(hx)
            except Exception: continue
            if len(b) >= 3: hid.append((b[0], b[2]))
        if hid:
            KM = {0x04:'a',0x05:'b',0x06:'c',0x07:'d',0x08:'e',0x09:'f',0x0a:'g',0x0b:'h',0x0c:'i',0x0d:'j',0x0e:'k',0x0f:'l',
                  0x10:'m',0x11:'n',0x12:'o',0x13:'p',0x14:'q',0x15:'r',0x16:'s',0x17:'t',0x18:'u',0x19:'v',0x1a:'w',0x1b:'x',
                  0x1c:'y',0x1d:'z',0x1e:'1',0x1f:'2',0x20:'3',0x21:'4',0x22:'5',0x23:'6',0x24:'7',0x25:'8',0x26:'9',0x27:'0',
                  0x28:'\n',0x2c:' ',0x2d:'-',0x2e:'=',0x2f:'[',0x30:']',0x31:'\\',0x33:';',0x34:"'",0x36:',',0x37:'.',0x38:'/',
                  0x2a:'\x08'}
            SHIFT = {'1':'!','2':'@','3':'#','4':'$','5':'%','6':'^','7':'&','8':'*','9':'(','0':')','-':'_','=':'+','[':'{',']':'}','\\':'|',';':':',"'":'"',',':'<','.':'>','/':'?'}
            typed = []
            for mod, kc in hid:
                ch = KM.get(kc)
                if not ch: continue
                if mod & 0x22 and ch in SHIFT: ch = SHIFT[ch]
                elif mod & 0x22 and ch.isalpha(): ch = ch.upper()
                typed.append(ch)
            txt = ''.join(typed)
            if len(txt.strip()) >= 3:
                note('  ★ USB HID 键盘解码出 %d 个字符: %r' % (len(txt), txt[:160]))
                scan_flags(txt, 'USB HID 键盘')
                scan_base64_blobs(txt, 'USB HID 键盘')
                save('usb_hid.txt', txt)
                suggest('USB 键盘流量：上面是按 HID 键值表直接翻出来的内容（鼠标题要画坐标图）')
    except Exception:
        pass

# ============================================================
#                    G I T  泄 露
# ============================================================
_GIT_DONE = set()
_EMBED_DONE = set()

def git_analyze(rootdir, depth=0):
    _gk = os.path.realpath(rootdir)
    if _gk in _GIT_DONE:
        return False
    _GIT_DONE.add(_gk)
    gd = None
    for r, ds, fs in os.walk(rootdir):
        if '.git' in ds:
            gd = os.path.join(r, '.git'); break
        if os.path.isfile(os.path.join(r, 'HEAD')) and os.path.isdir(os.path.join(r, 'objects')):
            gd = r; break
    if not gd:
        return False
    repo = os.path.dirname(gd.rstrip('\\/')) or rootdir
    head('Git 仓库泄露分析')
    note('仓库: ' + repo)
    # 清理 mac 垃圾
    n = 0
    for r, ds, fs in os.walk(repo):
        for f in fs:
            if f.startswith('._'):
                try:
                    os.remove(os.path.join(r, f)); n += 1
                except Exception:
                    pass
    if n:
        note('清理了 %d 个 mac 打包垃圾文件 (._*)' % n)

    G = lambda *a: run(['git', '-c', 'safe.directory=*', '-C', repo] + list(a), timeout=90)

    o = G('status', '-s')
    if o.strip():
        note('工作区状态 (有文件被删!):')
        for l in o.splitlines()[:10]:
            note('   ' + l)

    note('')
    note('【提交历史】')
    for l in G('log', '--all', '--oneline', '--decorate').splitlines()[:25]:
        note('   ' + l)

    note('')
    note('【reflog 操作记录】—— 被 reset / 删分支的提交都在这')
    t = G('reflog')
    for l in t.splitlines()[:30]:
        note('   ' + l)
    scan_flags(t, 'git-reflog')

    note('')
    note('【悬空对象】—— 被删掉的东西')
    t = G('fsck', '--lost-found', '--unreachable')
    for l in [x for x in t.splitlines() if 'bad sha1' not in x][:30]:
        note('   ' + l)

    note('')
    note('【全对象扫描 + 碎片提取】')
    objs = G('cat-file', '--batch-all-objects', '--batch-check').splitlines()
    parts = {}
    flags_found = []
    for line in objs:
        m = re.match(r'^([0-9a-f]{40}) (\w+)', line)
        if not m:
            continue
        sha, ty = m.group(1), m.group(2)
        if ty == 'tree':
            continue
        if ty == 'commit':
            txt = G('log', '-1', '--format=%B', '-n', '1', sha)
        else:
            txt = G('cat-file', '-p', sha)
        scan_flags(txt, 'git对象 ' + sha[:8])
        for fm in FLAG_RE.finditer(txt):
            flags_found.append((fm.group(0), sha[:8]))
        for line2 in txt.splitlines():
            if re.match(r'\s*[-*]\s*\[', line2):
                continue   # 跳过提示清单
            pm = re.search(r'part\s*#?\s*(\d+)\s*[^:\n]{0,40}:\s*"?([^\s"]+)"?', line2, re.I)
            if not pm:
                continue
            k = int(pm.group(1)); v = pm.group(2).strip('"')
            if not (1 <= len(v) <= 40):
                continue
            sc = (2 if ('{' in v or '}' in v) else 0) + (1 if '_' in v else 0) + (1 if re.search(r'\d', v) else 0)
            if k not in parts or sc > parts[k][2]:
                parts[k] = (v, sha[:8], sc)
    if parts:
        note('★ 找到碎片:')
        for k in sorted(parts):
            note('   Part %d = %-16s (来自 %s)' % (k, parts[k][0], parts[k][1]))
        joined = ''.join(parts[k][0] for k in sorted(parts))
        note('★ 按顺序拼起来: ' + joined)
        add_flag(joined, 'git碎片拼接')
    if flags_found:
        note('★ 对象里形如 flag 的字符串:')
        seen = set()
        for v, s in flags_found:
            if v in seen:
                continue
            seen.add(v)
            note('   %-50s (来自 %s)' % (v, s))
    why('Git 不会真的删东西: 提交过又被删/改/重置的内容, 都还在 .git/objects 里')

    # 尝试把工作区文件恢复出来
    try:
        o = G('fsck', '--lost-found')
        dang = os.path.join(repo, '.git', 'lost-found')
        if os.path.isdir(dang):
            note('已恢复的悬空对象在: ' + dang)
    except Exception:
        pass
    return True

# ============================================================
#                    可 执 行 文 件 / 二 进 制
# ============================================================
def entropy(b):
    if not b:
        return 0.0
    c = Counter(b)
    ln = len(b)
    return -sum((v/ln) * math.log2(v/ln) for v in c.values())

def binary_analyze(path, data):
    head('字符串提取（逆向第一步）')
    ss = re.findall(rb'[\x20-\x7e]{4,}', data)
    txt = b'\n'.join(ss).decode('latin-1')
    scan_flags(txt, 'strings')
    scan_base64_blobs(txt, 'strings')
    scan_base64_blobs(txt.replace(' ', ''), 'strings-紧凑')
    interesting = [s.decode('latin-1') for s in ss if re.search(rb'(?i)flag|\{|\}|correct|wrong|success|password|key|C404', s)]
    if interesting:
        note('★ 值得看的字符串 (前 25 条):')
        for s in interesting[:25]:
            note('   ' + s[:140])
    else:
        note('提取到 %d 条字符串, 没看到明显关键字 (已存 strings.txt)' % len(ss))
    save('strings.txt', txt)
    ss16 = [s.decode('utf-16-le', 'replace') for s in re.findall(rb'(?:[\x20-\x7e]\x00){4,}', data)]
    if ss16:
        note('另外发现 %d 条 UTF-16 宽字符串（Windows 程序常这样存）' % len(ss16))
        for s in ss16[:15]:
            note('   ' + s[:120])
        scan_flags('\n'.join(ss16), 'strings-utf16')
        save('strings_utf16.txt', '\n'.join(ss16))
    why('逆向第一步永远是看字符串 —— flag、提示语、比较用的密码经常直接明文躺在里面')

    if re.search(rb'(?i)flag\.txt|under maintenance|couldn.t find the flag', data):
        note('  ★ 这题是交互式/逻辑题：flag 在运行目录的 flag.txt 里，需要运行或调试程序')
        note('     → 插件不能离线出 flag（服务器上的 flag.txt 不在附件里）')
        note('     → 下一步：用 gdb 跟 main / 找读取 flag.txt 的条件（价格/余额/整数溢出）')
        suggest('交互式程序：用 gdb 跟 main，重点看 read_uint / 价格比较 / flag.txt 读取条件')

    head('文件信息')
    note('大小: %d 字节, 熵值: %.3f' % (len(data), entropy(data[:4 * 1024 * 1024])))
    if entropy(data) > 7.5:
        note('  熵很高 → 大概率被压缩或加密了')
    for sig, key, nm in MAGIC:
        if data.startswith(sig):
            note('  类型: ' + nm)
    if b'PyInstaller' in data or b'pyi-' in data or b'MEI\x0c\x0b\x0a\x0b\x0e' in data:
        note('  ★ 这是 PyInstaller 打包的 Python 程序!')
        note('     -> 用 向导 里的 "PyInstaller 解包"（pyreverse.py）解开就能看到 .pyc')
        try:
            _pr = os.path.join(HERE, 'tools', 'pyreverse.py')
            if os.path.isfile(_pr):
                note('     → 自动解包中（可能要几十秒）...')
                _po = run([sys.executable, _pr, path], timeout=300)
                for _pl in [x for x in _po.splitlines() if x.strip()][:25]:
                    note(_pl)
                scan_flags(_po, 'PyInstaller解包')
        except Exception as _pe:
            note('     解包失败: %s' % _pe)
    if b'UPX!' in data or b'UPX0' in data or b'UPX1' in data:
        note('  ★ 检测到 UPX 壳!')
        upx = tool(r'05-逆向\upx\upx-5.2.1-win64\upx.exe', r'05-逆向\upx\upx.exe')
        if upx:
            note('     正在自动脱壳...')
            o = run([upx, '-d', path], timeout=120)
            for l in o.splitlines()[:8]:
                note('     ' + l)
        else:
            note('     找不到 upx.exe, 手动: 05-逆向\\upx 里运行 upx -d 文件名')
    if b'BSJB' in data or b'mscorlib' in data:
        note('  ★ 这是 .NET (C#) 程序!')
        note('     -> 用 dnSpy 打开 (05-逆向\\dnSpy\\dnSpy.exe) 能直接看到源码')
    if data[:2] == b'MZ':
        note('  Windows PE 文件 —— 建议拖进 DetectItEasy 看壳和语言')

# ============================================================
#                    音 频
# ============================================================
CUR_DEPTH = 0          # 当前递归深度（深层就不再 OCR，避免耗时爆炸）

def _ocr_text_variants(t):
    # Generate conservative OCR corrections for flag prefixes/characters.
    seen = set()
    def emit(v):
        if v and v not in seen:
            seen.add(v)
            return v
        return None
    first = emit(t)
    if first:
        yield first
    lower = t.lower()
    if 'mdctf{' in lower and t[:1].upper() in ('J', 'I', 'U'):
        idx = lower.find('mdctf{')
        v = 'UMDCTF' + t[idx + 6:]
        got = emit(v)
        if got:
            yield got
    m = re.search(r'([A-Za-z0-9_\-]{2,20})\{', t)
    if not m:
        return
    prefix = m.group(1)
    tail = t[m.end(1):]
    confuse = {'0':'O', 'O':'0', '1':'I', 'I':'1', '5':'S', 'S':'5', '8':'B', 'B':'8', 'J':'U', 'U':'J'}
    for i, ch in enumerate(prefix):
        repl = confuse.get(ch)
        if repl:
            v = prefix[:i] + repl + prefix[i + 1:] + tail
            got = emit(v)
            if got:
                yield got

def ocr_and_harvest(gray, label='图片', force=False):
    if CUR_DEPTH > 1 and not force:
        return []
    """对一张灰度图跑 OCR：记录文本、找 flag、提取疑似密码进爆破候选"""
    try:
        _pixels = int(getattr(gray, 'size', 0))
    except Exception:
        _pixels = 0
    if _pixels > 1500000:
        note('  图片像素过大（%d），跳过自动 OCR，避免识别器把时间耗在噪声图上' % _pixels)
        diag('ocr', 'skipped', '跳过超大图 OCR',
             why='OCR 在随机噪声/超大的图上收益低且可能持续很久',
             assumption='先看通道、位平面和 LSB，再对手工裁出的局部做 OCR',
             evidence='%d pixels' % _pixels, next_action='用 StegSolve/画图裁出可疑文字区域后单独 OCR')
        return []
    try:
        import ocr as _OCR
    except Exception as e:
        note('  OCR 模块不可用: %s' % e)
        return []
    if not _OCR.available():
        return []
    try:
        txts = _OCR.ocr_array(gray)
    except Exception as e:
        note('  OCR 出错: %s' % e)
        return []
    if not txts:
        return []
    for t in txts[:12]:
        note('  ★ OCR 读到: %r' % t)
        variants = list(_ocr_text_variants(t))
        for v in variants:
            add_result(v, label + ' OCR')
            scan_flags(v, label + ' OCR')
        for pw in _OCR.guess_passwords(t):
            if pw and pw not in EXTRA_PW:
                EXTRA_PW.append(pw)
                note('     >>> 提取到疑似密码 %r，已加入自动解压候选' % pw)
                hint(9, 'OCR 从「%s」读到密码 %r —— 已自动拿去试解压' % (label, pw))
        for pw in _OCR.guess_passwords(t):
            hint(9, 'OCR 从「%s」读到: %s' % (label, t[:80]))
    return txts
def _wav_direct(path):
    """不依赖 ffmpeg，直接读 WAV 并生成频谱图/波形图/倒放"""
    import wave
    import numpy as np
    from PIL import Image
    w = wave.open(path, 'rb')
    ch, sw, fr, nf = w.getnchannels(), w.getsampwidth(), w.getframerate(), w.getnframes()
    raw = w.readframes(nf); w.close()
    note('WAV: %d 声道, %d 位, %d Hz, %.1f 秒' % (ch, sw * 8, fr, nf / max(1, fr)))
    a = np.frombuffer(raw, dtype={1: 'int8', 2: 'int16', 4: 'int32'}.get(sw, 'int16')).astype(np.float64)
    a2 = a.reshape(-1, ch) if ch > 1 else a.reshape(-1, 1)
    # ---- WAV LSB（16 位采样最低位藏数据）----
    try:
        bits = ''.join(str(int(v) & 1) for v in a[:len(a) // 8 * 8])
        by = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
        t = by.decode('utf-8', 'replace')
        if FLAG_RE.search(t):
            note('  ★★★ WAV 采样最低位里读到文字: %r' % t[:160])
            scan_flags(t, 'WAV LSB')
            save('wav_lsb.bin', by)
    except Exception as _e:
        note('  WAV LSB 检查失败: %s' % _e)
    # ---- WAV 摩尔斯（按声音长短解点划）----
    try:
        x = a2[:, 0]
        win = max(1, fr // 200)
        seg = len(x) // win * win
        env = np.abs(x[:seg]).reshape(-1, win).max(axis=1)
        thr = env.max() * 0.15
        on = env > thr
        runs = []
        i = 0
        while i < len(on):
            j = i
            while j < len(on) and on[j] == on[i]: j += 1
            runs.append((bool(on[i]), (j - i) * win / fr)); i = j
        ons = [d for o, d in runs if o and d > 0]
        if len(ons) >= 4:
            unit = min(ons)
            sym = ''
            for o, d in runs:
                n = d / unit
                if o: sym += '.' if n < 2 else '-'
                else:
                    if n >= 6: sym += ' / '
                    elif n >= 2: sym += ' '
            MORSE = {'.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G','....':'H',
                     '..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N','---':'O','.--.':'P',
                     '--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X',
                     '-.--':'Y','--..':'Z','-----':'0','.----':'1','..---':'2','...--':'3','....-':'4',
                     '.....':'5','-....':'6','--...':'7','---..':'8','----.':'9','..--..':'?','-.-.--':'!',
                     '-.--.':'{','-.--.-':'}','..--.-':'_'}
            txt = ''.join(MORSE.get(g, '') for grp in sym.split('/') for g in grp.split())
            if len(txt) >= 4:
                note('  ★ WAV 声音长短像摩尔斯：%s' % txt[:120])
                scan_flags(txt, 'WAV摩尔斯')
                try:
                    import advanced as _ADVW
                    for cand in _ADVW.morse_flag_candidates(txt):
                        note('  ★ Morse/leet 格式化候选: %s' % cand)
                        add_flag(cand, 'WAV摩尔斯+英文分词')
                except Exception:
                    pass
                save('wav_morse.txt', txt)
    except Exception as _e:
        note('  WAV 摩尔斯检查失败: %s' % _e)
    # ---- 主频序列（旋律 / 摩尔斯 / FSK）----
    try:
        x = a2[:, 0]
        win = max(256, int(fr * 0.03)); hop = max(1, win // 2)
        seq = []
        for i in range(0, len(x) - win, hop):
            S = np.abs(np.fft.rfft(x[i:i+win] * np.hanning(win)))
            f = np.fft.rfftfreq(win, 1.0 / fr)
            if S[1:].size: seq.append(round(f[int(np.argmax(S[1:])) + 1]))
        runs = []
        for fq in seq:
            if not runs or abs(fq - runs[-1][0]) > 20: runs.append([fq, 1])
            else: runs[-1][1] += 1
        if runs:
            note('  主频序列（前 30 段）: ' + ', '.join('%dHz x%d' % (fq, n) for fq, n in runs[:30]))
            if 2 <= len(set(r[0] for r in runs)) <= 12:
                note('  ★ 主频只有 %d 种，像旋律/FSK/DTMF —— 可以按音高序列继续解' % len(set(r[0] for r in runs)))
    except Exception:
        pass
    for ci in range(a2.shape[1]):
        x = a2[:, ci]
        N, hop = 1024, 256
        segs = max(1, (len(x) - N) // hop); segs = min(segs, 3000)
        win = np.hanning(N)
        S = np.array([20 * np.log10(np.abs(np.fft.rfft(x[i*hop:i*hop+N] * win)) + 1e-9) for i in range(segs)]).T
        S = S - S.min(); S = S / (S.max() + 1e-9)
        p = outpath('频谱图_声道%d.png' % (ci + 1))
        _gray = (S * 255).astype('uint8')[::-1]
        Image.fromarray(_gray).save(p)
        note('  ★★★ 频谱图已生成: %s' % p)
        ocr_and_harvest(_gray, '频谱图', force=True)
        hint(9, '打开频谱图看有没有文字 → %s   （音频题常把密码/flag 画在频谱里）' % p)
        note('      >>> 立刻双击打开它！很多音频题把密码 / flag 直接"画"在频谱里')
        step = max(1, len(x) // 2400)
        wv = x[::step]
        h = 240
        img = Image.new('L', (max(1, len(wv)), h), 255); px = img.load()
        mx = max(1.0, abs(wv).max())
        for i2, v in enumerate(wv):
            px[i2, max(0, min(h - 1, int((1 - (v / mx)) * (h - 1) / 2)))] = 0
        p2 = outpath('波形图_声道%d.png' % (ci + 1))
        img.save(p2)
        note('  波形图: %s' % p2)
    try:
        rev = a2[:, 0].astype(np.int16).tobytes()
        pr = outpath('倒放.wav')
        ww = wave.open(pr, 'wb'); ww.setnchannels(1); ww.setsampwidth(2); ww.setframerate(fr)
        ww.writeframes(rev); ww.close()
        note('  倒放版本: %s' % pr)
    except Exception:
        pass

def audio_analyze(path, data):
    """音频/视频分析：ffmpeg 解码 + 频谱图 + 波形图 + 声道分离 + 倒放"""
    import numpy as np
    from PIL import Image
    FF = tool(r'01-通用工具\ffmpeg\ffmpeg.exe')
    FP = tool(r'01-通用工具\ffmpeg\ffprobe.exe')
    head('音频 / 视频分析')
    if data[:4] == b'RIFF':
        try:
            note('原始 WAV：先按原始采样分析（LSB / 摩尔斯 / 频谱）...')
            _wav_direct(path)
        except Exception as _e:
            note('  原始 WAV 分析失败: %s' % _e)
    if not FF:
        note('没找到 ffmpeg，只能处理 WAV（放一份到 01-通用工具\ffmpeg 就能支持全部格式）')
        if data[:4] == b'RIFF':
            note('这文件是 RIFF/WAV，直接读（不需要 ffmpeg）...')
            try:
                _wav_direct(path)
            except Exception as _e:
                note('  直接读 WAV 失败: %s' % _e)
            return
        else:
            note('→ 手动: 用 Audacity 打开，切"频谱图"视图看')
            return

    # ---- 1. 基本信息 ----
    if FP:
        o = run([FP, '-v', 'error', '-show_entries',
                 'stream=codec_name,codec_type,sample_rate,channels,duration:format=duration,bit_rate',
                 '-of', 'default=noprint_wrappers=1', path], timeout=90)
        info = [l.strip() for l in o.splitlines() if '=' in l and not l.strip().startswith('#')]
        if info:
            note('文件信息:')
            for l in info[:14]:
                note('   ' + l)
        # 有几个流
        o2 = run([FP, '-v', 'error', '-show_entries', 'stream=codec_type', '-of', 'csv=p=0', path], timeout=60)
        kinds = [x.strip() for x in o2.splitlines() if x.strip()]
        if kinds:
            note('流的类型: ' + ', '.join(kinds))

    def wav_to_array(wav):
        import wave
        w = wave.open(wav, 'rb')
        ch, sw, fr, nf = w.getnchannels(), w.getsampwidth(), w.getframerate(), w.getnframes()
        raw = w.readframes(nf)
        w.close()
        dt = {1: 'int8', 2: 'int16', 4: 'int32'}.get(sw, 'int16')
        a = np.frombuffer(raw, dtype=dt).astype(np.float64)
        if ch > 1:
            a = a.reshape(-1, ch)
        return a, fr, ch

    def spectrogram(a, fr, tag):
        try:
            N = 2048
            hop = max(1, N // 8)
            if len(a) < N * 2:
                return None
            segs = min((len(a) - N) // hop, 3000)
            win = np.hanning(N)
            cols = []
            for i in range(segs):
                seg = a[i * hop:i * hop + N] * win
                cols.append(20 * np.log10(np.abs(np.fft.rfft(seg)) + 1e-9))
            S = np.array(cols).T
            S = (S - S.min()) / (S.max() - S.min() + 1e-9)
            # 只显示 0~1/4 采样率（有效频段）
            h = S.shape[0]
            S = S[:h // 2]
            img = Image.fromarray((S * 255).astype('uint8')[::-1])
            # 放大宽度方便看字
            if img.width < 800:
                img = img.resize((1200, img.height * 2), Image.NEAREST)
            p = outpath('频谱图_%s.png' % tag)
            img.save(p)
            note('  已生成频谱图(%s): %s' % (tag, p))
            return p
        except Exception as e:
            note('  频谱图(%s)失败: %s' % (tag, e))
            return None

    def waveform(a, tag):
        try:
            step = max(1, len(a) // 4000)
            pts = a[::step]
            h = 320
            img = Image.new('L', (len(pts), h), 255)
            px = img.load()
            mx = max(1.0, abs(pts).max())
            for x, v in enumerate(pts):
                y = int((1 - (v / mx)) * (h - 1) / 2)
                px[x, max(0, min(h - 1, y))] = 0
            p = outpath('波形图_%s.png' % tag)
            img.save(p)
            note('  已生成波形图(%s): %s' % (tag, p))
        except Exception:
            pass

    # ---- 2. 统一转成 WAV（单声道）----
    wav = outpath('转成_单声道.wav')
    run([FF, '-y', '-v', 'error', '-i', path, '-ac', '1', '-ar', '44100', '-f', 'wav', wav], timeout=300)
    if not os.path.isfile(wav):
        note('ffmpeg 转换失败（可能是纯视频或损坏文件）')
    else:
        try:
            a, fr, ch = wav_to_array(wav)
            note('转成单声道 WAV: %d 采样, %.1f 秒' % (len(a), len(a) / max(1, fr)))
            spectrogram(a.astype(np.float64), fr, '单声道')
            waveform(a.astype(np.float64), '单声道')
            why('很多音频题把 flag 画在频谱的高频区域，或把文字画成波形 —— 两张图都看看')
            # 倒放
            spectrogram(a[::-1].astype(np.float64), fr, '倒放')
        except Exception as e:
            note('读 WAV 失败: %s' % e)

    # ---- 3. 声道分离（flag 常藏在一个声道里）----
    wav2 = outpath('转成_立体声.wav')
    run([FF, '-y', '-v', 'error', '-i', path, '-ac', '2', '-ar', '44100', '-f', 'wav', wav2], timeout=300)
    if os.path.isfile(wav2):
        try:
            a2, fr2, ch2 = wav_to_array(wav2)
            if ch2 >= 2:
                for ci, cn in ((0, '左声道'), (1, '右声道')):
                    spectrogram(a2[:, ci].astype(np.float64), fr2, cn)
                # 左右相减（很多题把内容放在"差值"里）
                diff = a2[:, 0] - a2[:, 1]
                if abs(diff).max() > 1:
                    spectrogram(diff.astype(np.float64), fr2, '左右相减')
        except Exception:
            pass

    # ---- 4. 如果是视频，抽帧 ----
    kinds = ''
    try:
        kinds = run([FP, '-v', 'error', '-show_entries', 'stream=codec_type', '-of', 'csv=p=0', path], timeout=60)
    except Exception:
        pass
    if 'video' in kinds.lower():
        head('视频：抽取关键帧')
        fr_dir = outpath('视频帧')
        os.makedirs(fr_dir, exist_ok=True)
        run([FF, '-y', '-v', 'error', '-i', path, '-vf', 'fps=2', os.path.join(fr_dir, 'f%04d.png')], timeout=300)
        frames = sorted(os.listdir(fr_dir))
        note('抽了 %d 帧 -> %s' % (len(frames), fr_dir))
        suggest('视频题常见: 逐帧扫二维码 / 帧里藏字 / 音轨隐写 —— 已经抽好帧了，去那个目录翻')

    note('')
    note('产出目录: ' + OUTDIR)

# ============================================================
#                    文 本 统 一 入 口
# ============================================================
def symbol_analyze(s):
    """通用符号表分析：任意 2~64 种符号 -> 比特/进制 -> 字节。

    不针对任何具体题目：只要一段文本只由少量符号组成（DNA、emoji、星星、
    扑克牌、自造符号、二进制/三进制…），就自动尝试
      · 每符号 k 位（小字母表枚举所有映射）
      · base-N 大整数（正/反序）
      · n 个符号拼 1 字节（正/反权重）
    并按"可打印率 + 是否出现 flag"排序。"""
    t = re.sub(r'\s+', '', s)
    if len(t) < 16 or len(t) > 200000:
        return
    cnt = Counter(t)
    alpha = [c for c, _ in cnt.most_common()]
    N = len(alpha)
    if not (2 <= N <= 64):
        return
    if len(t) / max(1, len(s)) < 0.6:
        return
    head('通用符号表分析（%d 种符号 × %d 个）' % (N, len(t)))
    note('  符号: ' + ' '.join(str(c) for c in alpha[:16]) + (' …' if N > 16 else ''))
    t = t[:20000]
    orders = [('频次序', alpha), ('码点序', sorted(alpha, key=ord))]
    if N <= 8 and len(t) <= 4000:
        for p in itertools.permutations(alpha):
            orders.append(('排列', list(p)))
    else:
        import random as _rnd
        _base = list(alpha)
        for _ in range(300):
            _rnd.shuffle(_base)
            orders.append(('随机排列', list(_base)))
    n_orders = orders
    if len(orders) * max(1, len(t) // 4) > 5000000:
        n_orders = orders[:2] + orders[2:302]
    results = []

    def add(tag, by):
        if not by:
            return
        txt = by.decode('utf-8', 'replace')
        pr = sum(1 for x in by[:600] if 32 <= x < 127 or x in (9, 10, 13)) / max(1, min(600, len(by)))
        hit = bool(FLAG_RE.search(txt))
        results.append((hit, pr, tag, by, txt))

    kbits = max(1, (N - 1).bit_length())
    # 每符号 k 位：N<=4 枚举所有单射映射，否则用自然序
    if N <= 4:
        code_perms = itertools.permutations(range(1 << kbits), N)
    else:
        code_perms = [tuple(range(N))]
    for oname, order in orders[:2] if N > 4 else [('码点序', sorted(alpha, key=ord))]:
        base_map = {c: i for i, c in enumerate(order)}
        for codes in code_perms:
            m = {c: codes[base_map[c]] for c in order}
            bits = ''.join(format(m[c], '0%db' % kbits) for c in t)
            for off in range(8):
                bb = bits[off:]
                bb = bb[:len(bb) // 8 * 8]
                if bb:
                    add('%s %dbit/符号 off%d' % (oname, kbits, off),
                        bytes(int(bb[i:i + 8], 2) for i in range(0, len(bb), 8)))
    # base-N 大整数（正/反序）
    for oname, order in orders[:2]:
        m = {c: i for i, c in enumerate(order)}
        for rev in (False, True):
            v = 0
            for c in (t[::-1] if rev else t):
                v = v * N + m[c]
            if v:
                add('%s base%d 大整数 rev=%s' % (oname, N, rev), v.to_bytes((v.bit_length() + 7) // 8, 'big'))
    # n 个符号 -> 1 字节
    for n in range(1, 9):
        if N ** n < 256:
            continue
        for oname, order in n_orders:
            m = {c: i for i, c in enumerate(order)}
            for rev in (False, True):
                by = bytearray()
                for i in range(0, len(t) - n + 1, n):
                    g = t[i:i + n]
                    if rev:
                        g = g[::-1]
                    v = 0
                    for c in g:
                        v = v * N + m[c]
                    by.append(v & 0xFF)
                add('%s %d符号/字节 rev=%s' % (oname, n, rev), bytes(by))
    # 观测到的符号可能只是完整字母表的子集（比如 8 种 emoji 只出现 6 种）
    # 再试更大的进制 R（R^N 种取值里选 N 个）
    extra_radices = sorted(set([r for r in (2, 4, 8, 16, 32, 64) if r > N] + [N + 1, N + 2, N + 3]))
    for R in extra_radices:
        if R > 64:
            continue
        maps = []
        for oname, order in orders[:2]:
            maps.append((oname, list(range(N))))
        if R <= 9 and N <= 6 and len(t) <= 4000:
            for p in itertools.permutations(range(R), N):
                maps.append(('排列', list(p)))
        n = 1
        while R ** n < 256:
            n += 1
        for oname, vals in maps[:30000]:
            for base_order_name, base_order in (orders[0], orders[1]):
                m = {c: vals[i] for i, c in enumerate(base_order)}
                for rev in (False, True):
                    by = bytearray()
                    for i in range(0, len(t) - n + 1, n):
                        g = t[i:i + n]
                        if rev:
                            g = g[::-1]
                        v = 0
                        for c in g:
                            v = v * R + m[c]
                        by.append(v & 0xFF)
                    add('R%d %s %d符号/字节 rev=%s' % (R, oname, n, rev), bytes(by))
    if not results:
        return
    results.sort(key=lambda x: (-x[0], -x[1]))
    for _hit, _pr, _tag, _by, _txt in results[:12]:
        if _hit:
            scan_flags(_txt, _tag)
            add_result(_txt[:200], _tag)
    note('  共试 %d 种通用解释，最像的前 6 个：' % len(results))
    for hit, pr, tag, by, txt in results[:6]:
        view = ''.join(chr(x) if 32 <= x < 127 else '.' for x in by[:60])
        note('    %s %-28s 可打印率%.2f -> %s' % ('★' if hit else ' ', tag, pr, view))
        if hit:
            note('        *** 命中 flag: %s' % (FLAG_RE.search(txt).group(0)))

def text_analyze(s):
    if _is_final_flag(s):
        scan_flags(s, '原文')
        note('这段文本里已经是完整 flag（已知前缀），跳过后续暴力变换，避免产生一堆假 flag')
        return
    decode_chain(s)
    try:
        symbol_analyze(s)
    except Exception as _e:
        note('通用符号表分析跳过: %s' % _e)
    scan_base64_blobs(s, '文本内嵌base64')
    try_vigenere(s)
    rsa_analyze(s)
    caesar_bruteforce(s[:4000])
    xor_bruteforce(s[:20000])
    hash_analyze(s)
    jwt_analyze(s)
    # 0/1
    bits = re.sub(r'[^01]', '', s)
    if len(bits) > 100 and len(bits) / max(1, len(s)) > 0.5:
        head('发现大量 0/1 数据，尝试拼图')
        n = int(round(len(bits) ** 0.5))
        note('%d 个 0/1 字符' % len(bits))
        if n * n == len(bits):
            note('%d = %d x %d 正好正方形 → 拼成图片并扫码' % (len(bits), n, n))
            p = save('01数据.txt', bits)
            analyze(p, 1)   # 进程内递归，结果直接进汇总
        else:
            note('不是完全平方数（%d），可能要先按行/列切' % len(bits))
# ============================================================
#                    暴 力 调 度 主 引 擎
# ============================================================
SUGGEST = []

def suggest(msg):
    if msg not in SUGGEST:
        SUGGEST.append(msg)

PATHS = OrderedDict()          # flag -> 解题路径
_RSA_DONE = [False]
_VIG_DONE = [False]
_HUNT_N = [0]

def run_hunt(text, label='穷举'):
    """全路线穷举：把所有可能的变换组合层层展开，找出通往 flag 的路径"""
    try:
        import hunt as H
    except Exception as e:
        note('穷举引擎加载失败: %s' % e)
        return []
    if _HUNT_N[0] >= 3:
        return []
    _HUNT_N[0] += 1
    head('全路线穷举（把所有能组合的变换都铺开试一遍）')
    note('变换器共 %d 种，逐层展开，最多 6 层' % len(H.TRANSFORMS))
    try:
        res = H.hunt(text, max_depth=6, beam=30, verbose=lambda m: note(m))
    except Exception as e:
        note('穷举出错: %s' % e)
        return []
    if res:
        for flag, path, _ in res[:8]:
            route = ' → '.join(path)
            note('')
            note('★ 找到 flag: %s' % flag)
            note('   解题路径: %s' % route)
            add_flag(flag, '穷举路线:' + route)
            if flag not in PATHS:
                PATHS[flag] = path
    else:
        note('穷举没找到 flag —— 说明这题不是纯编码/密码链，需要换方向（看下面的建议）')
        suggest('穷举走不通 → 这题可能需要看别的方向（图片/流量/逆向/Git），不是编码题')
    return res
def scan_all_files_for_flags(folder, limit=200):
    n = 0
    for r, ds, fs in os.walk(folder):
        for fn in fs:
            if n >= limit:
                return
            fp = os.path.join(r, fn)
            try:
                if os.path.getsize(fp) > 2 * 1024 * 1024 and os.path.splitext(fn)[1].lower() not in (
                    '.txt', '.md', '.json', '.xml', '.csv', '.html', '.js', '.py', '.yaml', '.yml'
                ):
                    continue
                b = read_bytes(fp, 4 * 1024 * 1024)
            except Exception:
                continue
            if fn in ('报告.md',):
                continue
            n += 1
            try:
                t = b.decode('utf-8')
            except UnicodeDecodeError:
                continue
            if not t.strip():
                continue
            scan_flags(t, '产出文件:' + fn)
            scan_base64_blobs(t, '产出文件:' + fn)

def video_analyze(path, data):
    """Extract audio and a frame contact sheet from common video containers."""
    head('视频容器：音轨 / 抽帧 / 联系表')
    ffmpeg = tool(r'01-通用工具\ffmpeg\ffmpeg.exe')
    if not ffmpeg:
        note('找不到 ffmpeg，无法自动抽音轨/抽帧')
        return
    base = os.path.splitext(os.path.basename(path))[0]
    wav = outpath(base + '_音轨.wav')
    o = run([ffmpeg, '-y', '-i', path, '-vn', '-ac', '2', '-ar', '44100', wav], timeout=180)
    if os.path.isfile(wav) and os.path.getsize(wav) > 44:
        note('  ★ 已抽出音轨: %s' % wav)
        try:
            audio_analyze(wav, read_bytes(wav))
        except Exception as _e:
            note('  音轨分析失败: %s' % _e)
    else:
        note('  没有可用音轨，或 ffmpeg 抽取失败')
    sheet = outpath(base + '_每秒联系表.png')
    run([ffmpeg, '-y', '-i', path, '-vf', 'fps=1,scale=320:180,tile=6x6',
         '-frames:v', '1', sheet], timeout=180)
    if os.path.isfile(sheet):
        note('  ★ 视频每秒联系表: %s' % sheet)

def analyze(path, depth=0):
    global CUR_DEPTH
    CUR_DEPTH = depth
    if depth > 4:
        return
    if depth == 0:            # 每次顶层分析重置"穷举预算"
        _HUNT_N[0] = 0
    if not os.path.isfile(path):
        # 也许是目录（Git 仓库等）
        if os.path.isdir(path):
            if not git_analyze(path, depth):
                say('  这是个目录，但没发现 .git 仓库')
            return
        say('  找不到: ' + path)
        return
    try:
        size = os.path.getsize(path)
    except Exception as e:
        say('  读不到文件: %s' % e)
        return

    head('开始分析: %s  (%d 字节)' % (os.path.basename(path), size))
    try:
        data = read_bytes(path, 64 * 1024 * 1024)
    except Exception as e:
        say('  读取失败: %s' % e)
        return

    kind, name = sniff(data)
    diag('triage', 'done', '按文件头/结构判断类型',
         assumption='文件头比后缀可靠；未知类型仍会继续尝试兜底分析',
         evidence='%s / %s / %d bytes' % (kind, name, len(data)),
         artifacts=[path], next_action='若类型判断可疑，用 DetectItEasy/ImHex 复核',
         confidence='high' if kind != 'unknown' else 'low')
    note('真实类型: %s' % name)
    ext = os.path.splitext(path)[1].lstrip('.').lower()
    # ---- 补充识别：apk / wasm / dex（sniff 认不出来，但很好认）----
    if data[:4] == b'RIFF' and data[8:12] == b'WEBP':
        kind = 'webp'
    elif data[:4] == b'\x00\x00\x01\x00':
        kind = 'ico'
    elif data[:4] in (b'II*\x00', b'MM\x00*'):
        kind = 'tiff'
    if ext == 'apk':
        kind = 'apk'
    elif data[:4] == b'\x00asm' or ext == 'wasm':
        kind = 'wasm'
    elif data[:4] == b'dex\n' or ext == 'dex':
        kind = 'dex'

    if ext and ext != kind and kind not in ('unknown', 'text'):
        note('⚠ 后缀 .%s 和真实类型不符 —— "改后缀"是常见套路' % ext)
        suggest('后缀名可以造假 —— 想知道真实类型，用 ImHex 看文件头')

    # ---------- 通用：先扫 flag ----------
    try:
        scan_flags(data.decode('utf-8', 'replace'), '原文')
    except Exception:
        pass

    # ---------- 按类型分派 ----------
    try:
        if kind == 'datauri':
            head('Data URI：把伪装成文字的文件拆出来')
            try:
                t = data.decode('utf-8', 'replace').strip()
                comma = t.find(',')
                head_part = t[:comma]
                note('说明部分: ' + head_part[:80])
                body = t[comma+1:].strip()
                out = os.path.join(OUTDIR, os.path.splitext(os.path.basename(path))[0] + '_解出来.bin')
                os.makedirs(OUTDIR, exist_ok=True)
                if 'base64' in head_part:
                    b = base64.b64decode(re.sub(r'\s', '', body) + '=' * (-len(re.sub(r'\s', '', body)) % 4))
                else:
                    b = urllib.parse.unquote_to_bytes(body)
                with open(out, 'wb') as fh:
                    fh.write(b)
                note('★ 解出 %d 字节 -> %s' % (len(b), out))
                why('data: URI 是"把文件内容直接写成一段文字"，逗号后面才是真正的数据')
                analyze(out, depth + 1)
            except Exception as e:
                note('拆解失败: %s' % e)
                suggest('data:URI 解不开，检查逗号后面的内容是否完整')

        elif kind == 'bits':
            head('0/1 数据：尝试拼成图片')
            t = data.decode('utf-8', 'replace')
            bits = re.sub(r'[^01]', '', t)
            note('共 %d 个 0/1 (0=%d, 1=%d)' % (len(bits), bits.count('0'), bits.count('1')))
            n = int(round(len(bits) ** 0.5))
            if n * n == len(bits):
                note('★ %d = %d x %d 正好正方形 → 拼图' % (len(bits), n, n))
                why('总数是完全平方数 → 每个 0/1 当一个像素，排成正方形才是图')
                try:
                    from PIL import Image
                    import numpy as np
                    for inv in (False, True):
                        a = np.array([1 if c == '1' else 0 for c in bits], dtype='uint8').reshape(n, n)
                        if inv:
                            a = 1 - a
                        img = Image.fromarray((a * 255).astype('uint8'), 'L')
                        p = os.path.join(OUTDIR, '01_%s.png' % ('inverted' if inv else 'normal'))
                        os.makedirs(OUTDIR, exist_ok=True)
                        img.save(p)
                        note('已生成: %s' % p)
                    # 顺手扫码（改成进程内调用，结果才能进汇总）
                    for _nm2 in ('01_normal.png', '01_inverted.png'):
                        qr_scan_all(os.path.join(OUTDIR, _nm2), '0/1还原的图')
                except Exception as e:
                    note('拼图失败: %s' % e)
            else:
                note('不是完全平方数（%d = %s）' % (len(bits), int(n) ** 2))
                suggest('0/1 数量不是平方数，可能要先按行切分（看题目有没有给宽高）')

        elif kind in ('png', 'jpg', 'gif', 'bmp', 'webp', 'ico', 'tiff'):
            _usepath = path
            if kind == 'png':
                try:
                    _fx = png_try_fix(path, data)
                    if _fx:
                        _usepath = _fx
                        note('  → 后续分析改用修复版图片')
                except Exception as _e:
                    note('  修复尝试失败: %s' % _e)
            image_analyze(_usepath, read_bytes(_usepath) if _usepath != path else data)
            suggest('图片题还可以: 改后缀成 .zip 用 7-Zip 打开 / 用 StegSolve 翻颜色通道')

        elif kind in ('zip', 'rar', '7z', 'gz', 'bz2', 'xz', 'tar'):
            archive_analyze(path, data)
            if ADV and kind == 'zip':
                # 同一文件里可能出现多个 EOCD/中央目录，不同解压器会看到不同条目。
                try:
                    views = ADV.zip_polyglot_views(data)
                    if len(views) > 1:
                        head('ZIP 多视图/多 EOCD 异常')
                        joined = bytearray()
                        for idx, view in enumerate(views, 1):
                            note('  视图 %d: EOCD=%d, CD=%d, entries=%d, names=%s' % (
                                idx, view['eocd'], view['cd_offset'], view['entries'],
                                ','.join(view['names'][:6])))
                            joined += view['data']
                        txt = bytes(joined).decode('utf-8', 'replace')
                        scan_flags(txt, 'ZIP多EOCD视图拼接')
                        save('zip_all_eocd_views.bin', bytes(joined))
                        why('合规 ZIP 不应有多个互相矛盾的 EOCD；不同解压器选不同视图，把各视图内容拼起来常能恢复完整 flag')
                    entries = ADV.zip_local_entries(data)
                    if entries:
                        note('  本地文件头总数: %d（标准 zipfile 可能只显示一部分）' % len(entries))
                        names = [e['name'] for e in entries]
                        scan_flags('\n'.join(names), 'ZIP全部本地文件名')
                        for entry in entries:
                            if entry['encrypted'] or len(entry['data']) > 2 * 1024 * 1024:
                                continue
                            try:
                                t = entry['data'].decode('utf-8')
                            except Exception:
                                continue
                            scan_flags(t, 'ZIP本地条目:' + entry['name'])
                except Exception as _e:
                    note('ZIP 多视图分析失败: %s' % _e)
            # 递归解压
            if depth < 4:
                ex = os.path.join(OUTDIR, os.path.splitext(os.path.basename(path))[0] + '_解压')
                os.makedirs(ex, exist_ok=True)
                ok = False
                if kind == 'zip':
                    try:
                        _z = zipfile.ZipFile(io.BytesIO(data))
                        _tot = sum(i.file_size for i in _z.infolist())
                        if _tot > 400 * 1024 * 1024:
                            note('⚠ 压缩包解开会超过 400MB（疑似压缩炸弹），跳过自动解压' % ())
                        else:
                            _z.extractall(ex)
                        ok = True
                    except Exception as e:
                        note('自动解压失败: %s' % e)
                else:
                    sz = r'C:\Program Files\7-Zip\7z.exe'
                    if os.path.isfile(sz):
                        o = run([sz, 'x', '-y', '-o' + ex, path], timeout=120)
                        ok = os.path.isdir(ex)
                if ok:
                    inner = []
                    for r, ds, fs in os.walk(ex):
                        for fn in fs:
                            inner.append(os.path.join(r, fn))
                    note('★ 已自动解压，继续分析里面 %d 个文件...' % len(inner))
                    try:
                        scan_all_files_for_flags(ex, limit=5000)
                    except Exception:
                        pass
                    for fp in inner[:12]:
                        analyze(fp, depth + 1)

        elif kind == 'apk':
            apk_analyze(path, data)

        elif kind == 'wasm':
            wasm_analyze(path, data)

        elif kind == 'dex':
            binary_analyze(path, data)

        elif kind == 'pdf':
            pdf_analyze(path, data)

        elif kind == 'pcap':
            pcap_analyze(path, data)

        elif kind in ('exe', 'elf'):
            binary_analyze(path, data)

        elif kind in ('mkv', 'mp4', 'mov', 'avi', 'webm'):
            video_analyze(path, data)

        elif kind in ('riff', 'mp3', 'ogg', 'flac'):
            audio_analyze(path, data)

        elif kind == 'unknown' and size > 4 * 1024 * 1024:
            note('大未知文件：只做抽样 strings / 文件头检查，避免把磁盘镜像当普通二进制全量扫描')
            sample = data[:2 * 1024 * 1024]
            try:
                scan_flags(sample.decode('latin-1', 'replace'), '大未知文件抽样')
            except Exception:
                pass
            diag('dispatch', 'done', '大未知文件抽样分析',
                 assumption='未知大文件更可能是磁盘/容器/加密块，需要先识别结构',
                 evidence='%d bytes' % size, artifacts=[path],
                 next_action='先看文件头/分区/RAID 元数据；若确认是普通二进制再做完整 strings')

        else:
            # 文本 / 未知 → 当文本处理
            t = None
            try:
                t = data.decode('utf-8')
            except Exception:
                pass
            if t is None:
                try:
                    t = data.decode('gbk')
                except Exception:
                    t = data.decode('latin-1')
            import unicodedata as _ud2
            print_ok = sum(1 for ch in t[:3000]
                           if ch in '\r\n\t' or _ud2.category(ch) not in ('Cc', 'Cs', 'Co', 'Cn'))
            if print_ok / max(1, len(t[:3000])) > 0.7:
                if ADV:
                    try:
                        for _vh in ADV.vigenere_url_candidates(t):
                            note('  ★ 题面密钥线索: key=%s' % _vh['key'])
                            note('    Vigenere 解密: %s' % _vh['plain'][:220])
                            note('    隐藏 URL: %s' % _vh['url'])
                            _media = ADV.download_public_video(_vh['url'], OUTDIR)
                            if _media:
                                note('  ★ 已下载公开媒体: %s' % _media)
                                analyze(_media, depth + 1)
                            else:
                                note('    （未能自动下载；可手动打开上述 URL 继续）')
                    except Exception as _ve:
                        note('题面密钥 URL 分析失败: %s' % _ve)
                if len(t) > 16000 or depth > 0:
                    scan_flags(t, '大文本/归档原文')
                    try:
                        scan_base64_blobs(t, '大文本/归档base64')
                    except Exception:
                        pass
                    note('大文本或归档内文本（%d 字符）先做快速扫描，跳过开销很大的穷举解码' % len(t))
                else:
                    text_analyze(t)
                if ADV:
                    try:
                        _missing = ADV.missing_letters(t)
                        _common_missing = [x for x in _missing if x in 'etaoinshrdlu']
                        if _common_missing and len(t) >= 1000:
                            note('  ！文本异常缺失常见字母: %s（疑似 lipogram/删除字符编码）' % ', '.join(_common_missing))
                            suggest('缺失字符题：先对比每个文本片段共同缺失的字母，再结合题目标题/文件顺序寻找编码')
                    except Exception:
                        pass
                if ADV and ext in ('py', 'js', 'ts', 'rs', 'java', 'go', 'php'):
                    try:
                        routes = ADV.source_routes(t)
                        if routes:
                            head('源码路由清单（可作为 Web 手工验证入口）')
                            for r in routes[:40]:
                                note('  %-6s %s  (第 %d 行)' % (r['method'], r['path'], r['line']))
                            suggest('Web 源码题：逐条用浏览器或 Burp 验证路由；重点看无鉴权路由、参数入口和返回静态文件的接口')
                    except Exception as _re:
                        note('源码路由提取失败: %s' % _re)
                    try:
                        findings = ADV.source_audit(t)
                        if findings:
                            head('源码审计线索（通用静态规则）')
                            for f in findings[:20]:
                                note('  [%s] 第 %d 行: %s' % (f['type'], f['line'], f['code'][:180]))
                                note('     为什么: %s' % f['why'])
                                note('     下一步: %s' % f['next'])
                    except Exception as _e:
                        note('源码审计失败: %s' % _e)
                    if ext == 'py' and 'random.seed' in t and 'randint' in t and 'kernel' in t:
                        try:
                            import advanced as _ADV2
                            from pathlib import Path as _Path
                            _cands = _ADV2.convolution_candidates_from_source(_Path(path), t, OUTDIR)
                            if _cands:
                                head('源码卷积参数反演 / Wiener 反卷积')
                                note('从源码推断随机核，生成了 %d 个反卷积候选' % len(_cands))
                                for _cand in _cands[:30]:
                                    try:
                                        _a = _imread(_cand['png'])
                                        if _a is not None:
                                            _g = _a if _a.ndim == 2 else _a[:, :, 1]
                                            ocr_and_harvest(_g, '反卷积通道%d' % _cand['channel'], force=True)
                                    except Exception:
                                        pass
                        except Exception as _e:
                            note('卷积反演失败: %s' % _e)
            else:
                note('看起来是二进制且不是常见格式')
                note('顺手跑一遍 XOR 爆破（很多密文题就是一段裸二进制）')
                xor_bruteforce(data[:20000])
                binary_analyze(path, data)
    except Exception as e:
        diag('dispatch', 'error', '当前分析分支异常',
             assumption='异常不一定代表题目无解，只代表这条自动路线中止',
             evidence=repr(e), next_action='查看诊断日志末段，回到对应路线用手工工具复核',
             confidence='low')
        note('这个方向的分析出错了: %s' % e)
        note('(不影响其他分析, 继续)')

    # ---------- 全路线穷举（兜底暴力，只对文本类跑）----------
    if depth <= 1 and kind in ('text', 'datauri') and size < 12000:
        try:
            txt = data.decode('utf-8', 'replace')
            if sum(1 for ch in txt[:3000] if 32 <= ord(ch) < 127 or ch in '\r\n\t') / max(1, len(txt[:3000])) > 0.9:
                run_hunt(txt)
        except Exception as e:
            note('穷举跳过: %s' % e)
    elif depth == 0 and kind == 'unknown' and size < 6000:
        try:
            txt = data.decode('latin-1')
            run_hunt(txt)
        except Exception:
            pass

    # ---------- 复合文件检测：整个文件里还藏着别的文件？ ----------
    try:
        import poly as _PL
        if size > 4 * 1024 * 1024 and kind not in ('image', 'archive', 'apk'):
            note('文件较大（%d 字节），跳过无限递归式内嵌文件雕刻' % size)
            diag('composite', 'skipped', '跳过大文件自动雕刻',
                 why='大磁盘镜像/二进制里可能有大量伪文件头，递归雕刻会严重拖慢分析',
                 assumption='先判断容器/文件系统，再决定 carve 或 mount',
                 evidence='%d bytes' % size, next_action='用 7-Zip/ImHex/文件系统工具分阶段分析；不要连续点自动 carve')
            raise StopIteration
        _hits = [h for h in _PL.find_embedded(data) if h[0] != 0 and (os.path.basename(path), h[0]) not in _EMBED_DONE]
        _hits = [h for h in _PL.find_embedded(data) if h[0] != 0 and (os.path.basename(path), h[0]) not in _EMBED_DONE]
        if _hits:
            head('复合文件检测（这个文件里还嵌着别的东西）')
            for _off, _end, _kind, _blob in _hits[:6]:
                _EMBED_DONE.add((os.path.basename(path), _off))
                note('  ★ 偏移 %d..%d 是一个 %s（%d 字节）' % (_off, _end, _kind, _end - _off))
                _p = save('内嵌_%d.%s' % (_off, _kind), _blob)
                note('     已切出 -> %s' % os.path.basename(_p))
                try:
                    analyze(_p, depth + 1)
                except Exception as _e:
                    note('     继续分析失败: %s' % _e)
            suggest('这是"复合文件"（一个文件里塞了多种格式）—— 上面切出来的每个都要看')
    except StopIteration:
        pass
    except Exception as _e:
        note('复合文件检测出错: %s' % _e)

    # ---------- 容器解包 + Git 探测（不管什么类型都试）----------
    if kind in ('gz', 'bz2', 'xz', 'tar') or path.lower().endswith(('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tar.xz')):
        head('压缩容器：解开看看里面')
        dest = os.path.join(OUTDIR, os.path.splitext(os.path.basename(path))[0] + '_解开')
        os.makedirs(dest, exist_ok=True)
        ok = False
        try:
            with tarfile.open(path) as tf:
                tf.extractall(dest, filter='data')
            ok = True
        except Exception:
            pass
        if not ok:
            sz = r'C:\Program Files\7-Zip\7z.exe'
            if os.path.isfile(sz):
                run([sz, 'x', '-y', '-o' + dest, path], timeout=120)
                ok = os.path.isdir(dest) and any(os.scandir(dest))
        if ok:
            inner = [os.path.join(r, fn) for r, ds, fs in os.walk(dest) for fn in fs]
            note('解开 %d 个文件' % len(inner))
            if git_analyze(dest, depth):
                pass
            else:
                for fp in inner[:8]:
                    analyze(fp, depth + 1)
        else:
            note('解不开这个容器')

# ============================================================
#                    主 入 口
# ============================================================
def _conf(v, where):
    """给候选打可信度分，越像真 flag 分越高"""
    s = 0.0
    pre = v.split('{')[0].lower()
    if pre in ('flag', 'ctf', 'c404', 'fleg', 'key', 'nss', 'buu', 'hgame', 'rjsb', 'flag1'):
        s += 6
    w = ' '.join(sorted(where)).lower()
    for kw, b in (('git碎片', 6), ('二维码', 5), ('哈希', 4), ('lsb', 4), ('xor', 3),
                  ('编码链', 3), ('png文本', 3), ('内嵌base64', 3), ('0/1', 3),
                  ('exif', 2), ('strings', 0.5), ('原文', 0.5), ('产出文件', 0)):
        if kw in w:
            s += b
    if 8 <= len(v) <= 80:
        s += 1
    return s
def final_report(target):
    say('')
    say('  ' + '=' * 60)
    say('   汇  总')
    say('  ' + '=' * 60)
    real, fake = [], []
    for v, where in FLAGS.items():
        if FAKE_HINT.search(v):
            fake.append((v, where))
        else:
            real.append((v, where))
    if HINTS:
        say('')
        say('   ' + '=' * 54)
        say('   ★ ★ ★   你 现 在 要 做 的 事（别跳过）')
        say('   ' + '=' * 54)
        for lv, t in sorted(HINTS, key=lambda z: -z[0]):
            say('   [%d] %s' % (lv, t))
        say('   ' + '=' * 54)
    real.sort(key=lambda t: -_conf(t[0], t[1]))
    if real:
        say('')
        say('   ★ flag 候选（共 %d 个，按可信度排序）:' % len(real))
        for i, (v, where) in enumerate(real[:15], 1):
            say('      [%d] %s' % (i, v))
            if v in PATHS:
                say('          ★ 解题路径: ' + ' → '.join(PATHS[v]))
            else:
                say('          来自: %s' % ', '.join(sorted(where))[:120])
    else:
        say('')
        say('   没有自动找到 flag 格式的字符串。')

    if fake:
        say('')
        say('   ⚠ 疑似"假 flag"（含 fake/test 等字样，出题人用来骗你的）:')
        for v, _ in fake[:5]:
            say('      ' + v)

    _res = [v for v in RESULTS if v not in FLAGS]
    if _res:
        say('')
        say('   ★ 解出来的内容（不是 flag 格式，但很可能就是答案）:')
        for v in _res[:12]:
            say('      ' + v[:120])
            say('          来自: ' + ', '.join(sorted(RESULTS[v]))[:100])
    if SUGGEST:
        say('')
        say('   接下来可以试（按顺序）:')
        for i, s in enumerate(SUGGEST[:10], 1):
            say('      %d) %s' % (i, s))

    say('')
    say('   产出文件都在: ' + OUTDIR)
    say('   报告: ' + os.path.join(OUTDIR, '报告.md'))
    say('')
    say('   (还是没头绪的话: 打开 暴力插件\\题解库.html 按题型找对应章节)')

# ============ 大工具启动器（补进来的）============
def launch_tools():
    """列出并启动工具箱里的大工具（不用记路径）"""
    import subprocess as _sp
    ITEMS = [
        ('1',  'CyberChef（在线官方版）',        'URL', 'https://gchq.github.io/CyberChef/'),
        ('2',  'Wireshark（流量分析）',           'EXE', r'C:\Program Files\Wireshark\Wireshark.exe'),
        ('3',  'DetectItEasy（查文件类型/加壳）', 'EXE', r'03-杂项与取证\DetectItEasy\die\die.exe'),
        ('4',  'ImHex（十六进制编辑器）',         'EXE', r'03-杂项与取证\ImHex\imhex.exe'),
        ('5',  'StegSolve（图片通道）',           'JAR', r'03-杂项与取证\StegSolve\stegsolve.jar'),
        ('6',  'OpenStego（图片隐写 GUI）',       'EXE', r'03-杂项与取证\图片隐写\OpenStego\openstego-0.8.6\openstego.bat'),
        ('7',  'dnSpy（.NET 逆向）',              'EXE', r'05-逆向\dnSpy\dnSpy.exe'),
        ('8',  'x64dbg（动态调试）',              'EXE', r'05-逆向\x64dbg\release\x96dbg.exe'),
        ('9',  'Ghidra（静态反编译）',            'EXE', r'05-逆向\Ghidra\ghidra_12.1.4_PUBLIC\ghidraRun.bat'),
        ('10', 'jadx（安卓 apk）',                'EXE', r'05-逆向\jadx\jadx-gui-1.5.6.exe'),
        ('11', 'Audacity（音频频谱）',            'EXE', r'C:\Program Files\Audacity 4\bin\Audacity4.exe'),
        ('12', 'CTF Wiki（在线教程）',            'URL', 'https://ctf-wiki.org/'),
        ('13', '打开暴力分析输出目录',             'DIR', os.path.join(tempfile.gettempdir(), 'CTF暴力分析')),
        ('14', '打开工具箱目录',                  'DIR', ROOT),
    ]
    while True:
        print()
        print('  ============== 大 工 具 启 动 器 ==============')
        for k, name, kind, path in ITEMS:
            print('     %2s. %s' % (k, name))
        print('      0. 返回')
        print()
        try:
            sel = input('  输入编号: ').strip()
        except EOFError:
            return
        if sel == '0' or not sel:
            return
        it = next((x for x in ITEMS if x[0] == sel), None)
        if not it:
            print('  没有这个编号'); continue
        k, name, kind, path = it
        try:
            if kind == 'URL':
                import webbrowser; webbrowser.open(path); print('  已用浏览器打开: %s' % path)
            elif kind == 'DIR':
                if os.path.isdir(path): os.startfile(path); print('  已打开目录')
                else: print('  目录不存在: %s' % path)
            elif kind == 'JAR':
                j = os.path.join(ROOT, r'01-通用工具\Java21\bin\java.exe')
                p = os.path.join(ROOT, path)
                if os.path.isfile(j) and os.path.isfile(p):
                    _sp.Popen([j, '-jar', p]); print('  已启动: %s' % name)
                else: print('  找不到 Java 或 jar')
            else:
                p = path if os.path.isabs(path) else os.path.join(ROOT, path)
                if os.path.isfile(p):
                    _sp.Popen([p], cwd=os.path.dirname(p)); print('  已启动: %s' % name)
                else:
                    print('  找不到: %s' % p)
                    print('  （工具不在这个位置的话，去 %s 下找）' % ROOT)
        except Exception as e:
            print('  启动失败: %s' % e)
        print()
def main():
    global OUTDIR
    args = [a for a in sys.argv[1:]]
    quiet = '--quiet' in args
    args = [a for a in args if a != '--quiet']
    text = None
    if '--password' in args:
        _i = args.index('--password')
        if _i + 1 < len(args):
            EXTRA_PW.append(args[_i + 1])
            args = args[:_i] + args[_i + 2:]
    if '--text' in args:
        i = args.index('--text')
        text = ' '.join(args[i+1:])
        args = args[:i]
    target = ' '.join(args).strip().strip('"') if args else None

    # --tools 模式：直接开大工具（CyberChef / Wireshark / dnSpy 等）
    if target in ('--tools', 'tools', '-t'):
        launch_tools()
        return
    if not target and text is None:
        if not sys.stdin.isatty():
            text = sys.stdin.read()
        if not text:
            print(__doc__)
            print('用法:')
            print('  python super.py 题目文件            # 分析文件')
            print('  python super.py "一段乱码"          # 当文本分析')
            print('  echo 乱码 | python super.py --text  # 从管道读')
            return

    if target and os.path.exists(target):
        base = os.path.splitext(os.path.basename(target))[0]
    else:
        base = '文本'
    OUTDIR = os.path.join(tempfile.gettempdir(), 'CTF暴力分析', base)
    os.makedirs(OUTDIR, exist_ok=True)

    if not quiet:
        say('')
        say('  ╔' + '═' * 58 + '╗')
        say('  ║    C T F   暴 力 分 析 引 擎   v1                        ║')
        say('  ║    所有能试的自动全试一遍, 最后汇总 flag 候选             ║')
        say('  ╚' + '═' * 58 + '╝')
        say('')
        say('   输出目录: ' + OUTDIR)

    t0 = time.time()
    if target and os.path.exists(target):
        analyze(target, 0)
        # 把产出目录里所有文件也扫一遍 flag
        try:
            scan_all_files_for_flags(OUTDIR, 120)
        except Exception:
            pass
    else:
        head('文本分析: %s' % (text[:60].replace('\n', ' ') + ('...' if len(text) > 60 else '')))
        text_analyze(text)

    if not quiet:
        final_report(target)
        say('   耗时 %.1f 秒' % (time.time() - t0))

    # 写报告
    try:
        with open(os.path.join(OUTDIR, '报告.md'), 'w', encoding='utf-8') as fh:
            fh.write('# CTF 暴力分析报告\n\n')
            fh.write('- 目标: %s\n' % (target or '（文本）'))
            fh.write('- 时间: %s\n\n' % time.strftime('%Y-%m-%d %H:%M:%S'))
            fh.write('## 分析过程\n\n```\n')
            fh.write('\n'.join(NOTES))
            fh.write('\n```\n\n## flag 候选\n\n')
            for v, where in FLAGS.items():
                fh.write('- `%s`  ← %s\n' % (v, ', '.join(sorted(where))[:150]))
            fh.write('\n## 下一步建议\n\n')
            for s in SUGGEST:
                fh.write('- %s\n' % s)
    except Exception:
        pass

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n  [中断]')
    except Exception as e:
        import traceback
        print('\n  [程序出错] %s' % e)
        print('  （这不影响你手动分析，把报错发给我我修）')
        traceback.print_exc()
