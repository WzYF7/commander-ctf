# -*- coding: utf-8 -*-
"""hunt —— 全路线穷举：把所有编码/密码变换层层组合，找出通往 flag 的路径
（原来是"暴力插件"里的模块，合并时丢了，这里重新实现，接口保持一致）"""
import base64, binascii, codecs, re

FLAG_RE = re.compile(r'[\w\u4e00-\u9fff]{2,20}\{[^}\n]{3,150}\}')

def _b64(s):
    t = s.strip().replace('\n', '')
    if len(t) < 8: return None
    return base64.b64decode(t + '=' * (-len(t) % 4))

def _b64url(s):
    t = s.strip()
    if len(t) < 8: return None
    return base64.urlsafe_b64decode(t + '=' * (-len(t) % 4))

def _b32(s):
    t = s.strip().upper()
    if len(t) < 8: return None
    return base64.b32decode(t + '=' * (-len(t) % 8))

def _b85(s):
    return base64.b85decode(s.strip().encode())

def _a85(s):
    return base64.a85decode(s.strip().encode())

def _hex(s):
    t = re.sub(r'[^0-9a-fA-F]', '', s)
    if len(t) < 4 or len(t) % 2: return None
    return binascii.unhexlify(t)

def _morse(s):
    M = {'.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G','....':'H',
         '..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N','---':'O','.--.':'P',
         '--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X',
         '-.--':'Y','--..':'Z','.----':'1','..---':'2','...--':'3','....-':'4','.....':'5',
         '-....':'6','--...':'7','---..':'8','----.':'9','-----':'0'}
    if not re.fullmatch(r'[.\-\s/]+', s.strip()): return None
    return ' '.join(''.join(M.get(c, '?') for c in w.split()) for w in s.split('/'))

def _rot13(s):
    return codecs.decode(s, 'rot_13') if (s.isalpha() or ' ' in s) else None

def _rev(s):
    return s[::-1]

def _caesar(s, k):
    if not s.isalpha(): return None
    return ''.join(chr((ord(c) - 65 + k) % 26 + 65) if c.isupper()
                   else chr((ord(c) - 97 + k) % 26 + 97) if c.islower() else c for c in s)

def _unpad(s):
    return s.strip()

def keep_utf8(b):
    try: return b.decode('utf-8')
    except Exception: return None

# 变换器表：每个是 (名字, 函数)。函数返回 str 或 None
TRANSFORMS = [
    ('b64',    lambda s: keep_utf8(_b64(s) or b'')),
    ('b64url', lambda s: keep_utf8(_b64url(s) or b'')),
    ('b32',    lambda s: keep_utf8(_b32(s) or b'')),
    ('b85',    lambda s: keep_utf8(_b85(s) or b'')),
    ('a85',    lambda s: keep_utf8(_a85(s) or b'')),
    ('hex',    lambda s: keep_utf8(_hex(s) or b'')),
    ('morse',  _morse),
    ('rot13',  _rot13),
    ('reverse', _rev),
    ('trim',   _unpad),
]
for _k in range(1, 26):
    TRANSFORMS.append(('caesar%d' % _k, (lambda k: (lambda s: _caesar(s, k)))(_k)))

def hunt(text, max_depth=6, beam=30, verbose=None):
    """层层组合变换，找 flag。返回 [(flag, 路径列表, 最终文本), ...]"""
    text = (text or '').strip()
    if not text: return []
    found, seen = [], {text}
    frontier = [(text, [])]
    for depth in range(max_depth):
        nxt = []
        for cur, path in frontier:
            m = FLAG_RE.search(cur)
            if m and m.group() not in [f for f, _, _ in found]:
                found.append((m.group(), path, cur))
                if verbose: verbose('  深度%d 命中: %s' % (depth, m.group()))
            for name, fn in TRANSFORMS:
                if name in path: continue
                try: nv = fn(cur)
                except Exception: nv = None
                if not nv or nv == cur or len(nv) > 400000: continue
                if nv in seen: continue
                seen.add(nv)
                nxt.append((nv, path + [name]))
                if len(nxt) >= beam * 3: break
            if len(nxt) >= beam * 3: break
        # 按"像不像有编码特征"排一下，保留 beam 条
        def sc(t):
            s = t[0]
            return -(1 if FLAG_RE.search(s) else 0) * 1000 - len(s)
        nxt.sort(key=sc)
        frontier = nxt[:beam]
        if not frontier: break
    return found