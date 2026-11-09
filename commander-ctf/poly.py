# -*- coding: utf-8 -*-
"""poly —— 零宽字符解码 + 复合文件检测
（原来是"暴力插件"里的模块，合并时丢了，这里重新实现，接口保持一致）"""
import re

ZW_MAP = {'\u200b':'0', '\u200c':'1', '\u200d':'1', '\ufeff':'1', '\u2060':'1'}
ZW_ALL = set(ZW_MAP.keys())

def zw_stats(text):
    return sum(1 for c in text if c in ZW_ALL)

def decode_zero_width(text):
    """把零宽字符解成文字。返回 [(结果, 方法名), ...]"""
    zw = [c for c in text if c in ZW_ALL]
    if len(zw) < 8:
        return []
    out = []
    # 方案1：200B=0 / 200C=1
    for label, mp in (('二进制(200B=0,200C=1)', {'\u200b':'0','\u200c':'1'}),
                      ('二进制(200B=0,200D=1)', {'\u200b':'0','\u200d':'1'})):
        bits = ''.join(mp.get(c, '') for c in zw)
        bits = bits[:len(bits) - len(bits) % 8]
        if not bits:
            continue
        try:
            s = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))
            if s.strip() and all(32 <= ord(ch) < 127 or ord(ch) > 127 for ch in s):
                out.append((s, label))
        except Exception:
            pass
    return out

# 常见文件头
_SIG = (
    (b'\x89PNG\r\n\x1a\n', 'png'), (b'\xff\xd8\xff', 'jpg'), (b'GIF8', 'gif'),
    (b'PK\x03\x04', 'zip'), (b'Rar!\x1a\x07', 'rar'), (b'7z\xbc\xaf\x27\x1c', '7z'),
    (b'%PDF', 'pdf'), (b'BM', 'bmp'), (b'\x1f\x8b\x08', 'gz'),
)

def _end_of(data, start, kind):
    if kind == 'png':
        i = data.find(b'IEND', start)
        return i + 8 if i > start else None
    if kind == 'jpg':
        i = data.find(b'\xff\xd9', start + 2)
        return i + 2 if i > start else None
    if kind == 'gif':
        i = data.find(b'\x3b', start + 6)
        return i + 1 if i > start else None
    if kind == 'zip':
        i = data.find(b'PK\x05\x06', start)
        if i > start:
            try:
                import struct
                clen = struct.unpack('<H', data[i+20:i+22])[0]
                return i + 22 + clen
            except Exception:
                return None
        return None
    if kind == 'pdf':
        i = data.find(b'%%EOF', start)
        return i + 5 if i > start else None
    return None

def find_embedded(data):
    """找文件里嵌着的其它文件。返回 [(起点, 终点, 类型, 内容), ...]"""
    hits = []
    for sig, kind in _SIG:
        i = data.find(sig)
        while i != -1:
            hits.append((i, kind))
            i = data.find(sig, i + 1)
    hits.sort()
    out, taken = [], []
    for off, kind in hits:
        if any(a <= off < b for a, b in taken):
            continue
        end = _end_of(data, off, kind)
        if end is None or end <= off:
            nxt = next((o for o, _ in hits if o > off), None)
            end = nxt if nxt else len(data)
        taken.append((off, end))
        out.append((off, end, kind, data[off:end]))
    return out

def emit(*a, **k):
    pass