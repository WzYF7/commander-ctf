# -*- coding: utf-8 -*-
"""编码解码向导 —— 把看不懂的一串东西粘进来，自动帮你试。

流程（先简单后复杂）：
  第 1 步 按标准编码解：base64 / base32 / 十六进制 / URL / 摩斯 / ROT13 / data:URI
  第 2 步 还解不出，才是"变种"：凯撒位移 / base64 换表
  第 3 步 都不行，就让你自己挑

（为什么这个顺序：标准编码能被程序直接判断出来，
 凯撒和换表属于"猜"，一上来就猜容易把正确答案顶掉。）"""
import os
import sys, base64, binascii, codecs, urllib.parse, re

# Windows 控制台默认用 GBK，遇到特殊字符会报 UnicodeEncodeError，这里强制用 UTF-8
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass

MORSE = {
    '.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G','....':'H',
    '..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N','---':'O','.--.':'P',
    '--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X',
    '-.--':'Y','--..':'Z','.----':'1','..---':'2','...--':'3','....-':'4','.....':'5',
    '-....':'6','--...':'7','---..':'8','----.':'9','-----':'0',
}
B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
FREQ = 'etaoinshrdlucmfwypvbgkjqxz'
FLAGWORDS = ('flag','ctf','fleg','key','nss','buu','hgame','ctfshow','c404')

def read_input(argv):
    """支持三种输入方式（哪个方便用哪个）：
       ① 直接给一个文件的路径 → 读文件内容
       ② 直接粘一段文字      → 用文字本身
       ③ 从管道/标准输入喂   → 读 stdin
       （为什么要有这个：在向导菜单里点时给的是"文件路径"，
         在命令行粘贴时给的是"内容"，两种都得能用）"""
    args = [a for a in argv[1:] if a]
    if args:
        p = args[0].strip('"').strip()
        if os.path.isfile(p):
            with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read().strip()
        return ' '.join(args).strip()
    try:
        return sys.stdin.read().strip()
    except Exception:
        return ''


def b58decode(t):
    """Base58 解码（比特币那种编码，没有 +/ 和 0OIl 这些易混字符）"""
    A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n = 0
    for c in t:
        if c not in A: raise ValueError('bad b58')
        n = n * 58 + A.index(c)
    if n == 0: return b''
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

def bindecode(t):
    """二进制串：每 8 个 0/1 是一个字节（例如 01000110 01001100 = FL）"""
    t = re.sub(r'[^01]', '', t)
    if len(t) < 8: raise ValueError('too short')
    t = t[:len(t) - len(t) % 8]
    return bytes(int(t[i:i+8], 2) for i in range(0, len(t), 8))

def morse(s):
    """摩斯电码：空格分词，/ 分单词"""
    if not re.fullmatch(r'[.\-\s/]+', s): return None
    out = []
    for w in s.split('/'):
        for ch in w.split(): out.append(MORSE.get(ch, '?'))
        out.append(' ')
    return ''.join(out).strip()

def looks_text(v):
    """像不像正常文字：可打印字符占比要够高"""
    if not v or len(v) < 3: return False
    ok = sum(1 for c in v if 32 <= ord(c) < 127 or '\u4e00' <= c <= '\u9fff')
    return ok / len(v) > 0.9

def has_flag(v):
    """有没有 flag 的样子（带花括号）"""
    return bool(v) and '{' in v and '}' in v

def eng_score(v):
    """像不像正常英文/flag，用来给凯撒结果排序。
       （原文本身带 {} 时，26 种位移结果全都带 {}，只能靠"读起来像不像人话"来挑）"""
    s = 0
    if '{' in v and v.split('{')[0].strip().lower() in FLAGWORDS: s += 100
    letters = [c.lower() for c in v if c.isalpha()]
    if letters:
        s += sum((26 - FREQ.index(c)) if c in FREQ else 0 for c in letters) / len(letters)
    return s

def is_base64ish(s):
    """本身能不能当 base64 直接解开"""
    raw = re.sub(r'[^A-Za-z0-9+/=]', '', s.replace('\n','').replace('\r',''))
    if len(raw) < 8 or len(raw) != len(s.strip()): return False
    try:
        return looks_text(base64.b64decode(raw + '=' * (-len(raw) % 4)).decode('utf-8'))
    except Exception:
        return False

def is_plainhex(s):
    """是不是纯十六进制（比如 666c6167 = flag）"""
    t = re.sub(r'\s', '', s)
    return len(t) >= 8 and len(t) % 2 == 0 and re.fullmatch(r'[0-9a-fA-F]+', t) is not None

def caesar_all(s):
    """凯撒密码：字母整体挪 1~25 位，全试"""
    out = []
    for k in range(1, 26):
        out.append(('凯撒移%2d位' % k, ''.join(
            chr((ord(c)-65+k)%26+65) if c.isupper() else
            chr((ord(c)-97+k)%26+97) if c.islower() else c for c in s)))
    return out

def basetable_all(s):
    """base64 换表：字母表整体循环挪 1~63 位再解"""
    out = []
    raw = re.sub(r'[^A-Za-z0-9+/=]', '', s)
    for rot in range(1, 64):
        tab = B64[rot:] + B64[:rot]
        try:
            d = base64.b64decode(raw.translate(str.maketrans(B64, tab)) + '=' * (-len(raw) % 4))
            t = d.decode('utf-8')
            if looks_text(t) or has_flag(t): out.append(('base64表位移%2d' % rot, t))
            if has_flag(t): break
        except Exception: pass
    return out

def xor_brute(s):
    """单字节异或爆破：把每个字节都异或同一个密钥，试 0~255。
       （异或是最简单的加密：同一个数异或两次会还原。CTF 里常出现，
        标准编码试不出来时值得一试）"""
    import string
    raw = None
    t = re.sub(r'[^0-9a-fA-F]', '', s)
    if len(t) >= 8 and len(t) == len(s.strip()) and len(t) % 2 == 0:
        try: raw = bytes.fromhex(t)
        except Exception: pass
    if raw is None: raw = s.encode('utf-8', 'ignore')
    PRINT = set(bytes(string.printable, 'ascii'))
    out = []
    for k in range(1, 256):
        d = bytes(b ^ k for b in raw)
        sc = sum(1 for b in d if b in PRINT) / max(1, len(d))
        txt = d.decode('utf-8', 'ignore')
        if has_flag(txt): out.append(('异或密钥0x%02x' % k, txt))
    return out

def rot47(s):
    """ROT47：对 ASCII 33~126 整体位移 47（大小写和符号一起转）
       （和凯撒只转字母不同，ROT47 转的是所有可打印字符，
        所以既可能出现在密码题里，也常被用来藏明文）"""
    return ''.join(chr(33 + ((ord(x) - 33 + 47) % 94)) if 33 <= ord(x) <= 126 else x for x in s)
def candidates(s, allow_rot13=True):
    """把所有标准编码都试一遍"""
    s = s.strip().replace('\n','').replace('\r','')
    out = []
    def add(name, v):
        if isinstance(v, bytes):
            try: v = v.decode('utf-8')
            except UnicodeDecodeError: return
        v = (v or '').strip()
        if v and v != s: out.append((name, v))
    pad = lambda t, n: t + '=' * (-len(t) % n)
    for name, fn in (('Base64', lambda: base64.b64decode(pad(s,4))),
                     ('Base64URL', lambda: base64.urlsafe_b64decode(pad(s,4))),
                     ('Base32', lambda: base64.b32decode(pad(s.upper(),8))),
                     ('Hex(十六进制)', lambda: binascii.unhexlify(re.sub(r'[^0-9a-fA-F]','',s))),
                     ('Base85',   lambda: base64.b85decode(s.encode())),
                     ('Base85(a85)', lambda: base64.a85decode(s.encode())),
                     ('Base58',   lambda: b58decode(s)),
                     ('二进制串',  lambda: bindecode(s))):
        try: add(name, fn())
        except Exception: pass
    if '%' in s: add('URL编码', urllib.parse.unquote(s))
    if allow_rot13 and (s.isalpha() or ' ' in s): add('ROT13', codecs.decode(s, 'rot_13'))
    m = morse(s)
    if m: add('摩斯电码', m)
    add('倒序', s[::-1])
    seen, uniq = set(), []
    for n, v in out:
        if v not in seen: seen.add(v); uniq.append((n, v))
    return uniq

def best_pick(cands):
    """自动挑最像答案的候选。
       注意："倒序"永远不参与自动选择 —— 它只是把字符串反过来，
       看着像带花括号其实不是答案，会抢答。(CTF 里倒序确实是种套路，
       所以保留成手动选项，但绝不自动选它)"""
    braced = [x for x in cands if has_flag(x[1]) and '倒序' not in x[0]]
    if braced: return braced[0]
    strong = [x for x in cands if '倒序' not in x[0] and looks_text(x[1])]
    return strong[0] if len(strong) == 1 else None

def auto_decode(s, rounds=6):
    """自动一层层往下解，解不动就停"""
    cur = s
    for i in range(rounds):
        # 只有在'已经解过至少一层'之后，才认花括号。
        # （否则输入本身带 {} 就会被误判成'已经解出来了'，比如凯撒密文 mshn{jhlzhy_vr}）
        if i > 0 and has_flag(cur): return cur
        cands = candidates(cur, i == 0)
        if not cands: return cur
        pick = best_pick(cands)
        if not pick and len(cands) == 1 and cands[0][0] != '倒序': pick = cands[0]
        if not pick: return cur
        cur = pick[1]
    return cur

def main():
    data = read_input(sys.argv)
    if not data.strip(): print('  (没读到内容)'); return
    cur = data.strip()

    # 特判：data: URI
    if cur.startswith('data:') and ',' in cur:
        head, _, b64 = cur.partition(',')
        print('  [认出] data: URI，声明类型 = %s' % head.split(';')[0].replace('data:',''))
        print('  （data: 开头 = 把文件内容直接写进文字；逗号前是说明书，逗号后才是数据）')
        try:
            d = base64.b64decode(b64 + '=' * (-len(b64) % 4))
            print('  → 解出 %d 字节，文件头 = %s' % (len(d), d[:4].hex()))
        except Exception as e: print('  → 解不开:', e)
        return

    print('  ── 第 1 步：按标准编码解（base64/hex/摩斯/URL/ROT13...）──')
    r = auto_decode(cur)
    if r and r != cur and has_flag(r):
        print('\n  ★★★ 解出来了 ★★★\n  %s\n' % r); return
    if r != cur and looks_text(r):
        print('     解到一半：%s' % r[:200])
    else:
        print('     标准编码解不出来')

    print('\n  ── 第 2 步：试"变种"密码 ──')
    if is_base64ish(cur):
        print('     它本身是合法 base64，跳过（免得凯撒把答案顶掉）')
    elif is_plainhex(cur):
        print('     它本身是纯十六进制，跳过（同上）')
    else:
        print('     试着按"凯撒位移 / base64换表"解（这两种属于猜，所以要放后面）...')
        cands2 = caesar_all(cur) + basetable_all(cur) + xor_brute(cur) + [('ROT47', rot47(cur))]
        # 把"原文本身"也放进去一起比分数：
        # 如果原文比所有变种都更像答案，说明它自己就是 flag，别再瞎转换。
        # （这一步修正了"输入本身带花括号就被误判成已解出"的老问题）
        cands2.append(('(原文本身)', cur))
        cands2.sort(key=lambda x: -eng_score(x[1]))
        print('     按"像不像正常英文/flag"排序，前 3 名：')
        for name, v in cands2[:3]:
            print('     %-18s %s' % (name, v[:100]))
        best = cands2[0]
        if has_flag(best[1]) and eng_score(best[1]) >= eng_score(cur):
            print('\n  ★★★ 最可能是【%s】★★★\n  %s\n' % (best[0], best[1][:300])); return

    print('\n  ── 第 3 步：都不像，你自己挑挑看 ──')
    cur2 = cur
    for rnd in range(1, 5):
        cands = candidates(cur2, rnd == 1)
        if not cands: print('     没得挑了'); break
        for i,(n,v) in enumerate(cands,1):
            print('   [%d] %-14s -> %s' % (i, n, v[:100] + ('...' if len(v)>100 else '')))
        try: sel = input('   输编号继续（回车=停）: ').strip()
        except EOFError: sel = ''
        if not sel.isdigit() or not (1 <= int(sel) <= len(cands)): break
        cur2 = cands[int(sel)-1][1]
        print('   -> %s\n' % cur2[:200])

if __name__ == '__main__':
    # 统一兜底：任何意外都不会甩一堆报错给你，而是给一句人话
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print('')
        print('  （输入中断，退出了。想重来就再双击一次）')
    except Exception as _e:
        print('')
        print('  [!] 这个工具出错了: %s' % _e)
        print('  （把这段截图发给开发者就能修。这题先换个工具试试）')
