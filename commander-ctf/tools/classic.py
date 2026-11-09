# -*- coding: utf-8 -*-
"""古典密码综合 —— CTF 密码题最常见的几种"老式密码"全在这里。

包含：凯撒 / 维吉尼亚 / 栅栏 / 培根 / Atbash(反字母表) / 仿射 / 摩斯 / ROT
（这些叫"古典密码"，特点是靠手工替换或移位，没有密钥就很难解。
  现代密码如 AES/RSA 靠数学难题，古典密码靠"规律"——所以暴力试是可行的手段。）"""
import os
import sys, re, itertools, collections
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass

FREQ = 'etaoinshrdlucmfwypvbgkjqxz'
FLAGWORDS = ('flag','ctf','fleg','key','nss','buu','hgame','ctfshow','c404')
MORSE = {'.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G','....':'H',
'..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q',
'.-.':'R','...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z',
'.----':'1','..---':'2','...--':'3','....-':'4','.....':'5','-....':'6','--...':'7','---..':'8','----.':'9','-----':'0'}

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

def score(v):
    """给一段文字打分：像正常英文/flag 的分高"""
    s = 0
    if '{' in v and v.split('{')[0].strip().lower() in FLAGWORDS: s += 100
    L = [c.lower() for c in v if c.isalpha()]
    if L: s += sum((26 - FREQ.index(c)) if c in FREQ else 0 for c in L) / len(L)
    return s

def caesar(s):
    """凯撒：字母整体挪 n 位（挪几位就是密钥）"""
    return [('凯撒移%2d' % k, ''.join(
        chr((ord(c)-65+k)%26+65) if c.isupper() else
        chr((ord(c)-97+k)%26+97) if c.islower() else c for c in s)) for k in range(1,26)]

def atbash(s):
    """Atbash：字母表反过来（A→Z, B→Y...）。这是固定规则，不用密钥"""
    return [('Atbash', ''.join(
        chr(90-ord(c)+65) if c.isupper() else chr(122-ord(c)+97) if c.islower() else c for c in s))]

def affine(s):
    """仿射：每个字母做 y = (a*x + b) mod 26 的变换。a 必须和 26 互素"""
    out = []
    for a, b in itertools.product([1,3,5,7,9,11,15,17,19,21,23,25], range(26)):
        ai = pow(a, -1, 26)
        out.append(('仿射 a=%d b=%d' % (a,b), ''.join(
            chr(((ai*((ord(c)-65)-b))%26)+65) if c.isupper() else
            chr(((ai*((ord(c)-97)-b))%26)+97) if c.islower() else c for c in s)))
    return out

def railfence(s):
    """栅栏密码：把文字按 n 个一组竖着排再横着读。穷举栏数 2~len-1"""
    out = []
    t = re.sub(r'\s','',s)
    for n in range(2, min(21, len(t))):
        rows = [t[i::n] for i in range(n)]
        out.append(('栅栏 %d 栏' % n, ''.join(rows)))
    # 也有"往回复读"的栅栏变种，这里给最常见的一种
    return out

def bacon(s):
    """培根密码：每组 5 个 a/b（或 A/B、0/1）对应一个字母"""
    t = ''.join(c for c in s if c.upper() in 'AB01')
    if len(t) < 10 or len(t) % 5: return []
    m = {'A':'a','B':'b','0':'a','1':'b'}
    bits = ''.join(m[c.upper()] for c in t)
    out = []
    for off, name in ((0, '培根(a=0)'), (32, '培根(a=A大写)')):
        r = ''
        for i in range(0, len(bits), 5):
            r += chr(int(bits[i:i+5].replace('a','0').replace('b','1'), 2) + 65 + off)
        out.append((name, r))
    return out

def morse(s):
    if not re.fullmatch(r'[.\-\s/]+', s.strip()): return []
    out = []
    for w in s.split('/'):
        out.append(''.join(MORSE.get(c,'?') for c in w.split()))
    return [('摩斯', ' '.join(out))]

def vigenere_known(s, key):
    """维吉尼亚：用已知 key 解密（key 是字母串，代表每个位置挪几位）"""
    r = []
    ki = 0
    for c in s:
        if c.isalpha():
            k = ord(key[ki % len(key)].lower()) - 97
            r.append(chr(((ord(c.lower())-97-k) % 26) + 97) if c.islower() else chr(((ord(c.upper())-65-k) % 26) + 65))
            ki += 1
        else: r.append(c)
    return ''.join(r)

def vigenere_auto(s):
    """维吉尼亚无 key 自动破解：
       1. 先猜 key 长度（看"重合指数"，也就是同一个位置上的字母分布像不像自然英语）
       2. 每个位置单独当凯撒来解（频率分析）
       （这是密码学里很经典的"频率分析"思路，值得记住）"""
    letters = [c.lower() for c in s if c.isalpha()]
    if len(letters) < 30: return []
    best_len, best_ic = 1, 0
    for L in range(1, 21):
        ics = []
        for i in range(L):
            grp = letters[i::L]
            if len(grp) < 4: continue
            cnt = collections.Counter(grp)
            ic = sum(v*(v-1) for v in cnt.values()) / (len(grp)*(len(grp)-1))
            ics.append(ic)
        if not ics: continue
        avg = sum(ics)/len(ics)
        if avg > best_ic: best_ic, best_len = avg, L
    key = []
    for i in range(best_len):
        grp = letters[i::best_len]
        if not grp: continue
        best_k, best_s = 0, -1
        for k in range(26):
            dec = ''.join(chr((ord(c)-97-k) % 26 + 97) for c in grp)
            sc = sum((26 - FREQ.index(c)) if c in FREQ else 0 for c in dec)
            if sc > best_s: best_s, best_k = sc, k
        key.append(chr(best_k+97))
    k = ''.join(key)
    return [('维吉尼亚 猜key=%s' % k, vigenere_known(s, k))]

def all_try(s):
    out = []
    for fn in (caesar, atbash, affine, railfence, bacon, morse, vigenere_auto):
        try: out += fn(s)
        except Exception: pass
    out.sort(key=lambda x: -score(x[1]))
    return out

def main():
    key = None
    if len(sys.argv) > 2 and sys.argv[1] == '-k': key = sys.argv[2]; args = sys.argv[3:]
    else: args = sys.argv[1:]
    data = read_input(['x'] + args)
    if not data: print('  (没读到内容)'); return
    if key:
        print('  按你给的 key【%s】解维吉尼亚：' % key)
        print('  %s' % vigenere_known(data, key)); return
    print('  输入：%s' % (data[:80] + ('...' if len(data)>80 else '')))
    print('  （会把凯撒/维吉尼亚/栅栏/培根/Atbash/仿射/摩斯全试一遍，按"像不像正常英文"排序）\n')
    r = all_try(data)
    if not r: print('  一个都没试出来'); return
    for name, v in r[:8]:
        mark = '  ★' if score(v) > 100 else '   '
        print('%s %-16s %s' % (mark, name, v[:110] + ('...' if len(v)>110 else '')))
    best = r[0]
    if '{' in best[1]:
        print('\n  ★★★ 最可能是【%s】：\n  %s\n' % (best[0], best[1][:300]))
    else:
        print('\n  最像的是【%s】，但它不含花括号，可能还不是答案' % best[0])
        print('  → 可以把它再丢进「编码解码」里接着解一层')

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
