# -*- coding: utf-8 -*-
"""异或爆破 —— 试 256 个单字节密钥。
（原理：异或(XOR)是"同一个数异或两次会还原"，常拿来做最简单的加密。
 出题人用一个密钥 k 把每个字节都异或一次；我们不知道 k，就把 0~255 全试一遍，
 哪个结果看起来像正常文字（尤其出现 flag）就是它。）"""
import os
import sys, binascii, re, string
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass


PRINT = set(bytes(string.printable, 'ascii'))

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

def score(b):
    if not b: return -1
    s = sum(1 for c in b if c in PRINT) / len(b)
    t = b.lower()
    for kw in (b'flag', b'ctf', b'{', b'}'):
        if kw in t: s += 1.5
    return s

def load(s):
    s = s.strip()
    h = re.sub(r'[^0-9a-fA-F]', '', s)
    if len(s) >= 4 and len(h) == len(s) and len(h) % 2 == 0:
        try: return binascii.unhexlify(h), 'hex(十六进制)'
        except Exception: pass
    if s.startswith('\\x'):
        try: return bytes.fromhex(s.replace('\\x','')), 'hex 转义'
        except Exception: pass
    return s.encode('utf-8','ignore'), '普通文本'






def looks_flag(b):
    """严格判断：解出来的东西是不是"完整的 flag"。
       要求：开头是 短前缀{，结尾是 }，中间全是可打印字符。
       （为什么要这么严：只要求"可打印"的话，密钥猜错一两个字节也会通过，
        结果就是密钥被截断成错的）"""
    try: t = b.decode('utf-8')
    except Exception: return False
    return re.match(r'^[\w\u4e00-\u9fff-]{2,24}\{[^}\n]{2,200}\}$', t) is not None

def texty(b):
    """判断这些字节"像不像能读的文字"（CTF 里的答案都是能读的）"""
    if not b: return False
    pr = sum(1 for c in b if 32 <= c < 127) / len(b)
    return pr > 0.9

def ctf_score(b):
    """CTF 专用打分：可读字符多、含花括号/flag 字样的分高。
       （注意：CTF 的明文是 flag{...} 这种东西，不是正常英语，
        所以不能用"英文字母频率"来猜，要用"像不像 flag"）"""
    if not b: return -1e9
    pr = sum(1 for c in b if 32 <= c < 127) / len(b)
    t = b.lower()
    sc = pr * 3
    if b'{' in t and b'}' in t: sc += 4
    if b'flag' in t or b'ctf' in t: sc += 4
    sc += sum(1 for c in b if chr(c).isalnum() or c in b'{}_-') / len(b)
    return sc





# 各个比赛常用的 flag 开头
PREFIXES = (b'flag{', b'ctf{', b'FLAG{', b'CTF{', b'flag', b'FLAG')

# flag 里可能出现的字符（解密结果必须全落在这个集合里，否则这个密钥肯定不对）
FLAGCHARS = set(b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-{}')
FLAGCHARS |= set(b'!@#$%^&*()+=.,:;/\\?~ |')


# 英文里最常见的一些"双字母组合"。正常英文里这些占很大比例，
# 密钥猜错时，解出来的东西会包含很多不常见的组合 —— 靠这个区分。
BIGRAMS = set(('th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as '
               'ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur ca el ta la '
               'ns di fo ho pe ec pr no ct us ac il tr ly st un wi ge ay ea ge us ni im am op ot '
               'ck qu wh ex ag id ig ke ol ug mp ul ss ff tt nn rr dd ee oo aa').split())

def bigram_score(b):
    try: t = b.decode('ascii', 'ignore').lower()
    except Exception: return 0
    if len(t) < 3: return 0
    hits = sum(1 for i in range(len(t) - 1) if t[i:i+2] in BIGRAMS)
    return hits / (len(t) - 1)

def flag_likeness(b):
    """给一个"解出来像 flag 的东西"打分：越像真的分越高。
       真 flag 的特点：字母多、符号少、内容是有意义的词。
       （为什么需要：SECRET 和 SECRE@ 解出来都"合法"，
        但 SECRE@ 里有个 @，明显不是出题人写的 —— 靠这个区分）"""
    if not b: return -1e9
    letters = sum(1 for c in b if chr(c).isalpha())
    digits  = sum(1 for c in b if chr(c).isdigit())
    good    = sum(1 for c in b if chr(c) in '_-')
    bad     = sum(1 for c in b if 32 <= c < 127 and not (chr(c).isalnum() or chr(c) in '_-{}'))
    sc = (letters * 2 + digits + good * 0.5 - bad * 6) / len(b)
    sc += bigram_score(b) * 12      # 双字母组合分（最能区分对错）
    if b[:5].lower() in (b'flag{', b'ctf{') or b[:4].lower() in (b'flag', b'ctf'):
        sc += 5
    return sc

def _key_candidates(raw, i, L):
    """求 key[i] 所有可能值：让 raw[i::L] 解密后每个字节都在 flag 字符集里。
       （这一步是"约束求解"的思路 —— 用"明文必须是合法字符"来筛掉大部分可能）"""
    out = []
    grp = raw[i::L]
    for k in range(256):
        if all((b ^ k) in FLAGCHARS for b in grp):
            out.append(k)
    return out

def _dfs(raw, L, known, unknown, idx, out_list, budget):
    """深度优先：把未知的密钥字节一个个填，每填一个就检查约束，不行就回退"""
    if budget[0] <= 0: return
    budget[0] -= 1
    if idx == len(unknown):
        k = bytes(known[i] for i in range(L))
        d = bytes(b ^ k[i % L] for i, b in enumerate(raw))
        if looks_flag(d): out_list.append((k, d))
        return
    i = unknown[idx]
    for k in _key_candidates(raw, i, L):
        known[i] = k
        _dfs(raw, L, known, unknown, idx + 1, out_list, budget)
        if len(out_list) >= 12: return
    known.pop(i, None)

def repeat_key(raw, deadline=None):
    import time as _t
    if deadline is None: deadline = _t.time() + 8.0
    """重复密钥异或爆破 —— 用"明文一定是 flag{...}"这个约束来解：

       ① 假设明文以 flag{ 开头 → 直接反推密钥的前几字节
       ② 密钥比前缀长时，剩下的字节用"明文必须是合法字符"逐位筛选 + 深度搜索
       ③ 完全解不出来时，退回"逐位最佳"的盲猜
    """
    # ===== ①② 用 flag 格式约束求解 =====
    for pre in PREFIXES:
        if len(raw) < len(pre) + 3: continue
        k0 = bytes(raw[i] ^ pre[i] for i in range(len(pre)))
        for L in range(1, min(33, len(raw))):
            if len(raw) < L + 3: break
            if _t.time() > deadline: return b'', raw
            known, conflict = {}, False
            for i in range(len(pre)):            # 前缀给出的已知字节
                pp = i % L
                if pp in known and known[pp] != k0[i]: conflict = True; break
                known[pp] = k0[i]
            if conflict: continue
            unknown = [i for i in range(L) if i not in known]
            if len(unknown) > 6: continue         # 未知太多就不搜了
            found = []
            _dfs(raw, L, known, unknown, 0, found, [30000])
            if found:
                # 可能有好几个"都解得像 flag"的，挑最像真的那个
                found.sort(key=lambda kv: -flag_likeness(kv[1]))
                return found[0][0], found[0][1]

    # ===== ③ 兜底：纯盲猜 =====
    best = None
    for L in range(2, 17):
        if len(raw) < L * 3: break
        key = []
        for i in range(L):
            cs = _key_candidates(raw, i, L)
            grp = raw[i::L]
            if cs:
                key.append(max(cs, key=lambda kk: ctf_score(bytes(b ^ kk for b in grp))))
            else:
                bk, bs = 0, -1e9
                for kk in range(256):
                    sc = ctf_score(bytes(b ^ kk for b in grp))
                    if sc > bs: bs, bk = sc, kk
                key.append(bk)
        k = bytes(key)
        out = bytes(b ^ k[i % L] for i, b in enumerate(raw))
        sc = flag_likeness(out) + (10 if looks_flag(out) else 0)
        if best is None or sc > best[0]:
            best = (sc, k, out)
    if not best: return b'', raw
    return best[1], best[2]

def main():
    print('  把密文粘进来（十六进制像 1a2b3c，或直接贴乱码），粘完回车两次')
    data = read_input(sys.argv)
    if not data.strip(): print('  (没读到)'); return
    raw, how = load(data)
    print('  按 %s 读取，共 %d 字节\n' % (how, len(raw)))
    res = sorted(((score(bytes(b ^ k for b in raw)), k) for k in range(256)), reverse=True)
    print('  最像答案的 10 个：')
    for i,(sc,k) in enumerate(res[:10],1):
        x = bytes(b ^ k for b in raw)
        try: t = x.decode('utf-8')
        except UnicodeDecodeError: t = x.decode('latin-1')
        t = re.sub(r'[\x00-\x1f]','.',t)
        print('  [%2d] 密钥=0x%02x(%3d)  像文字程度 %.2f' % (i,k,k,sc))
        print('       %s' % t[:100])
    print('\n  （看哪一行像 flag，那一行的密钥就是对的了）')
    print('\n  ── 顺便试试"重复密钥"异或（密钥不止 1 个字节）──')
    try:
        kb, out = repeat_key(raw)
        if len(kb) > 1:
            print('     猜出的密钥 = %r' % kb)
            t = out.decode('utf-8', 'replace')
            print('     解出: %s' % t[:200])
            if '{' in t and '}' in t:
                print('\n  ★★★ 这个更像答案: %s' % t[:200])
        else:
            print('     密钥只有 1 个字节，就是上面单字节的结果')
        print('     （说明：密钥不超过 5 字节时基本都能猜对；')
        print('       更长的密钥如果含数字/符号，可能存在多个看起来都对的解，')
        print('       这时候需要题目给的线索来确认）')
    except Exception as e:
        print('     （跳过: %s）' % e)
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
