# -*- coding: utf-8 -*-
"""Emoji 编码解码 —— 一整串表情符号也是种编码。

（原理：出题人用一个 emoji 字母表，把每个 emoji 当成一个"数字"，
  按 base64/base32 那样拼起来。常见做法有几种，这里挨个试：
   ① 把出现的 emoji 按 Unicode 码点排序，当作 base64 的 64 个字母
   ② 按它们在文中首次出现的顺序排序，当作 base64 字母表
   ③ 同上，但用 base32（32 个字母）
   ④ 直接取 (码点 - 最小值) 当数字串
  不用你知道是哪种 —— 全试一遍看哪个解出 flag。）

用法: python emoji.py 文件或直接粘贴
"""
import sys, os, re, base64, collections
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass

B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

def is_emoji(ch):
    o = ord(ch)
    return (0x1F300 <= o <= 0x1FAFF) or (0x2600 <= o <= 0x27BF) or (0x1F000 <= o <= 0x1F2FF) \
        or (0xFE00 <= o <= 0xFE0F) or (0x2190 <= o <= 0x21FF) or (0x2B00 <= o <= 0x2BFF)

def try_decode(chars, table, alphabet, label):
    """chars 是 emoji 序列，table 是 emoji->数字 的映射，alphabet 是目标编码的字母表"""
    try:
        s = ''.join(alphabet[table[c]] for c in chars if c in table)
    except Exception:
        return []
    pad = len(s) % 4 if alphabet is B64 else len(s) % 8
    s2 = s + ('=' * (4 - pad) if alphabet is B64 and pad else '')
    if alphabet is B32:
        s2 = s + '=' * ((8 - len(s) % 8) % 8)
    out = []
    try:
        if alphabet is B64:
            d = base64.b64decode(s2)
        else:
            d = base64.b32decode(s2)
        t = d.decode('utf-8')
        if t.strip():
            out.append((label, t))
    except Exception:
        pass
    return out

def main():
    path = ' '.join(sys.argv[1:]).strip().strip('"')
    if path and os.path.isfile(path):
        data = open(path, encoding='utf-8', errors='ignore').read()
    elif path:
        data = path
    else:
        print('  把含 emoji 的内容粘进来，回车两次')
        data = sys.stdin.read()
    if not data: print('  （没读到）'); return

    chars = [c for c in data if is_emoji(c)]
    if len(chars) < 8:
        print('  没找到足够的 emoji（%d 个）' % len(chars)); return
    cnt = collections.Counter(chars)
    uniq_code = sorted(cnt.keys(), key=ord)
    seen, uniq_first = set(), []
    for c in chars:
        if c not in seen:
            seen.add(c); uniq_first.append(c)

    print('  共 %d 个 emoji，%d 种' % (len(chars), len(cnt)))
    print('  码点范围: U+%X ~ U+%X' % (ord(uniq_code[0]), ord(uniq_code[-1])))
    print('  （会试 8 种常见 emoji 编码方案）\n')

    results = []
    # 方案 1/2：码点排序 / 首次出现顺序  ->  base64 表
    for order_name, order in (('按码点排序', uniq_code), ('按首次出现', uniq_first)):
        for tb_name, tb in (('base64', B64), ('base32', B32)):
            n = len(tb)
            table = {}
            ok = True
            for i, c in enumerate(order):
                # 如果种类数 == 表长，直接一一对应
                if len(order) == n:
                    table[c] = i
                else:
                    # 种类数不够：按 (码点 - 最小码点) 当索引
                    idx = ord(c) - ord(uniq_code[0])
                    if idx >= n: ok = False; break
                    table[c] = idx
            if not ok: continue
            for lab, t in try_decode(chars, table, tb, '%s→%s' % (order_name, tb_name)):
                results.append((lab, t))
    # 方案 3：码点差当十进制数字
    try:
        nums = [ord(c) - ord(uniq_code[0]) for c in chars]
        for base in (10, 16):
            s = ''.join(str(x) for x in nums)
            results.append(('码点差(base%d)' % base, s[:120]))
    except Exception:
        pass

    shown = 0
    for lab, t in results:
        if not t.strip(): continue
        shown += 1
        mark = '  ★' if ('{' in t and '}' in t) else '   '
        print('%s %-24s %s' % (mark, lab, t[:110]))
        if shown >= 12: break
    print()
    for lab, t in results:
        if '{' in t and '}' in t:
            m = re.search(r'[\w\u4e00-\u9fff]{2,20}\{[^}\n]{2,150}\}', t)
            if m:
                print('  ★★★ 解出来了：%s' % m.group()); return
    print('  没直接出 flag。还可以试：')
    print('   1. 一共 %d 种 emoji —— 如果种类数是 16/26/32/64，就是换表编码' % len(cnt))
    print('   2. 用十六进制编辑器看原始字节，有些题 emoji 只是"障眼法"')
    print('   3. 在线工具：搜 "emoji cipher decoder"')

if __name__ == '__main__':
    try: main()
    except (EOFError, KeyboardInterrupt): print('\n  （中断）')
    except Exception as e: print('\n  [!] 出错: %s' % e)