# -*- coding: utf-8 -*-
"""哈希识别 + 爆破。
（哈希 = 把任意内容压成一串固定长度的"指纹"，单向不可逆，
 32 位十六进制通常是 MD5。爆破 = 猜原文，把你猜的东西也做一次哈希，对上了就是它。）"""
import os, sys, re, hashlib
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass


TYPES = [(32,'md5'), (40,'sha1'), (64,'sha256'), (96,'sha384'), (128,'sha512')]
COMMON = ['123456','password','admin','123456789','12345678','qwerty','abc123','111111',
'123123','admin123','root','1234567890','letmein','iloveyou','welcome','monkey','dragon',
'flag','test','guest','666666','888888','000000','1234','12345','password1','passw0rd','hello']

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

def dicts():
    r = os.path.join(os.environ.get('COMMANDER_TOOLKIT_DIR') or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'toolkit'), '07-字典')
    return [os.path.join(r,n) for n in sorted(os.listdir(r)) if n.endswith('.txt')] if os.path.isdir(r) else []

def main():
    h = read_input(sys.argv)
    if not h: print('  (没输入)'); return
    algo = next((n for L,n in TYPES if len(h) == L), None)
    print('  长度 %d → 可能是 %s' % (len(h), algo or '未知（本工具支持 md5/sha1/sha256/sha384/sha512）'))
    if not algo: return
    fn = getattr(hashlib, algo); target = h.lower().strip()
    print('\n  先试常见弱口令...')
    for w in COMMON:
        for c in (w, w.capitalize(), w.upper()):
            if fn(c.encode()).hexdigest() == target:
                print('\n  ★ 破解成功！原文明文 = %s\n' % c); return
    print('  没中，开始查字典（可能慢，别关窗口）...')
    n = 0
    for p in dicts():
        try:
            with open(p, encoding='utf-8', errors='ignore') as fp:
                for line in fp:
                    w = line.strip()
                    if not w: continue
                    n += 1
                    if fn(w.encode('utf-8','ignore')).hexdigest() == target:
                        print('\n  ★ 破解成功！原文明文 = %s  （来自 %s）\n' % (w, os.path.basename(p))); return
        except Exception: pass
        print('     查完 %s，累计 %d 个' % (os.path.basename(p), n))
    print('\n  字典里没有。可以试在线网站: cmd5.com / crackstation.net')

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
