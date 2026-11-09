# -*- coding: utf-8 -*-
"""JWT 解析 —— 登录凭证类的题。

（JWT = 一种登录令牌，长得像 xxx.yyy.zzz 三段，用点分开：
  第一段是"算法说明"，第二段是"携带的信息(比如我是谁、是不是管理员)"，
  第三段是签名。三段都是 base64 编码的，所以能直接解开看内容。
  常见漏洞：① 把算法改成 none，签名就不校验了
           ② 密钥太弱，能爆破
           ③ 改第二段里的 is_admin 之类字段）"""
import os
import sys, base64, json
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass

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

def b64d(s):
    s = s + '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def b64e(b):
    return base64.urlsafe_b64encode(b).decode().rstrip('=')

def main():
    tok = read_input(sys.argv)
    if not tok: print('  (没输入)'); return
    parts = tok.split('.')
    print('  一共 %d 段' % len(parts))
    names = ['头部(算法说明)', '载荷(携带的信息)', '签名']
    for i, p in enumerate(parts):
        try:
            d = b64d(p)
            try: t = d.decode('utf-8')
            except Exception: t = repr(d)
            try: t = json.dumps(json.loads(t), ensure_ascii=False, indent=2)
            except Exception: pass
            print('\n  ── 第 %d 段 %s ──' % (i+1, names[i] if i < 3 else ''))
            print('     ' + t.replace('\n', '\n     '))
        except Exception as e:
            print('\n  ── 第 %d 段 ── 解不开: %s' % (i+1, e))

    print('\n  ── 常见打法 ──')
    if len(parts) >= 2:
        try:
            hdr = json.loads(b64d(parts[0]))
            if hdr.get('alg','').lower() != 'none':
                forged = b64e(json.dumps({'alg':'none','typ':'JWT'}).encode()) + '.' + parts[1] + '.'
                print('   ① 试试"算法改成 none"（有些实现不校验签名）：')
                print('      改成: %s' % (forged[:120] + '...'))
            else:
                print('   ① 算法已经是 none 了，说明这把已经被改过')
        except Exception: pass
    print('   ② 第二段里如果有 is_admin / role / user 这类字段，')
    print('      改成 admin/1 再重新拼回去试试（有些实现只信内容不看签名）')
    print('   ③ 密钥很弱的话，用 hashcat 爆破：')
    print('      hashcat -m 16500 jwt.txt 字典文件')
    print('   ④ 在线工具：https://jwt.io  （把 token 粘进去能直接看/改）')
    print('')
    print('  （JWT 这段属于 Web 题的"鉴权"考点，比赛遇到再看也行）')

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
