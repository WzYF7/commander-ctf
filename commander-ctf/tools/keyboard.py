# -*- coding: utf-8 -*-
"""键盘密码 —— 用键盘上"位置关系"做的密码。

（原理：不是按字母表换，而是按键盘布局换。最常见三种：
  ① 手放歪了：你本来想打 flag，手整体往右挪了一格，打成了 g;sh
     → 解法：把每个字符换成它左边/右边的键
  ② 上下串行：想打上面一行，打成了下面一行
  ③ 键盘镜像：q↔p、a↔;（左右对称）

用法: python keyboard.py 密文
"""
import sys
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass

ROWS = ['`1234567890-=', 'qwertyuiop[]\\', "asdfghjkl;'", 'zxcvbnm,./']

def shift(s, dx=0, dy=0):
    """把每个字符按键盘位置挪 (dx, dy) 格"""
    out = []
    for c in s:
        low = c.lower()
        hit = False
        for r, row in enumerate(ROWS):
            if low in row:
                i = row.index(low)
                nr, ni = r + dy, i + dx
                if 0 <= nr < len(ROWS) and 0 <= ni < len(ROWS[nr]):
                    nc = ROWS[nr][ni]
                    out.append(nc.upper() if c.isupper() else nc)
                else:
                    out.append(c)
                hit = True
                break
        if not hit: out.append(c)
    return ''.join(out)

def mirror(s):
    """键盘左右镜像：q<->p, w<->o, a<->; 这种"""
    m = {}
    for row in ROWS:
        n = len(row)
        for i, c in enumerate(row):
            m[c] = row[n-1-i]
    return ''.join(m.get(c.lower(), c).upper() if c.isupper() else m.get(c, c) for c in s)

def main():
    a = ' '.join(sys.argv[1:]).strip().strip('"')
    if not a:
        print('  把密文粘进来，回车两次')
        a = sys.stdin.read().strip()
    if not a: print('  （没读到内容）'); return
    print('  输入: %s' % a[:80])
    print('  （会试 8 种移动方向 + 左右镜像，看哪个像正常文字）\n')
    res = []
    names = {(-1,0):'左移一格', (1,0):'右移一格', (0,-1):'上移一行', (0,1):'下移一行',
             (-1,-1):'左上', (1,-1):'右上', (-1,1):'左下', (1,1):'右下'}
    for (dx, dy), nm in names.items():
        res.append((nm, shift(a, dx, dy)))
    res.append(('左右镜像', mirror(a)))
    # 按"像不像正常文字"排（看有多少字母）
    def score(t):
        return sum(1 for c in t if c.isalpha()) / max(1, len(t))
    res.sort(key=lambda x: -score(x[1]))
    for nm, t in res[:5]:
        mark = '  ★' if '{' in t else '   '
        print('%s %-10s %s' % (mark, nm, t[:110]))
    print('')
    for nm, t in res:
        if '{' in t and '}' in t:
            print('  ★★★ 看着就是 flag: %s' % t); return
    print('  没直接出 flag。提示：')
    print('   - 键盘密码常见组合是"先键盘移位，再按别的密码解一层"')
    print('   - 上面最像正常文字的那行可以再丢进「编码解码」或「古典密码」')
    print('   - 手机九宫格（222 33 5553 这种）用「编码解码」试')

if __name__ == '__main__':
    try: main()
    except (EOFError, KeyboardInterrupt): print('\n  （输入中断）')
    except Exception as e: print('\n  [!] 出错: %s' % e)