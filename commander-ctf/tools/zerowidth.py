# -*- coding: utf-8 -*-
"""零宽字符解码 —— 藏在"看不见的字符"里的信息。

（原理：Unicode 里有几个字符是"零宽度"的 —— 屏幕上不显示任何东西，
  但确实是字符。出题人把一串零宽字符混在正常文字里，你复制粘贴看着一样，
  用十六进制编辑器或这个工具才能看出来。）

常见零宽字符：
  U+200B 零宽空格   U+200C 零宽非连接符   U+200D 零宽连接符
  U+FEFF BOM        U+2060 词连接符
"""
import sys, os, re
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass

ZW = {'\u200b', '\u200c', '\u200d', '\ufeff', '\u2060', '\u2061', '\u2062', '\u2063'}
MAP2 = {'\u200b':'0', '\u200c':'1', '\u200d':'1', '\ufeff':'1'}   # 常见约定
MAP3 = {'\u200b':'0', '\u200c':'1', '\u200d':'2'}                   # 三进制变体

def main():
    data = ''
    a = ' '.join(sys.argv[1:]).strip().strip('"')
    if a and os.path.isfile(a):
        with open(a, encoding='utf-8', errors='ignore') as f: data = f.read()
    elif a:
        data = a
    else:
        print('  把含零宽字符的文字粘进来（或拖文件进来），粘完回车两次')
        data = sys.stdin.read()
    if not data:
        print('  （没读到内容）'); return

    zw = [c for c in data if c in ZW]
    print('  总字符数 %d，其中零宽字符 %d 个' % (len(data), len(zw)))
    if not zw:
        print('  没有零宽字符（这题不是这个套路）')
        return
    from collections import Counter
    print('  种类: %s' % dict(Counter('U+%04X' % ord(c) for c in zw)))

    # 方案 1：两种字符 → 二进制
    for name, mp in (('二进制(200B=0,200C=1)', MAP2), ('三进制(200B/200C/200D)', MAP3)):
        try:
            bits = ''.join(mp.get(c, '') for c in zw)
            if not bits: continue
            if name.startswith('三进制'):
                # 每 3 位一组的变体不常见，直接按 base3 试
                print('\n  ── 试 %s ──' % name)
                print('     ' + bits[:120])
                continue
            pad = len(bits) % 8
            out = ''
            for i in range(0, len(bits) - pad, 8):
                out += chr(int(bits[i:i+8], 2))
            print('\n  ── %s ──' % name)
            print('     解出: %s' % out[:200])
            if '{' in out and '}' in out:
                print('\n  ★★★ 看着就是 flag: %s' % out[:200])
                return
        except Exception as e:
            print('  （%s 失败: %s）' % (name, e))

    # 方案 2：零宽字符当"隐藏位"，普通字符之间的空隙编码
    print('')
    print('  提示：')
    print('   - 如果上面没解出来，试试把零宽字符之间的正常文字单独读一遍')
    print('   - 有些题是"零宽字符表示 0/1"，但也有用 200B/200C/200D 表示三种值的')
    print('   - 把这段文字粘到 https://330k.github.io/misc_tools/unicode_steganography.html 也能解')

if __name__ == '__main__':
    try: main()
    except (EOFError, KeyboardInterrupt): print('\n  （输入中断）')
    except Exception as e: print('\n  [!] 出错: %s' % e)