# -*- coding: utf-8 -*-
"""熵值分析 —— 判断一段数据"有多乱"。

（原理：熵 = 混乱程度。普通文本熵约 4~5，base64 约 5~6，加密/压缩数据接近 8。
  用法：① 看整个文件是不是被加密/压缩了
        ② 分段算熵，找出"突然变乱"的那一段 —— 那一段往往就是藏东西的地方）
用法: python entropy.py 文件 [块大小]
"""
import sys, os, math, collections
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass

def ent(b):
    if not b: return 0.0
    c = collections.Counter(b); n = len(b)
    return -sum((v/n) * math.log2(v/n) for v in c.values())

def main():
    path = ' '.join(sys.argv[1:2]).strip().strip('"')
    if not path: path = input('  把文件拖进来再回车: ').strip().strip('"')
    if not os.path.isfile(path): print('  找不到:', path); return
    blk = 1024
    data = open(path, 'rb').read()
    print('  文件大小: %d 字节' % len(data))
    print('  整体熵值: %.4f  （0=完全规律, 8=完全随机）' % ent(data))
    if ent(data) > 7.5:
        print('     → 接近 8，说明整体是加密/压缩过的数据')
    elif 5.0 <= ent(data) <= 6.5:
        print('     → 5~6.5，可能是 base64 之类的编码文本')
    print('')
    print('  分块熵值（每 %d 字节一块，找出突然变乱的地方）:' % blk)
    rows = []
    for i in range(0, len(data), blk):
        rows.append((i, ent(data[i:i+blk])))
    for off, e in rows[:40]:
        bar = '#' * int((e/8)*50)
        mark = '  <<< 这里很乱' if e > 7.9 else ''
        print('     偏移 0x%-8x  %.3f  %s%s' % (off, e, bar, mark))
    if len(rows) > 40: print('     ...（还有 %d 块）' % (len(rows)-40))
    print('')
    print('  怎么看：找到熵突然升高（接近 8）的偏移，那块就是藏东西的位置，')
    print('  记下偏移量，用 ImHex 跳过去看，或者用「文件分离」切出来')

if __name__ == '__main__':
    try: main()
    except (EOFError, KeyboardInterrupt): print('\n  （输入中断）')
    except Exception as e: print('\n  [!] 出错: %s' % e)
