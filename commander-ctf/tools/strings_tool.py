# -*- coding: utf-8 -*-
"""字符串提取 —— 从任何文件里挖出"像文字"的片段。

（原理：程序或二进制文件里除了机器码，还夹着大量可读文字：报错信息、
  函数名、网址、常量字符串。做逆向和取证题时，第一步常常就是"先把字符串
  全捞出来看一眼"，很多题的答案直接写在这些字符串里。
  这个工具同时支持 ASCII、UTF-8 中文、以及 Windows 程序常用的 UTF-16。）"""
import sys, re, os
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass

def extract(data):
    out = []
    # ASCII / UTF-8 可见字符串
    for m in re.finditer(rb'[\x20-\x7e]{4,}', data):
        try: out.append(('ascii', m.group().decode('utf-8', 'replace')))
        except Exception: pass
    # UTF-16LE（Windows 程序里的宽字符字符串，每个字符占 2 字节）
    try:
        m = re.findall(rb'(?:[\x20-\x7e]\x00){4,}', data)
        for x in m: out.append(('utf16', x.decode('utf-16le', 'replace')))
    except Exception: pass
    return out

def main():
    path = ' '.join(sys.argv[1:]).strip().strip('"')
    if not path: path = input('  把文件拖进来再回车: ').strip().strip('"')
    if not os.path.isfile(path): print('  找不到:', path); return
    data = open(path, 'rb').read()
    print('  文件大小: %d 字节' % len(data))
    items = extract(data)
    print('  挖到 %d 段字符串' % len(items))
    kws = ('flag', 'ctf', 'key', 'password', 'secret', 'admin', 'http', '.php', '.py', 'correct', 'wrong', 'success')
    hits = [(k, s) for k, s in items if any(w in s.lower() for w in kws)]
    if hits:
        print('\n  ★★ 下面这些看着可疑（含有 flag/key/password/http 之类关键词）:')
        for k, s in hits[:40]:
            print('     [%s] %s' % (k, s[:120]))
    print('\n  ── 前 40 段字符串 ──')
    for k, s in items[:40]:
        print('     [%s] %s' % (k, s[:120]))
    print('\n  提示：')
    print('   - 想更方便地翻，用 ImHex 打开文件，或用 Notepad++ 打开看')
    print('   - 反汇编/反编译工具（Ghidra、dnSpy）里也有"搜索字符串"功能')

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
