# -*- coding: utf-8 -*-
"""PyInstaller 解包 —— 把 Python 打包成的 exe 还原出源码。

（原理：PyInstaller 把 Python 脚本编译成 .pyc 字节码，塞进 exe 尾部。
  这个工具把尾部数据拆出来（pyinstxtractor 干的事），
  再把 .pyc 反编译回 .py（能反编译成功就等于拿到源码了）。
  你平台上的"PY安装器"那类题就是考这个。）"""
import sys, os, subprocess, glob
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass

HERE = os.path.dirname(os.path.abspath(__file__))

def main():
    path = ' '.join(sys.argv[1:]).strip().strip('"')
    if not path: path = input('  把 exe 拖进来再回车: ').strip().strip('"')
    if not os.path.isfile(path): print('  找不到:', path); return

    # 先确认是不是 exe
    with open(path,'rb') as f: head = f.read(2)
    if head != b'MZ':
        print('  [!] 这不是 exe（Windows 程序开头应该是 4D 5A）')
        print('      （如果后缀是 .exe 但文件头不对，说明是"改后缀"的题）')
        return

    print('  ── 第 1 步：用 pyinstxtractor 拆包 ──')
    extractor = os.path.join(HERE, 'pyinstxtractor.py')
    if not os.path.isfile(extractor):
        print('  ✘ 找不到 pyinstxtractor.py'); return
    out = path + '_extracted'   # pyinstxtractor 生成的目录名是 <原文件名>_extracted
    r = subprocess.run([sys.executable, extractor, path], capture_output=True, text=True, errors='ignore')
    print('     %s' % '\n     '.join((r.stdout or '').splitlines()[-8:]))
    # pyinstxtractor 有警告时也会返回非0，只看目录有没有生成
    if not os.path.isdir(out):
        # 兜底：在文件旁边找任何以 _extracted 结尾的新目录
        import glob as _g
        _cands = _g.glob(os.path.join(os.path.dirname(os.path.abspath(path)), '*_extracted'))
        _cands = [d for d in _cands if os.path.isdir(d)]
        if _cands:
            out = max(_cands, key=os.path.getmtime)
    if not os.path.isdir(out):
        print('  ✘ 拆包失败')
        print('      （可能不是 PyInstaller 打包的，用 DetectItEasy 看看真实情况）')
        return

    print('\n  ── 第 2 步：看看拆出来什么 ──')
    pycs = sorted(glob.glob(os.path.join(out, '*.pyc')))
    print('     目录: %s' % out)
    print('     里面有 %d 个 .pyc（就是编译后的 Python 代码）' % len(pycs))
    for p in pycs[:15]:
        print('       %s  (%d 字节)' % (os.path.basename(p), os.path.getsize(p)))

    print('\n  ── 第 3 步：尝试反编译回 .py ──')
    ok = 0
    for tool in (['decompyle3'], ['uncompyle6']):
        try: subprocess.run([sys.executable, '-m', tool[0], '--help'], capture_output=True, timeout=20)
        except Exception: continue
        for p in pycs[:5]:
            try:
                rr = subprocess.run([sys.executable, '-m', tool[0], p], capture_output=True, text=True, errors='ignore')
                src = os.path.splitext(p)[0] + '.py'
                if rr.stdout and len(rr.stdout) > 50:
                    open(src, 'w', encoding='utf-8').write(rr.stdout)
                    print('     ✔ %s → %s' % (os.path.basename(p), os.path.basename(src))); ok += 1
            except Exception: pass
    if 'different Python version' in r.stdout or 'different Python version' in (r.stderr or ''):
        print('')
        print('     ★ 提示：这个 exe 是用**更新的 Python 版本**打包的，本机版本解不开 pyz。')
        print('        变通办法：装对应版本的 Python 再跑一次 pyinstxtractor，')
        print('        或者用 imhex 直接在里面搜字符串（flag 常常明文躺在 .pyc 里）')
    if ok == 0:
        print('     ✘ 自动反编译没成功（多半是 Python 版本太新，反编译工具还没跟上）')
        print('')
        print('     ★★ 你可以手动做（不用装代码，直接用在线工具）：★★')
        print('       1. 打开 https://pylingual.io/  （在线 pyc 反编译，支持新版本）')
        print('       2. 把 %s 里的 .pyc 文件拖进去' % out)
        print('       3. 或者用 PyCharm / VS Code 的一些 pyc 插件看')
        print('')
        print('     （为什么要反编译：.pyc 是"编译过的 Python"，人看不懂；')
        print('       反编译 = 逆向这个过程，还原成人能读的 .py 源码）')

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
