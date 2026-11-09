# -*- coding: utf-8 -*-
"""wasm -- WebAssembly(.wasm) 反编译成可读文本，再找 flag

用法: python wasm.py 题目文件
（在commander里也可以直接输：wasm 题目文件）
"""
import os, sys, importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
ZD   = os.path.dirname(HERE)          # commander 目录


def load_engine():
    p = os.path.join(ZD, 'engine.py')
    sp = importlib.util.spec_from_file_location('eng_wasm', p)
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m


def main():
    path = ' '.join(sys.argv[1:]).strip().strip('"')
    if not path or not os.path.isfile(path):
        print('用法: python wasm.py 题目文件')
        return
    name = os.path.splitext(os.path.basename(path))[0]
    eng = load_engine()
    eng.OUTDIR = os.path.join('D:' + os.sep, 'temp', 'commander', name)
    os.makedirs(eng.OUTDIR, exist_ok=True)
    print('中间文件 -> %s' % eng.OUTDIR)
    data = open(path, 'rb').read()
    eng.wasm_analyze(path, data)
    print()
    if eng.FLAGS:
        print('* flag 候选:')
        for k in eng.FLAGS:
            print('   %s' % k)
    else:
        print('（没直接扫到完整 flag —— 看中间文件目录里的产出，或按上面的提示继续）')
    try:
        parts = list(getattr(eng, 'PARTIALS', {}) or {})
    except Exception:
        parts = []
    if parts:
        print()
        print('! 疑似 flag 的一部分（不完整，没有右花括号）：')
        for v in parts[:8]:
            print('   %s' % v)
        print('  （题目常把 flag 拆成几段分开藏，找齐拼起来才是完整的）')


if __name__ == '__main__':
    main()
