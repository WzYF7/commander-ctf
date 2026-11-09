# -*- coding: utf-8 -*-
"""压缩包工具 —— CTF 里压缩包题就三招：伪加密、弱口令、藏东西。

  ① 伪加密：zip 的"加密标记位"被人为设成了 1，但其实没真的加密。
     表现是：解压提示要密码，但随便输什么都说密码错误，或者直接装死。
     修法：把那个标记位改回 0。（我们直接改二进制，不动你的原文件）
  ② 弱口令：真加密但密码很弱，拿字典爆。
  ③ 藏东西：压缩包后面还追加了别的文件（用「文件分离」工具能切出来）。
"""
import sys, zipfile, os, io, struct, re
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass

def find_eocd(data):
    """找 zip 的"中央目录结束标记" PK\x05\x06（在文件末尾附近）"""
    i = data.rfind(b'PK\x05\x06')
    return i

def inspect(path):
    data = open(path, 'rb').read()
    print('  文件大小: %d 字节' % len(data))
    eocd = find_eocd(data)
    print('  ── ① 结构检查 ──')
    if eocd < 0:
        print('     ✘ 没找到 zip 结束标记 —— 也可能这不是 zip')
        print('     （先确认文件真身：拖到 DetectItEasy，或者看文件头是不是 50 4b 03 04）')
        return
    total = struct.unpack('<H', data[eocd+10:eocd+12])[0]
    cdsize = struct.unpack('<I', data[eocd+12:eocd+16])[0]
    cdoff  = struct.unpack('<I', data[eocd+16:eocd+20])[0]
    print('     条目数: %d' % total)
    tail = len(data) - (eocd + 22)
    if tail > 0:
        print('     ★ 结束标记后面还有 %d 字节 —— 可能藏着东西！' % tail)
        print('       → 用「文件分离」工具能把后面这段切出来')
    else:
        print('     尾部没有多余数据')

    print('  ── ② 伪加密检查 ──')
    fake = 0
    pos = 0
    while True:
        pos = data.find(b'PK\x03\x04', pos)
        if pos < 0: break
        flag = struct.unpack('<H', data[pos+6:pos+8])[0]
        if flag & 0x01: fake += 1
        pos += 4
    pos = 0
    while True:
        pos = data.find(b'PK\x01\x02', pos)
        if pos < 0: break
        flag = struct.unpack('<H', data[pos+8:pos+10])[0]
        if flag & 0x01: fake += 1
        pos += 4
    if fake:
        print('     ★ 发现 %d 处"加密标记" —— 很可能是伪加密！' % fake)
        print('       → 试试下面的"修伪加密"，或者直接用 7-Zip 解压')
    else:
        print('     没发现加密标记（不是伪加密）')

    print('  ── ③ 尝试读取内容 ──')
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        bad = z.testzip()
        if bad: print('     ✘ 有损坏的条目:', bad)
        for i in z.infolist()[:20]:
            enc = ' [加密]' if (i.flag_bits & 0x01) else ''
            print('     %-40s %8d 字节%s' % (i.filename, i.file_size, enc))
    except Exception as e:
        print('     打不开: %s' % e)

def fix_fake(path):
    data = bytearray(open(path, 'rb').read())
    n = 0
    pos = 0
    while True:
        pos = data.find(b'PK\x03\x04', pos)
        if pos < 0: break
        flag = struct.unpack('<H', data[pos+6:pos+8])[0]
        if flag & 0x01:
            data[pos+6:pos+8] = struct.pack('<H', flag & ~0x01); n += 1
        pos += 4
    pos = 0
    while True:
        pos = data.find(b'PK\x01\x02', pos)
        if pos < 0: break
        flag = struct.unpack('<H', data[pos+8:pos+10])[0]
        if flag & 0x01:
            data[pos+8:pos+10] = struct.pack('<H', flag & ~0x01); n += 1
        pos += 4
    out = os.path.splitext(path)[0] + '_修复.zip'
    open(out, 'wb').write(bytes(data))
    print('  改了 %d 处加密标记，存成: %s' % (n, out))
    print('  （原文件没动。现在用 7-Zip 打开这个新文件试试）')

def brute(path):
    d = os.path.join(os.environ.get('COMMANDER_TOOLKIT_DIR') or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'toolkit'), '07-字典')
    words = []
    for n in sorted(os.listdir(d)):
        if n.endswith('.txt'):
            try:
                with open(os.path.join(d,n), encoding='utf-8', errors='ignore') as fp:
                    words += [l.strip() for l in fp if l.strip()]
            except Exception: pass
    words = ['123456','password','admin','root','666666','123456789','flag',''] + words
    print('  准备 %d 个候选口令（含空口令）...' % len(words))
    try:
        z = zipfile.ZipFile(path)
        name = z.namelist()[0]
    except Exception as e:
        print('  打不开:', e); return
    for i, w in enumerate(words, 1):
        try:
            z.read(name, pwd=w.encode())
            print('\n  ★★ 密码是：【%s】' % (w if w else '(空)'))
            print('  → 用 7-Zip 手动解压时输入这个密码')
            return
        except Exception: pass
        if i % 2000 == 0: print('     试了 %d 个...' % i)
    print('  ✘ 字典里没有。可以试: 用 bkcrack 做"明文攻击"（如果知道包里某个文件的内容）')

def main():
    path = ' '.join(sys.argv[1:]).strip().strip('"')
    if not path: path = input('  把压缩包拖进来再回车: ').strip().strip('"')
    if not os.path.isfile(path): print('  找不到:', path); return
    print('  ── 检查 %s ──' % os.path.basename(path))
    inspect(path)
    print('\n  你想做什么？')
    print('    1. 修复伪加密（存成新文件，不动原文件）')
    print('    2. 用字典爆破密码')
    print('    0. 只看检查结果')
    k = input('  选: ').strip()
    if k == '1': fix_fake(path)
    elif k == '2': brute(path)

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
