# -*- coding: utf-8 -*-
"""文件分离 —— 把一个文件里藏着的另一个文件切出来。

（为什么会有这种题：出题人把 flag.zip 直接追加到 a.jpg 后面。
 你看 a.jpg 是正常的，但用十六进制编辑器拉到最底下会看到另一段数据。
 这个工具按"文件头特征"把里面藏的东西切出来。）

关键点：不能简单切到"下一个文件头"就完事 ——
比如一个 zip 里面本来就有很多 PK 开头的记录，那会被切得稀碎。
所以这里给每种格式都算了"它到底在哪结束"。
"""
import os, sys, struct
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass

# 每种文件开头的固定字节（文件头 / magic），这是内容的特征，改不了
SIGS = (
    (b'\x89PNG\r\n\x1a\n', 'png'), (b'\xff\xd8\xff', 'jpg'), (b'GIF8', 'gif'),
    (b'PK\x03\x04', 'zip'), (b'Rar!\x1a\x07', 'rar'), (b'7z\xbc\xaf\x27\x1c', '7z'),
    (b'%PDF', 'pdf'), (b'BM', 'bmp'), (b'\x1f\x8b\x08', 'gz'),
)

def find_end(data, start, kind):
    """算出从 start 开始的这个文件在哪结束（找不到就返回 None）"""
    try:
        if kind == 'png':
            i = data.find(b'IEND', start)
            return i + 8 if i > start else None
        if kind == 'jpg':
            i = data.find(b'\xff\xd9', start + 2)
            return i + 2 if i > start else None
        if kind == 'gif':
            i = data.find(b'\x3b', start + 6)
            return i + 1 if i > start else None
        if kind == 'zip':
            i = data.find(b'PK\x05\x06', start)       # zip 的"结束标记"
            if i > start:
                clen = struct.unpack('<H', data[i+20:i+22])[0]
                return i + 22 + clen
            return None
        if kind == 'pdf':
            i = data.find(b'%%EOF', start)
            return i + 5 if i > start else None
        if kind == 'gz':
            return None   # gz 的结尾在流里，不好直接找，交给下一种情况
    except Exception:
        return None
    return None

def main():
    path = ' '.join(sys.argv[1:]).strip().strip('"')
    if not path: path = input('  把文件拖进来再回车: ').strip().strip('"')
    if not os.path.isfile(path): print('  找不到:', path); return
    data = open(path, 'rb').read()
    print('  文件大小: %d 字节' % len(data))

    hits = []
    for sig, name in SIGS:
        i = data.find(sig)
        while i != -1:
            hits.append((i, name)); i = data.find(sig, i + 1)
    hits.sort()
    if not hits:
        print('  没发现内嵌文件的特征')
        print('  （说明这个文件是"单层"的，没套东西）')
        return

    # 逐个确认：算真实结束位置；落在已知文件内部的签名要跳过
    accepted = []
    for off, name in hits:
        if any(a <= off < b for a, b, _ in accepted):
            continue                      # 这个是上一个文件内部的数据，不是独立文件
        end = find_end(data, off, name)
        if end is None or end <= off:
            nxt = next((o for o, _ in hits if o > off), None)
            end = nxt if nxt else len(data)   # 找不到结束位置，就切到下一个签名/文件尾
        accepted.append((off, end, name))

    outdir = os.path.splitext(path)[0] + '_分离'
    os.makedirs(outdir, exist_ok=True)
    print('  发现 %d 个内嵌文件（偏移量 = 从头数第几个字节）:' % len(accepted))
    for idx, (off, end, name) in enumerate(accepted):
        chunk = data[off:end]
        fn = '%02d_%s_%08x.%s' % (idx, name, off, name)
        open(os.path.join(outdir, fn), 'wb').write(chunk)
        print('     偏移 0x%-6x 是 %-4s → 切出 %6d 字节  %s' % (off, name, len(chunk), fn))
    print('')
    print('  结果目录: %s' % outdir)
    print('  （切出来的文件如果打不开，用 ImHex 看看文件头对不对）')

if __name__ == '__main__':
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print('')
        print('  （输入中断，退出了）')
    except Exception as _e:
        print('')
        print('  [!] 这个工具出错了: %s' % _e)
        print('  （这题先换个工具试试）')