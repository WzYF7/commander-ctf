# -*- coding: utf-8 -*-
"""图片深度检查 —— 图片里有五个地方能藏东西，这个工具全查一遍。

  ① 宽高被改：出题人把图片高度改小，底部内容被"裁掉"了。
     这里会**算出真实高度**（PNG 里数据长度和宽高是绑定的，一算就露馅）
  ② 尾部附加：图片正常结束后又接了别的文件
  ③ 通道差分：R-G、R^G 这些操作能把藏在单个通道里的图案显出来
  ④ JPEG 拼接：两个 JPEG 首尾接在一起，这里会切开
  ⑤ GIF 多帧：某一帧才藏东西，这里会分帧
"""
import sys, os, struct, zlib, re, glob
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass

def png_real_height(data, w, bitd, colort):
    """算出 PNG 的真实高度。
       原理：PNG 的像素数据压缩后存在 IDAT 里，解压后长度 = 高 × (1 + 每行字节数)。
       宽高被改过的话，反推出来的高度就对不上。"""
    off = 8; idat = b''
    while off + 8 <= len(data):
        ln = struct.unpack('>I', data[off:off+4])[0]
        typ = data[off+4:off+8]
        if typ == b'IDAT': idat += data[off+8:off+8+ln]
        if typ == b'IEND': break
        off += 12 + ln
    if not idat: return None
    try: raw = zlib.decompress(idat)
    except Exception: return None
    ch = {0:1, 2:3, 3:1, 4:2, 6:4}.get(colort, 3)
    per_row = 1 + (w * ch * bitd + 7) // 8
    h = len(raw) // per_row
    return h if h * per_row == len(raw) else None

def check_png(data, outdir, path):
    w, h = struct.unpack('>II', data[16:24])
    bitd, colort = data[24], data[25]
    crc_stored = struct.unpack('>I', data[29:33])[0]
    crc_calc = zlib.crc32(data[12:29]) & 0xffffffff
    print('     声明的宽高: %d x %d   位深 %d  颜色类型 %d' % (w, h, bitd, colort))
    real = png_real_height(data, w, bitd, colort)
    if real and real != h:
        print('     ★★ 真实高度应该是 %d（不是声明的 %d）—— 宽高被改过！' % (real, h))
        try:
            from PIL import Image
            d2 = bytearray(data)
            struct.pack_into('>I', d2, 20, real)
            # 顺手把 CRC 也修好
            crc = zlib.crc32(bytes(d2[12:29])) & 0xffffffff
            struct.pack_into('>I', d2, 29, crc)
            out = os.path.join(outdir, '修好宽高的图.png')
            open(out, 'wb').write(bytes(d2))
            print('     → 已自动修复并另存: %s' % out)
            print('        （打开看看，被裁掉的内容就在下面）')
        except Exception as e: print('     （修复失败: %s）' % e)
    elif crc_stored != crc_calc:
        print('     ⚠ IHDR 校验值对不上（区域被改过，但不一定是宽高）')
    else:
        print('     ✔ 宽高正常，没被改过')
    # PNG 文本块（有时 flag 直接写在 tEXt 里）
    for m in re.finditer(rb'(tEXt|zTXt|iTXt)', data):
        i = m.start()
        if i + 8 < len(data):
            ln = struct.unpack('>I', data[i-4:i])[0]
            txt = data[i+4:i+ln]
            print('     ★ PNG 文本块 %s: %s' % (m.group().decode(), txt[:200].decode('utf-8','replace')))

def split_jpeg(data, outdir):
    """JPEG 拼接图：一个文件里有多个 JPEG 头 FF D8 FF"""
    hits = [m.start() for m in re.finditer(rb'\xff\xd8\xff', data)]
    if len(hits) < 2: return 0
    print('     ★ 发现 %d 个 JPEG 头 —— 是拼接图，切开看看' % len(hits))
    for i, off in enumerate(hits):
        end = hits[i+1] if i+1 < len(hits) else len(data)
        o = os.path.join(outdir, '拼接图%d.jpg' % i)
        open(o, 'wb').write(data[off:end])
        print('        -> %s (%d 字节)' % (os.path.basename(o), end-off))
    return len(hits)

def channel_ops(path, outdir):
    """通道差分 / 异或：把藏在单通道或通道关系里的图案显出来"""
    try:
        import numpy as np
        from PIL import Image
    except ImportError:
        return
    arr = np.array(Image.open(path).convert('RGB')).astype('int16')
    R, G, B = arr[:,:,0], arr[:,:,1], arr[:,:,2]
    ops = [('R-G', R-G), ('G-B', G-B), ('R-B', R-B), ('R^G', R^G), ('R^B', R^B), ('G^B', G^B),
           ('R+G+B', (R+G+B)//3)]
    made = 0
    for name, a in ops:
        a = (a - a.min())
        mx = a.max() or 1
        img = (a * 255 // mx).astype('uint8')
        o = os.path.join(outdir, '通道_%s.png' % name.replace('^','xor'))
        Image.fromarray(img, 'L').save(o); made += 1
    print('     ✔ 通道差分/异或 生成 %d 张图（打开看有没有图案）' % made)

def gif_frames(path, outdir):
    try:
        from PIL import Image, ImageSequence
    except ImportError:
        return
    im = Image.open(path)
    n = 0
    for i, fr in enumerate(ImageSequence.Iterator(im)):
        fr.convert('RGB').save(os.path.join(outdir, '帧%02d.png' % i)); n += 1
        if n >= 60: break
    print('     ✔ GIF 分出 %d 帧（一帧一帧看，有时只有某帧藏东西）' % n)

def main():
    path = ' '.join(sys.argv[1:]).strip().strip('"')
    if not path: path = input('  把图片拖进来再回车: ').strip().strip('"')
    if not os.path.isfile(path): print('  找不到:', path); return
    data = open(path, 'rb').read()
    outdir = os.path.splitext(path)[0] + '_结构分析'
    os.makedirs(outdir, exist_ok=True)
    print('  文件: %s  (%d 字节)' % (os.path.basename(path), len(data)))
    print('  输出目录: %s' % outdir)

    if data[:8] == b'\x89PNG\r\n\x1a\n':
        print('  ── PNG 结构 ──')
        check_png(data, outdir, path)
    elif data[:3] == b'\xff\xd8\xff':
        print('  ── JPEG ──')
        print('     （JPEG 没有 CRC 校验，改宽高从结构上看不出来）')
        split_jpeg(data, outdir)
    elif data[:3] == b'GIF':
        print('  ── GIF ──')
        gif_frames(path, outdir)
    else:
        print('  [!] 不是常见图片格式，先用 DetectItEasy 看真身')
        return

    print('')
    print('  ── 图片正常结束位置之后还有东西吗 ──')
    ends = []
    if data[:3] == b'\xff\xd8\xff':
        i = data.rfind(b'\xff\xd9')
        if i > 0: ends.append(i+2)
    elif data[:8] == b'\x89PNG\r\n\x1a\n':
        i = data.rfind(b'IEND')
        if i > 0: ends.append(i+8)
    elif data[:3] == b'GIF':
        i = data.rfind(b'\x3b')
        if i > 0: ends.append(i+1)
    tail = 0
    for e in ends:
        if len(data) - e > 8:
            tail = len(data) - e
            print('     ★ 尾部还有 %d 字节！开头是: %s' % (tail, data[e:e+8].hex(' ')))
            print('        → 用菜单 16「文件分离」把它切出来')
    if not tail: print('     ✔ 尾部没有多余数据')

    print('')
    print('  ── 通道差分 / 异或 ──')
    channel_ops(path, outdir)

    print('')
    print('  下一步：')
    print('   1. 打开 %s 里的图看看' % os.path.basename(outdir))
    print('   2. 再跑一次菜单 19「图片隐写·一键暴力扫描」（含 zsteg 等专业工具）')
    print('   3. 元数据用菜单 12 之外，也可以直接用 ExifTool')

if __name__ == '__main__':
    try: main()
    except (EOFError, KeyboardInterrupt): print('\n  （输入中断）')
    except Exception as e: print('\n  [!] 出错: %s' % e)