# -*- coding: utf-8 -*-
"""图片隐写分析 —— 位平面 + LSB（单通道 + 多通道合并）。

（原理：一张彩色图每个像素有 R/G/B 三个值，各 8 个二进制位。
 出题人常常只改"最低的那一位"(LSB, Least Significant Bit)，
 因为改动最小、肉眼看不出，但能藏一整套数据。

 提取方式有两种，都要试：
   ① 单通道：只看 R，或只看 G，或只看 B
   ② 合并：按 R,G,B 的顺序把三个通道的最低位依次拼起来
      —— 很多题用这种，所以单看某一个通道全是乱码、会漏掉
 拼出来的东西常常是 base64，本工具会自动帮你解开。）"""
import os, sys, re, base64
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass


def readable_ratio(t):
    if not t: return 0.0
    ok = 0
    for c in t:
        o = ord(c)
        if 32 <= o < 127 or c in '\r\n\t' or 0x4e00 <= o <= 0x9fff:
            ok += 1
    return ok / len(t)


def scan_stream(data, tag, outdir, found, shorts):
    """把一串字节拿来找"人话"：flag 形状 / base64 / 明文"""
    with open(os.path.join(outdir, 'lsb_%s.bin' % tag), 'wb') as f:
        f.write(data)
    txt = data.decode('latin-1')

    # ① 直接就是 flag 形状
    for m in re.finditer(r'[A-Za-z0-9_]{2,12}\{[^}\x00-\x1f\x7f]{3,120}\}', txt):
        found.append((tag, '直接读出答案：' + m.group(0)))

    # ② 一段 base64，解开看看
    for m in re.finditer(r'[A-Za-z0-9+/]{16,}={0,2}', txt):
        s = m.group(0)
        try:
            dec = base64.b64decode(s + '=' * (-len(s) % 4))
            t = dec.decode('utf-8')
        except Exception:
            continue
        if readable_ratio(t) > 0.85 and len(t.strip()) >= 3:
            found.append((tag, 'base64 解开：%s\n                     (原文: %s)' % (t.strip(), s[:70])))

    if readable_ratio(txt) > 0.7:
        shorts.append((tag, txt))


def main():
    path = ' '.join(sys.argv[1:]).strip().strip('"')
    if not path: path = input('  把图片拖进来再回车: ').strip().strip('"')
    if not os.path.isfile(path): print('  找不到:', path); return
    outdir = os.path.splitext(path)[0] + '_隐写分析'
    os.makedirs(outdir, exist_ok=True)
    try:
        import numpy as np
        from PIL import Image
    except ImportError:
        print('  缺库，执行: python -m pip install pillow numpy'); return

    try:
        arr = np.array(Image.open(path).convert('RGB'))
    except Exception as e:
        print('  [!] 这个文件不是图片，打不开: %s' % e)
        print('  （先拖到 DetectItEasy 看看它的真实类型，或者用「文件分离」看看')
        print('    它里面是不是藏了别的文件）')
        return
    print('  图片尺寸: %d × %d' % (arr.shape[1], arr.shape[0]))

    found = []
    shorts = []

    # ---- 位平面 ----
    for bit in range(8):
        m = (arr >> bit) & 1
        img = (m.max(axis=2) * 255).astype('uint8')
        Image.fromarray(img, 'L').save(os.path.join(outdir, 'bit%d.png' % bit))
    print('  已导出 8 张位平面图 -> bit0.png ~ bit7.png')
    print('  （bit0 就是"最低位"，藏东西最常用；打开看看有没有文字或图案）')

    # ---- ① 单通道 LSB ----
    for idx, name in enumerate(('R', 'G', 'B')):
        bits = (arr[:, :, idx] & 1).reshape(-1)
        n = len(bits) // 8
        scan_stream(np.packbits(bits[:n * 8]).tobytes(), name, outdir, found, shorts)

    # ---- ② 多通道合并 LSB（关键：很多题藏在这里）----
    order_map = {'RGB': [0, 1, 2], 'BGR': [2, 1, 0], 'GRB': [1, 0, 2]}
    for tag, order in order_map.items():
        bits = (arr[:, :, order] & 1).reshape(-1)
        n = len(bits) // 8
        scan_stream(np.packbits(bits[:n * 8]).tobytes(), tag, outdir, found, shorts)

    # 只在真的读到"人话"时才打印那一串，避免刷屏
    for name, txt in shorts:
        print('\n  --- LSB %s 里读到文字 ---' % name)
        print('  ' + txt[:200])

    print()
    print('=' * 56)
    if found:
        print('   ★ 有发现！')
        seen = set()
        for tag, msg in found:
            if msg in seen: continue
            seen.add(msg)
            print('      [LSB %s] %s' % (tag, msg))
        print()
        print('   ★ 上面如果是 flag 形状的字符串，那就是答案')
    else:
        print('   没直接读出东西，可以再看看：')
        print('     · bit0.png（最低位画的图，常能看见文字或图案）')
        print('     · 结果目录里的 lsb_*.bin，用「乱码解码」过一遍')
        print('     · 换「图片深度检查」看宽高有没有被改、尾部有没有附加')
    print('=' * 56)
    print('   结果目录: %s' % outdir)


if __name__ == '__main__':
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print('')
        print('  （输入中断，退出了。想重来就再双击一次）')
    except Exception as _e:
        print('')
        print('  [!] 这个工具出错了: %s' % _e)
        print('  （把这段截图发给开发者就能修。这题先换个工具试试）')