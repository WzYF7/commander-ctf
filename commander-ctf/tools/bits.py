# -*- coding: utf-8 -*-
"""0/1 转图片 —— 一长串 0 和 1 拼成黑白图。
（为什么会有这种题：每个 0/1 就是一个像素点，黑白黑白的排起来就是一张图，
 最常见的结果是个二维码。判断依据：字符总数是完全平方数 → 是正方形。）"""
import sys, os
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass


def draw(bits, n, out, invert):
    from PIL import Image
    img = Image.new('1', (n, n)); px = img.load()
    for i, ch in enumerate(bits):
        on = (ch == '1')
        if invert: on = not on
        px[i % n, i // n] = 255 if on else 0
    img.save(out)

def scan_qr(path):
    """扫二维码：必须用 np.fromfile，否则中文路径会读不到（OpenCV 的老毛病）"""
    try:
        import numpy as np, cv2
        img = cv2.imdecode(np.fromfile(path, dtype=np.uint8), cv2.IMREAD_COLOR)
        if img is None: return None
        # 小图先放大，再加一圈白边。
        # 二维码四周必须有白色留白区（静默区），很多题目给的图没有，
        # 直接扫是扫不出来的，补上白边才好使。
        if max(img.shape[:2]) < 300:
            img = cv2.resize(img, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
        img = cv2.copyMakeBorder(img, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=(255,255,255))
        # 小图先放大 6 倍，否则 OpenCV 认不出（21×21 的二维码太小了）
        if max(img.shape[:2]) < 200:
            img = cv2.resize(img, None, fx=6, fy=6, interpolation=cv2.INTER_NEAREST)
        d = cv2.QRCodeDetector()
        ok, dec, _, _ = d.detectAndDecodeMulti(img)
        if ok and dec:
            r = [x for x in dec if x]
            if r: return r
        one = d.detectAndDecode(img)[0]
        return [one] if one else None
    except Exception:
        return None

def main():
    path = ' '.join(sys.argv[1:]).strip().strip('"')
    if not path: path = input('  把文件拖进来再回车: ').strip().strip('"')
    if not os.path.isfile(path): print('  找不到:', path); return
    raw = open(path, encoding='utf-8', errors='ignore').read()
    bits = ''.join(c for c in raw if c in '01')
    if len(bits) < 64: print('  没找到足够的 0/1'); return
    print('  共 %d 个 0/1 字符（0: %d 个, 1: %d 个）' % (len(bits), bits.count('0'), bits.count('1')))
    n = int(round(len(bits) ** 0.5))
    made = []
    if n*n == len(bits):
        print('  %d = %d × %d，正好是正方形 → 可以拼图' % (len(bits), n, n))
        base = os.path.splitext(path)[0]
        for out, inv, tag in ((base+'_1_normal.png', False, '正常(1=白)'), (base+'_2_inverted.png', True, '反色(1=黑)')):
            draw(bits, n, out, inv); made.append((out, tag))
            print('     生成: %s  [%s]' % (os.path.basename(out), tag))
    else:
        print('  %d 不是完全平方数，拼不成正方形' % len(bits)); return
    print('\n  顺手扫一下二维码...')
    for out, tag in made:
        r = scan_qr(out)
        if r:
            print('\n  ★★★ [%s] 扫出来了: %s ★★★' % (tag, r[0])); print()
        else:
            print('  [%s] 不是二维码（可能就是张普通黑白图，双击打开看看）' % tag)

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
