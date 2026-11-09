# -*- coding: utf-8 -*-
"""扫二维码 / 条形码 —— 自动试 原图 / 反色 / 放大 四种情况。
（为什么要反色：二维码规定"浅色是0、深色是1"，但出题人经常做反，
 变成"深色是0"，这时候直接扫是扫不出来的，得先反色。）"""
import sys, os
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass


def variants(path):
    import numpy as np, cv2
    img = cv2.imdecode(np.fromfile(path, dtype=np.uint8), cv2.IMREAD_COLOR)
    if img is None: return []
    inv = 255 - img
    # 加白边：二维码四周要有静默区，OpenCV 才认得出来
    img = cv2.copyMakeBorder(img, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=(255,255,255))
    inv = 255 - img
    return [('原图', img), ('反色', inv),
            ('放大3倍', cv2.resize(img, None, fx=3, fy=3, interpolation=cv2.INTER_NEAREST)),
            ('反色+放大', cv2.resize(inv, None, fx=3, fy=3, interpolation=cv2.INTER_NEAREST))]

def scan(img):
    res = []
    try:
        import cv2
        d = cv2.QRCodeDetector()
        ok, dec, _, _ = d.detectAndDecodeMulti(img)
        if ok and dec: res += [x for x in dec if x]
        one = d.detectAndDecode(img)[0]
        if one: res.append(one)
    except Exception: pass
    try:
        from pyzbar.pyzbar import decode as zb
        for r in zb(img):
            try: res.append(r.data.decode('utf-8'))
            except Exception: pass
    except Exception: pass
    return res

def main():
    path = ' '.join(sys.argv[1:]).strip().strip('"')
    if not path: path = input('  把图片拖进来再回车: ').strip().strip('"')
    if not os.path.isfile(path): print('  找不到:', path); return
    found = []
    for tag, img in variants(path):
        for r in scan(img):
            if r and r not in found:
                found.append(r)
                print('  [%s] 扫到: %s' % (tag, r))
                print('  ★ 答案：%s\n' % r)
    if not found:
        print('  没扫出来。可以试：')
        print('   1) 把图片放大看看是不是二维码')
        print('   2) 如果是 0/1 数据，用「0/1 转图片」工具先拼图')
        print('   3) 用手机对着屏幕扫（有时比软件灵）')

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
