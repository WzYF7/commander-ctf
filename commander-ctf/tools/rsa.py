# -*- coding: utf-8 -*-
"""RSA 解密 —— 按提示输数字就行。

RSA 是"公钥密码"，题目通常给你一堆大数字：
  n = p × q        （两个质数相乘，n 是公开的）
  e                （公开指数，常是 65537）
  c                （密文，加密后的结果）
  d                （私钥，p 和 q 一知道就能算出来；有 d 就能解密）

解 RSA 的核心就一句话：想办法把 n 拆成 p 和 q。
（为什么：n 是公开的，但如果能分解出它的两个质因数 p、q，
  就能算出私钥 d，然后明文 m = c^d mod n）"""
import sys
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass

def l2b(n):
    if n == 0: return b'\x00'
    b = []
    while n > 0: b.append(n & 0xff); n >>= 8
    return bytes(reversed(b))

def egcd(a, b):
    if b == 0: return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)

def inv(a, m):
    g, x, _ = egcd(a % m, m)
    return None if g != 1 else x % m

def show(m):
    try: t = l2b(m).decode('utf-8')
    except Exception: t = repr(l2b(m))
    print('\n  ★ 明文 = %s' % t)
    print('  ★ 十进制 = %s' % m)
    if '{' in t and '}' in t: print('\n  ★★★ 看着就是 flag，快提交！ ★★★')

def case1():
    print('  （p、q 是两个质数，e 是公开指数，c 是密文）')
    p = int(input('  p = ')); q = int(input('  q = ')); e = int(input('  e = ')); c = int(input('  c = '))
    d = inv(e, (p-1)*(q-1))
    if d is None: print('  [!] e 与 (p-1)(q-1) 不互素，p/q 可能不对'); return
    show(pow(c, d, p*q))

def fermat(n, limit=300000):
    """Fermat 分解：p 和 q 很接近时特别快"""
    import math
    a = math.isqrt(n)
    if a*a < n: a += 1
    for _ in range(limit):
        b2 = a*a - n
        b = math.isqrt(b2)
        if b*b == b2: return a-b, a+b
        a += 1
    return None

def case2():
    print('  （只有 n、e、c 时，我来试着把 n 拆开）')
    n = int(input('  n = ')); e = int(input('  e = ')); c = int(input('  c = '))
    print('  尝试 1：试除小质数...')
    i = 2
    while i < 2000000 and i*i <= n:
        if n % i == 0:
            p, q = i, n//i; print('     找到小因子 p =', p)
            show(pow(c, inv(e,(p-1)*(q-1)), n)); return
        i += 1 if i == 2 else 2
    print('  尝试 2：Fermat（适合 p、q 很接近的情况）...')
    r = fermat(n)
    if r:
        p, q = r; print('     成功:', p, '*', q)
        show(pow(c, inv(e,(p-1)*(q-1)), n)); return
    print('  尝试 3：用 sympy 分解...')
    try:
        import sympy
        f = sympy.factorint(n, limit=10**7)
        ps = []
        for k, v in f.items(): ps += [int(k)]*v
        if len(ps) == 2:
            p, q = ps; print('     成功:', p, '*', q)
            show(pow(c, inv(e,(p-1)*(q-1)), n)); return
        print('     分解出多个因子:', ps)
    except Exception as ex: print('     sympy 也失败:', ex)
    print('\n  ✘ 没拆开。')
    print('  你可以手动做：打开 https://factordb.com ，把 n 贴进去查（这是个公开的大数分解数据库）')
    print('  （为什么要用在线数据库：有些 n 早就被人分解过并记录下来了，直接查比算快得多）')

def iroot(n, k):
    if n < 0: return 0, False
    x = int(round(n ** (1.0/k))) or 1
    for _ in range(200):
        y = ((k-1)*x + n // (x**(k-1))) // k
        if y == x: break
        x = y
    for d in range(-3, 4):
        if x+d >= 0 and (x+d)**k == n: return x+d, True
    return x, False

def case3():
    print('  （e 很小比如 3，且 c 也不大时：明文可能"没取过模"，直接开方就行）')
    e = int(input('  e = ')); n = int(input('  n = ')); c = int(input('  c = '))
    m, ok = iroot(c, e)
    if ok: print('  直接开方成功'); show(m); return
    for k in range(1, 300000):
        m, ok = iroot(c + k*n, e)
        if ok: print('  试了 %d 次成功' % k); show(m); return
    print('  ✘ 低指数攻击失败')

def case4():
    print('  （同一个 n，两组 e 和 c，e1 e2 互素时可用"共模攻击"）')
    n = int(input('  n  = '))
    e1 = int(input('  e1 = ')); c1 = int(input('  c1 = '))
    e2 = int(input('  e2 = ')); c2 = int(input('  c2 = '))
    g, a, b = egcd(e1, e2)
    if g != 1: print('  [!] e1 e2 不互素，标准共模攻击不适用'); return
    if a < 0: c1, a = inv(c1, n), -a
    if b < 0: c2, b = inv(c2, n), -b
    show((pow(c1,a,n) * pow(c2,b,n)) % n)

def main():
    print('=' * 58)
    print('  RSA 解密向导')
    print('=' * 58)
    print('  你手上有哪些数字？')
    print('    1. p、q、e、c            （最完整，直接解）')
    print('    2. 只有 n、e、c          （我来试着拆 n）')
    print('    3. e 很小 + n、c         （低指数攻击）')
    print('    4. 同一个 n，两组 e/c    （共模攻击）')
    print('    0. 退出')
    print('-' * 58)
    k = input('  选一个: ').strip()
    try:
        { '1': case1, '2': case2, '3': case3, '4': case4 }.get(k, lambda: print('  已退出'))()
    except Exception as ex:
        print('\n  [!] 出错:', ex)
        print('  （多半是数字贴错了，或者数字里混进了空格/换行。重新试一次，一个数字一行）')

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
