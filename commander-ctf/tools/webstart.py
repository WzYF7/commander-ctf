# -*- coding: utf-8 -*-
"""Web 题起手式 —— 帮你自动访问常见"不小心漏出来"的路径。

（Web 题的第一步永远是"信息收集"：先看看网站有没有把不该公开的东西
  放在服务器上，比如源码备份、版本库、配置文件。这些东西一旦能下载，
  整道题基本就通了 —— 这叫"源码泄露题"，是新手最该先学会的一类。）

⚠ 只对你自己的靶机用（比赛题目地址）。不要拿它去扫别人的网站，
   那是违法的，而且比赛现场也会被抓。
"""
import sys, urllib.request, urllib.error, ssl
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass

PATHS = [
    ('/robots.txt',        '网站"爬虫说明"，常暴露隐藏目录 —— 每道 Web 题第一个看这个'),
    ('/.git/HEAD',         '.git 目录没删干净 → 可以用 git-dumper 把整个源码扒下来'),
    ('/.git/config',       '同上'),
    ('/.svn/entries',      'SVN 版本库泄露'),
    ('/www.zip',           '源码打包下载（常见考点）'),
    ('/web.zip',           '同上'),
    ('/backup.zip',        '备份文件'),
    ('/index.php.bak',     '编辑器产生的备份文件（.bak/.swp/~ 结尾）'),
    ('/index.php~',        '同上'),
    ('/.index.php.swp',    'vim 编辑时的临时文件'),
    ('/flag.php',          '直接猜 flag 位置'),
    ('/flag',              '同上'),
    ('/admin/',            '后台入口'),
    ('/phpinfo.php',       'PHP 配置信息泄露（能看到很多细节）'),
    ('/test.php',          '测试文件常留在服务器上'),
    ('/.DS_Store',         'Mac 打包时留下的文件，会暴露目录结构'),
    ('/ds_store',          '同上'),
    ('/.htaccess',         'Apache 配置文件'),
    ('/composer.json',     'PHP 依赖声明，会暴露用了什么框架/版本'),
    ('/package.json',      'Node 项目依赖'),
]

def get(url, timeout=6):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={'User-Agent':'Mozilla/5.0'})
    try:
        r = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = r.read(400)
        return r.status, len(body), body
    except urllib.error.HTTPError as e:
        return e.code, 0, b''
    except Exception as e:
        return None, 0, str(e).encode()

def main():
    base = ' '.join(sys.argv[1:]).strip().strip('"')
    if not base: base = input('  输入靶机地址（如 http://1.2.3.4:8080）: ').strip()
    if not base: print('  (没输入)'); return
    base = base.rstrip('/')
    print('  目标: %s' % base)
    print('  （只对你自己的靶机用！）\n')
    found = []
    for p, why in PATHS:
        code, n, body = get(base + p)
        mark = '  '
        if code == 200:
            mark = '★ '; found.append((p, why, body))
            print('  %s[200 存在] %-22s %s' % (mark, p, why))
        elif code in (301, 302, 403):
            print('  [%d]         %-22s %s' % (code, p, why))
    print('')
    if not found:
        print('  没扫到什么。下一步：')
    else:
        print('  ★★ 有发现！这几个值得马上打开看看：')
        for p, why, body in found:
            print('     %s%s' % (base, p))
            print('        %s' % why)
            if body[:200].strip():
                print('        内容开头: %s' % body[:120].decode('utf-8','replace').replace('\n',' '))
    print('')
    print('  ── 不管扫没扫到，Web 题都该做这几步 ──')
    print('   1. 浏览器打开网站，按 F12：')
    print('      · Network  → 点几个功能，看每个请求发了什么参数')
    print('      · Application/Storage → 看 Cookie、LocalStorage')
    print('      · Sources  → 翻 JS，找硬编码的 key、接口地址')
    print('      · Console  → 可以直接执行 JS 试东西')
    print('   2. 看看网址的参数（?id=1 这种），试试改数字、加引号')
    print('   3. 用 dirsearch/ffuf 扫目录（工具菜单里有）')

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
