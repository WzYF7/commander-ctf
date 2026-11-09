# -*- coding: utf-8 -*-
"""Web 题起手式 —— 扫一扫靶机上"不该公开"的路径。

（Web 题第一步永远是信息收集：先看网站有没有把源码备份、版本库、
  配置文件这些东西放在服务器上。这些东西能下载，题基本就通了。
  这叫"源码泄露"，是新手最该先学会的一类。）

用法: python web.py http://靶机:端口

⚠ 只对你自己的靶机用，不要扫别人的网站（违法）。

（这个工具是补充进来的 —— 原来暴力插件只处理文件，不处理网址。）"""
import sys, urllib.request, urllib.error, ssl
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass

PATHS = [
    ('/robots.txt','爬虫说明，常暴露隐藏目录 —— 每道 Web 题第一个看这个'),
    ('/.git/HEAD','.git 没删干净 → 能用 git-dumper 扒整个源码'),
    ('/.git/config','同上'),
    ('/.svn/entries','SVN 版本库泄露'),
    ('/www.zip','源码打包下载（高频考点）'),
    ('/web.zip','同上'),
    ('/wwwroot.zip','同上'),
    ('/backup.zip','备份文件'),
    ('/index.php.bak','编辑器备份（.bak/.swp/~ 结尾都试试）'),
    ('/index.php~','同上'),
    ('/.index.php.swp','vim 临时文件'),
    ('/flag.php','直接猜 flag 位置'),
    ('/flag','同上'),
    ('/admin/','后台入口'),
    ('/phpinfo.php','PHP 配置泄露'),
    ('/test.php','测试文件'),
    ('/.DS_Store','Mac 打包残留，暴露目录结构'),
    ('/.htaccess','Apache 配置'),
    ('/composer.json','PHP 依赖，暴露框架版本'),
    ('/package.json','Node 依赖'),
    ('/README.md','项目说明'),
    ('/Dockerfile','部署文件'),
    ('/.env','环境变量（含数据库密码！）'),
]

def get(url, timeout=6):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    try:
        r = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return r.status, r.read(500)
    except urllib.error.HTTPError as e:
        return e.code, b''
    except Exception:
        return None, b''

def main():
    base = ' '.join(sys.argv[1:]).strip().strip('"')
    if not base: base = input('  输入靶机地址（如 http://1.2.3.4:8080）: ').strip()
    if not base: print('  （没输入）'); return
    base = base.rstrip('/')
    print('=== Web 起手式扫描 ===')
    print('  目标: %s' % base)
    print('  （只对你自己有权测试的靶机用）')
    print()
    found = []
    for p, why in PATHS:
        code, body = get(base + p)
        if code == 200:
            found.append((p, why, body))
            print('  ★ [200 存在] %-24s %s' % (p, why))
        elif code in (301, 302, 403):
            print('    [%3d]        %-24s %s' % (code, p, why))
    print()
    if found:
        print('  ★★ 有发现，马上打开这些看看：')
        for p, why, body in found:
            print('     %s%s' % (base, p))
            print('        %s' % why)
            if body.strip():
                print('        内容开头: %s' % body[:120].decode('utf-8', 'replace').replace(chr(10), ' '))
    else:
        print('  没扫到。下一步：')
    print()
    print('  ── 不管扫没扫到，Web 题都要做这几步 ──')
    print('   1. 浏览器按 F12：Network 看请求参数 / Application 看 Cookie / Sources 翻 JS')
    print('   2. 看网址参数（?id=1 这种），改数字、加引号试试')
    print('   3. 扫目录：向导菜单 32（dirsearch）')
    print('   4. SQL 注入：向导菜单 33（sqlmap）')

if __name__ == '__main__':
    try: main()
    except (EOFError, KeyboardInterrupt): print('\n  （中断）')
    except Exception as e: print('\n  [!] 出错: %s' % e)
