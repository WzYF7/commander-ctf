# -*- coding: utf-8 -*-
"""Git 泄露分析 —— 网站源码里的 .git 目录被人扒下来了，怎么挖东西。

（原理：开发网站时用 git 管理代码，有些人把 .git 目录一起传到服务器上了。
  别人能访问 /.git/ 就能把整个仓库扒下来 —— 里面有历史提交、被删掉的代码，
  flag 常常藏在"已经删掉"的那次提交里。）

用法：
  python gitdeep.py 某个目录          （目录里要有 .git）
  python gitdeep.py xxxx.tar.gz      （会自动解压）
"""
import os, sys, subprocess, tempfile, shutil, glob, re, tarfile, zipfile
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass

FLAG_RE = re.compile(r'[\w\u4e00-\u9fff]{2,20}\{[^}\n]{3,200}\}')

def git(cwd, *args, timeout=120):
    try:
        r = subprocess.run(['git'] + list(args), cwd=cwd, capture_output=True,
                           text=True, encoding='utf-8', errors='ignore', timeout=timeout)
        return (r.stdout or '') + (r.stderr or '')
    except FileNotFoundError:
        return '__NOGIT__'
    except Exception as e:
        return '[git 出错: %s]' % e

def scan_flags(text, tag, found):
    for m in FLAG_RE.finditer(text or ''):
        s = m.group()
        if s.startswith('flag{...') or '{...}' in s: continue
        if s not in found:
            found.append(s)
            print('   ★★ [%s] 发现: %s' % (tag, s))

def main():
    path = ' '.join(sys.argv[1:]).strip().strip('"')
    if not path: path = input('  把 .git 所在目录（或压缩包）拖进来: ').strip().strip('"')
    if not os.path.exists(path):
        print('  找不到:', path); return
    tmp = None
    if os.path.isfile(path):
        ext = path.lower()
        d = tempfile.mkdtemp(prefix='gitdeep_'); tmp = d
        try:
            if ext.endswith(('.tar.gz','.tgz','.tar')):
                tarfile.open(path).extractall(d, filter='data'); print('  已解压 tar ->', d)
            elif ext.endswith('.zip'):
                zipfile.ZipFile(path).extractall(d); print('  已解压 zip ->', d)
            else:
                print('  [!] 不认识这个压缩格式，试试先解压再指定目录'); return
            path = d
        except Exception as e:
            print('  解压失败:', e); return

    # 找 .git 目录
    gitdir = None
    for root, dirs, files in os.walk(path):
        if '.git' in dirs: gitdir = os.path.join(root, '.git'); path = root; break
    if not gitdir:
        print('  没找到 .git 目录')
        print('  （确认一下：是目录里有 .git 文件夹，还是这个目录本身就是 .git？）')
        if os.path.isdir(os.path.join(path, 'objects')) and os.path.isfile(os.path.join(path, 'HEAD')):
            gitdir = path; print('  → 这个目录本身就是 .git！')
        else:
            return
    print('  .git 位置: %s' % gitdir)

    if git('', '--version').startswith('__NOGIT__'):
        print('  [!] 没找到 git 命令。你可以手动做：')
        print('      1. 装 Git（工具箱 01-通用工具 里没有的话去 git-scm.com 下）')
        print('      2. 在 .git 目录里执行: git log -p / git fsck --lost-found')
        print('      （为什么需要 git：分析版本库要靠 git 自己的命令，没有它不好办）')
        return

    found = []
    print('')
    print('═' * 60)
    print('  ① 提交历史（被删掉的东西可能在历史里）')
    print('═' * 60)
    log = git(path, 'log', '--all', '--oneline', '--graph')
    print('\n'.join('  ' + l for l in log.splitlines()[:20]) or '  （没有提交记录）')
    scan_flags(log, 'log', found)

    print('')
    print('═' * 60)
    print('  ② 所有文件的内容（含历史版本）')
    print('═' * 60)
    allobjs = git(path, 'cat-file', '--batch-all-objects', '--batch-check=%(objecttype) %(objectname)')
    blobs = [l.split()[1] for l in allobjs.splitlines() if l.startswith('blob')]
    print('  仓库里共有 %d 个文本对象' % len(blobs))
    for sha in blobs[:400]:
        c = git(path, 'cat-file', '-p', sha, timeout=20)
        scan_flags(c, 'blob:' + sha[:8], found)
    if len(blobs) > 400: print('  （只扫了前 400 个，够用了）')

    print('')
    print('═' * 60)
    print('  ③ 悬空 / 被丢弃的提交（git fsck）')
    print('═' * 60)
    fsck = git(path, 'fsck', '--lost-found', '--no-progress')
    print('\n'.join('  ' + l for l in fsck.splitlines()[:20]) or '  （没有悬空对象）')
    scan_flags(fsck, 'fsck', found)
    # 悬空对象在 .git/lost-found 里，也扫一遍
    for sub in ('lost-found/commit', 'lost-found/other'):
        d2 = os.path.join(gitdir, sub)
        if os.path.isdir(d2):
            for f in glob.glob(os.path.join(d2, '*')):
                try: scan_flags(open(f, encoding='utf-8', errors='ignore').read(), sub, found)
                except Exception: pass

    print('')
    print('═' * 60)
    print('  ④ reflog（"引用日志"，记录了所有操作，能挖到被 reset 掉的提交）')
    print('═' * 60)
    log2 = git(path, 'reflog', '--all')
    print('\n'.join('  ' + l for l in log2.splitlines()[:15]) or '  （没有 reflog）')
    scan_flags(log2, 'reflog', found)

    print('')
    print('═' * 60)
    if found:
        print('  ★★★ 找到这些：')
        for f in found[:10]: print('     ' + f)
    else:
        print('  没直接扫到 flag。下一步可以试：')
        print('   1. 在目录里跑: git log -p  （看每次提交改了什么）')
        print('   2. git diff HEAD~1         （看上一次提交的区别）')
        print('   3. 用 git-dumper 把网站上的 .git 整个扒下来:')
        print('      pip install git-dumper && git-dumper http://靶机/.git/ 输出目录')
    print('═' * 60)
    if tmp: print('\n  （临时解压目录: %s，用完可以删）' % tmp)

if __name__ == '__main__':
    try: main()
    except (EOFError, KeyboardInterrupt): print('\n  （输入中断）')
    except Exception as e: print('\n  [!] 出错: %s' % e)