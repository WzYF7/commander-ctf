# -*- coding: utf-8 -*-
"""commander  ——  CTF 一体化解题助手

【两种模式】（启动时可以选）
  教学模式   每一步都告诉你「为什么这么做」，最后能生成一份教程
  解题模式   只给大概思路 + 结果，快

【产出】（项目目录内）
  中间文件      .commander-work/<题目名>/        （解出来的文件、位平面图、报告草稿）
  题解 / 教程   <插件目录>/writeups/            （你自己写题的成果）
  最终产出      <插件目录>/outcome/<题目名>/    （flag + 关键文件）

【特点】
  · 一次解不出 flag 也不结束 —— 会给出「接下来可以尝试的点」，你可以接着试
  · 有上下文 —— 你可以把下一个文件、或自己处理过的文件再送进来，前面解出的
    flag、试过的方向都还记着
  · 纯本地运行 —— 不联网、不接 AI 也能用
"""
import os, sys, re, time, shutil, importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.abspath(os.environ.get('COMMANDER_TOOLKIT_DIR') or os.path.join(HERE, 'toolkit'))
MID_BASE = os.path.join(HERE, '.commander-work')
SESSION_FILE = os.path.join(HERE, 'session.json')   # 会话记录（关掉再开也能接上）
OUT_DIR  = os.path.join(HERE, 'outcome')
WU_DIR   = os.path.join(HERE, 'writeups')
TOOLS    = os.path.join(HERE, 'tools')

for _d in (MID_BASE, OUT_DIR, WU_DIR):
    try: os.makedirs(_d, exist_ok=True)
    except Exception: pass

# ---- 常用解释器 / 速查库（commander的"外脑"：按编号给 工具+位置+步骤+原理）----
PY312 = sys.executable
for _p in (HERE, TOOLS):
    if _p not in sys.path:
        sys.path.insert(0, _p)
try:
    import cheatsheet as CS
except Exception:
    CS = None
try:
    import routes as RT
except Exception:
    RT = None
try:
    import guide_map as GM
except Exception:
    GM = None

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass


# ============================ 会话（保留上下文）============================
class Session:
    def __init__(self):
        self.mode = 'solve'
        self.items = []      # 分析过的文件
        self.flags = {}      # flag -> 来源
        self.notes = []      # 全程文字记录（写题解/教程用）
        self.tried = []      # 已经试过的方向（用户标记"这个我试过了"）
        self.suggestions = []  # 上一轮给出的建议（编号后可标记已试）
        self.last_ctx = None   # 最近一次分析的文件/类型/特征（路线导航用）
        self.last_ranked = []  # 上一次路线排序（R1/R2 用）
        self.diag_path = None  # 最近一次诊断报告
        self.started = time.strftime('%Y-%m-%d %H:%M:%S')

    # ---- 存档 / 读档：让上下文跨次保留 ----
    def save(self):
        import json
        try:
            d = {
                'saved': time.strftime('%Y-%m-%d %H:%M:%S'),
                'mode': self.mode,
                'items': self.items[-30:],
                'flags': self.flags,
                'tried': self.tried[-60:],
                'suggestions': self.suggestions[-30:],
                'last_ctx': self.last_ctx,
                'last_ranked': self.last_ranked,
                'diag_path': self.diag_path,
            }
            with open(SESSION_FILE, 'w', encoding='utf-8') as f:
                json.dump(d, f, ensure_ascii=False, indent=1)
        except Exception:
            pass

    def load(self):
        import json
        try:
            if not os.path.isfile(SESSION_FILE):
                return False
            with open(SESSION_FILE, encoding='utf-8') as f:
                d = json.load(f)
            self.items = d.get('items') or []
            self.flags = d.get('flags') or {}
            self.tried = d.get('tried') or []
            self.suggestions = d.get('suggestions') or []
            self.last_ctx = d.get('last_ctx')
            self.last_ranked = d.get('last_ranked') or []
            self.diag_path = d.get('diag_path')
            return bool(self.items or self.flags or self.tried)
        except Exception:
            return False

S = Session()


def out(msg='', color=None):
    print(msg, flush=True)
    S.notes.append(msg)


def banner():
    def _row(txt):
        import unicodedata as _ud
        _w = sum(2 if _ud.east_asian_width(_c) in ('W', 'F') else 1 for _c in txt)
        return '  ║' + txt + ' ' * max(0, 58 - _w) + '║'
    print()
    print('  ╔' + '═' * 58 + '╗')
    print(_row('  C O M M A N D E R'))
    print(_row('  CTF 一体化助手  /  暴力解题  /  写题解  /  写教程'))
    print('  ╚' + '═' * 58 + '╝')
    print()


def pick_mode():
    print('  请选择模式：')
    print()
    print('    1. 教学模式   每一步都会告诉你「为什么这么做」')
    print('                  （适合学东西，最后能生成教程）')
    print('    2. 解题模式   只给大概思路 + 结果，快')
    print('                  （适合赶时间做题）')
    print()
    while True:
        try:
            c = input('  输入 1 或 2（直接回车 = 解题模式）: ').strip()
        except EOFError:
            return 'solve'
        if c in ('', '2'): return 'solve'
        if c == '1': return 'learn'
        print('  请输入 1 或 2')


# ============================ 引擎 ============================
_ENG = None

def engine():
    """把分析引擎加载进来（暴力插件的 super.py）"""
    global _ENG
    if _ENG is not None:
        return _ENG
    p = os.path.join(HERE, 'engine.py')
    sp = importlib.util.spec_from_file_location('candidate_engine', p)
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    _ENG = m
    return m


def run_engine(path, mid_dir):
    """跑一遍分析引擎，教学模式保留「为什么」，解题模式屏蔽"""
    eng = engine()
    eng.OUTDIR = mid_dir
    os.makedirs(mid_dir, exist_ok=True)
    try:
        from diagnostics import Diagnostics
        eng.DIAG = Diagnostics(mid_dir, path, S.mode)
        eng.diag('session', 'start', '启动诊断流水线',
                 assumption='自动结果只是候选；每一步都应保留证据、产物和手工接手点',
                 evidence=path, confidence='high')
    except Exception as _de:
        eng.DIAG = None
        print('  （诊断器未加载：%s）' % _de)

    if S.mode == 'solve':
        # 解题模式：把「为什么…」这类详细解释静音，只留结论
        eng.why = lambda msg: None
        _h = eng.head
        eng.head = lambda t: (_h('') or True) and None if False else (eng.say(''), eng.say('▶ ' + t))

    eng.analyze(path, 0)
    return eng


# ============================ 接下来可以尝试的点 ============================
NEXT_HINTS = {
    'image': [
        '把图片拖进「tools\\stego.py」再做一次位平面 + LSB 深挖',
        '打开 StegSolve（输 tools）肉眼翻颜色通道和位平面',
        '试试把后缀改成 .zip，用 7-Zip 打开（图片里可能塞了压缩包）',
        '看看图片宽高有没有被改（tools\\imgdeep.py 会自动算真实高度）',
        '两张几乎一样的图 → 试盲水印（bw-extract 带水印.png 原图.png 输出.png）',
        'JPEG 图 → 试 StegExpose / F5（输 tools 能开）',
    ],
    'archive': [
        '伪加密：tools\\archive.py 能检测并生成修复版',
        '弱口令：tools\\archive.py 会用字典爆破',
        '看压缩包"注释"字段（有时 flag 直接写在注释里）',
        '压缩包尾部可能还接了别的东西 → tools\\carve.py 切出来',
    ],
    'text': [
        '把内容粘进 tools\\decode.py 试所有编码（base64/85/58/摩斯/凯撒…）',
        '试键盘密码 tools\\keyboard.py（手放歪了那种）',
        '试零宽字符 tools\\zerowidth.py（看不见的字符）',
        '算一下熵 tools\\entropy.py，看有没有"突然变乱"的一段',
    ],
    'exe': [
        '先看是什么语言：tools 里开 DetectItEasy',
        'PyInstaller 打包的 → tools\\pyreverse.py 能还原源码',
        '.NET 的 → 直接开 dnSpy 看源码（输 tools）',
        '有 UPX 壳 → 先脱壳再分析（输 tools 里有）',
        '先提一遍字符串：tools\\strings_tool.py',
    ],
    'pcap': [
        '在 Wireshark 里手动看：Statistics → Protocol Hierarchy',
        '过滤框试试 frame contains "flag"',
        'USB 流量？过滤 usb，导出 HID 数据',
        '非 HTTP 流量（TCP 裸传）要在 Wireshark 里逐条看',
    ],
    'web': [
        'F12 看 Network / Application / Sources',
        '扫目录：dirsearch / ffuf（字典在 07-字典）',
        '试 SQL 注入：sqlmap',
        '试常见泄露：/.git/ /www.zip /.env /robots.txt',
    ],
    'unknown': [
        '先判断它到底是什么：tools 里开 DetectItEasy',
        '用 ImHex 看文件头（信文件头，别信后缀名）',
        '试试 tools\\carve.py 看里面有没有藏东西',
    ],
}


# 文件类型 -> 速查编号（commander给建议时用这些编号来指引你）
KIND_TO_NOS = {
    'image':   ['11', '19', '12', '13', '20', '16', '15'],
    'audio':   ['18'],
    'archive': ['14', '13', '54', '73'],
    'text':    ['21', '22', '23', '26', '27', '28', '17', '65', '72'],
    'exe':     ['41', '48', '42', '46', '47', '43', '66', '67', '68', '69'],
    'pcap':    ['51', '52', '56', '75'],
    'web':     ['31', '32', '33', '34', '61', '62', '63', '64', '65'],
    'apk':     ['44', '41', '70'],
    'wasm':    ['45'],
    'unknown': ['01', '03', '02', '13', '54', '55', '74'],
}


def guess_kind(path, eng):
    """根据文件特征猜它属于哪一类，用来给"接下来可以试的点"  """
    try:
        with open(path, 'rb') as f:
            head = f.read(16)
    except Exception:
        return 'unknown'
    ext = os.path.splitext(path)[1].lower()
    if head[:8] == b'\x89PNG\r\n\x1a\n' or head[:3] == b'\xff\xd8\xff' or head[:3] == b'GIF' or head[:2] == b'BM':
        return 'image'
    if head[:2] == b'PK' or head[:4] == b'Rar!' or head[:4] == b'7z\xbc\xaf':
        return 'archive'
    if head[:2] == b'MZ' or head[:4] == b'\x7fELF':
        return 'exe'
    if ext in ('.wav', '.mp3', '.flac', '.ogg', '.m4a', '.wma'):
        return 'audio'
    if ext == '.apk':
        return 'apk'
    if ext == '.wasm' or head[:4] == b'\x00asm':
        return 'wasm'
    if ext in ('.pcap', '.pcapng', '.cap') or head[:4] in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
        return 'pcap'
    if head[:1] == b'{' or (32 <= head[0] < 127 and all(32 <= c < 127 or c in (9,10,13) for c in head[:8])):
        return 'text'
    try:
        import unicodedata as _ud
        with open(path, 'rb') as _f:
            _raw = _f.read(4096)
        _t = _raw.decode('utf-8')
        if _t and sum(1 for _c in _t if _c in '\r\n\t' or _ud.category(_c) not in ('Cc', 'Cs', 'Co', 'Cn')) / len(_t) > 0.9:
            return 'text'
    except Exception:
        pass
    return 'unknown'


def show_next_steps(path, eng, kind):
    """给出「接下来可以尝试的点」—— 解不出 flag 时尤其重要"""
    print()
    print('  ' + '═' * 58)
    print('  ★ 接下来可以尝试的点')
    print('  ' + '═' * 58)

    n = 0
    S.suggestions = []
    _seen = set()

    def _emit(no):
        nonlocal n
        if n >= 14 or not CS: return
        e = CS.find(no)
        if not e: return
        if e['no'] in _seen or e['title'] in S.tried: return
        _seen.add(e['no']); n += 1
        _tl = (e.get('where') or '').strip()
        _tl = os.path.basename(_tl) if _tl else ''
        print('   #%-4s %s%s' % (e['no'], e['title'], ('   [' + _tl + ']') if _tl else ''))
        S.suggestions.append('#%s %s' % (e['no'], e['title']))

    for _no in KIND_TO_NOS.get(kind, KIND_TO_NOS['unknown']):
        _emit(_no)

    try:
        for h in list(eng.HINTS)[:4]:
            t = h[1] if isinstance(h, (list, tuple)) and len(h) > 1 else str(h)
            if not t or t in S.tried or t in _seen: continue
            if n >= 14: break
            _seen.add(t); n += 1
            print('   %2d. %s' % (n, t))
            S.suggestions.append(t)
    except Exception:
        pass

    print()
    print('   （带 #编号 的：输编号就能看详细步骤/工具位置/原理，比如输 12）')
    print('   （试过哪条就输 试过 <编号>；试完的结果或文件再拖进来，我还记着前面的）')
    print()
    print('   （上面这些不用一次试完。试过哪条就输 试过 <编号> 告诉我，')
    print('     下次不会再重复列；试完的结果或文件再送进来，我还记着前面的成果）')
    print('  ' + '═' * 58)


# ============================ 路线导航 ============================
def route_features(path, kind, eng):
    """从文件类型 + 分析记录 + 文本特征里提取"通用线索"（不依赖题目名）"""
    feats = set()
    if kind: feats.add(str(kind))
    ext = os.path.splitext(path)[1].lower().lstrip('.')
    if ext: feats.add('ext:' + ext)
    if kind in ('png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'ico', 'tiff'): feats.add('image')
    if kind in ('zip', 'rar', '7z', 'gz', 'bz2', 'xz', 'tar'): feats.add('archive')
    if kind in ('riff', 'mp3', 'ogg', 'flac'): feats.add('audio')
    if kind in ('exe', 'elf', 'apk', 'wasm', 'dex'): feats.add('binary')
    if kind in ('docx', 'xlsx', 'pptx'): feats.add('office')
    notes = ' '.join(getattr(eng, 'NOTES', []) or []).lower() if eng else ''
    table = {
        'lsb': ['lsb', '位平面', 'zsteg', '最低位'],
        'crc': ['crc 不对', 'crc不对', '宽高被改', '真实高度', '修复版'],
        'trailing': ['尾部还有', '尾部有', '附加数据', '尾部数据'],
        'embedded': ['嵌入', '内嵌', '复合文件'],
        'qr': ['二维码', 'qr'],
        'exif': ['exif', '元数据'],
        'comment': ['注释', 'comment'],
        'pseudo': ['伪加密'],
        'encrypted': ['加密', '密码', 'password'],
        'http': ['http'], 'dns': ['dns'], 'usb': ['usb'], 'icmp': ['icmp'],
        'git': ['git'], 'pyinstaller': ['pyinstaller'], 'dotnet': ['.net', 'dnspy'],
        'upx': ['upx'], 'jwt': ['jwt'], 'hashish': ['md5', 'sha1', 'sha256', '哈希'],
        'rsaish': ['rsa'], 'invisible': ['零宽', '空白', '变体'],
        'xorish': ['异或', 'xor'], 'emoji': ['emoji', '表情'],
        'known_plain': ['已知明文', '明文攻击'],
    }
    for tok, words in table.items():
        if any(w in notes for w in words):
            feats.add(tok)
    try:
        t = open(path, encoding='utf-8', errors='ignore').read() if kind in ('text', 'unknown', 'datauri') else ''
        st = t.strip()
        if st:
            chars = re.sub(r'\s', '', st)
            alpha = set(chars)
            if 2 <= len(alpha) <= 64 and len(st) >= 16:
                feats.add('small_alpha')
            if len(chars) >= 64 and len(alpha) > 8:
                feats.add('long_text')
            if re.fullmatch(r'[.\-\s/]+', st): feats.add('morseish')
            if re.search(r'eyJ[\w-]+\.eyJ[\w-]+\.', st): feats.add('jwt')
            if re.fullmatch(r'(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})', st): feats.add('hashish')
            if all(k in st for k in ('n', 'e', 'c')) and re.search(r'\bn\s*=', st): feats.add('rsaish')
            if st.isalpha() and len(st) >= 20: feats.add('alpha_only')
            if any(c in st for c in '\u200b\u200c\u200d\ufeff') or any(0xFE00 <= ord(c) <= 0xFE0F for c in st):
                feats.add('invisible')
            if alpha and all(ord(c) > 127 for c in alpha) and len(alpha) <= 64:
                feats.add('emoji')
            if re.fullmatch(r'[ACGTacgt\s]+', st) and len(st) >= 24: feats.add('dna')
    except Exception:
        pass
    try:
        d = os.path.dirname(path)
        imgs = [f for f in os.listdir(d) if f.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif'))]
        if len(imgs) >= 2: feats.add('two_images')
    except Exception:
        pass
    return feats


def _stars(n):
    n = max(1, min(5, int(n)))
    return '★' * n + '☆' * (5 - n)


def _rank_routes(feats):
    if not RT:
        return []
    out = []
    for r in RT.ROUTES:
        matched = [c for c in r.get('clues', []) if c in feats]
        score = r.get('freq', 1) * 8 + len(matched) * 6
        CAT = {'图片': {'image'}, '文本': {'text'}, '压缩包': {'archive'}, '音频': {'audio'},
               '流量': {'pcap'}, '逆向': {'binary'}, 'Web': {'web'},
               '取证': {'pdf', 'office', 'sqlite', 'git', 'unknown', 'embedded', 'disk'}}
        if CAT.get(r.get('cat'), set()) & feats:
            score += 25
        else:
            score -= 25
        if r['id'] in S.tried: score -= 100
        out.append((score, len(matched), r, matched))
    out.sort(key=lambda x: (-x[0], -x[1]))
    return out


def show_routes(all_routes=False):
    if not RT:
        print('  路线库没加载（routes.py 不在？）')
        return
    ctx = S.last_ctx or {}
    feats = set(ctx.get('features') or [])
    if not feats and S.items:
        feats = {'text'}
    if not feats:
        print('  先把文件拖进来分析一次（Web 题先跑 webaudit URL），我再按线索排路线')
        return
    ranked = _rank_routes(feats)
    S.last_ranked = [r['id'] for _, _, r, _ in ranked]
    print()
    print('  ' + '═' * 62)
    print('  ◆ 路线导航（一遍没出 flag 就按这个顺序自己试）')
    print('  ' + '═' * 62)
    if ctx.get('path'):
        print('  文件：%s' % ctx.get('path'))
    print('  已观察线索：%s' % (', '.join(sorted(feats)) or '（无）'))
    print()
    show = ranked if all_routes else ranked[:8]
    for i, (score, nmatch, r, matched) in enumerate(show, 1):
        print('  R%-2d [%s] %s' % (i, r['cat'], r['name']))
        print('      常见度 %s   线索: %s' % (_stars(r.get('freq')), ', '.join(matched) if matched else '（按文件类型匹配）'))
        print('      什么时候用: %s' % r['when'])
        _g = route_guidance(r)
        print('      工具: %s    工具说明里搜: %s' % (_g['tool'], _g['search']))
    print()
    print('  怎么用：')
    print('    · 输 R1 / R2 … 看该路线的详细步骤（会接上速查表 #编号）')
    print('    · 输 路线 全部 看全部路线')
    print('    · 试过 R1 标记这条已试过；跑 R1 看该路线的命令/操作')
    print('    · 试完把新文件/结果再拖进来，进度会接上')


def show_route(rid):
    if not RT:
        return
    r = RT.get(rid)
    if not r:
        # R1/R2 这种序号 -> 上一次排序
        m = re.fullmatch(r'[Rr]?(\d{1,2})', str(rid).strip())
        if m and S.last_ranked:
            i = int(m.group(1)) - 1
            if 0 <= i < len(S.last_ranked):
                r = RT.get(S.last_ranked[i])
    if not r:
        print('  没有这条路线。输「路线」看当前可选的 R 编号。')
        return
    print()
    print('  ' + '═' * 62)
    print('  ◆ %s  %s' % (r['id'], r['name']))
    print('  ' + '═' * 62)
    print('  分类：%s    考点常见度：%s' % (r['cat'], _stars(r.get('freq'))))
    print('  什么时候用：%s' % r['when'])
    print('  对应线索：%s' % ', '.join(r.get('clues') or []))
    _print_route_guidance(r)
    print('  怎么做：')
    for i, st in enumerate(r.get('steps') or [], 1):
        print('    %d) %s' % (i, st))
    print('  失败后接着试：%s' % (', '.join(r.get('next') or []) or '（无）'))
    if r.get('ref') and CS:
        e = CS.find(r['ref'])
        if e:
            print()
            print('  —— 详细工具/路径/命令（速查 #%s）——' % r['ref'])
            print(CS.render(e))
    print()
    print('  （做完把结果文件拖回来；想标记已试：输「试过 %s」）' % r['id'])


def run_route(rid):
    if not RT:
        return
    r = RT.get(rid)
    if not r:
        m = re.fullmatch(r'[Rr]?(\d{1,2})', str(rid).strip())
        if m and S.last_ranked:
            i = int(m.group(1)) - 1
            if 0 <= i < len(S.last_ranked):
                r = RT.get(S.last_ranked[i])
    if not r:
        print('  没有这条路线。输「路线」看编号。')
        return
    print()
    print('  ▶ %s 的操作（照做即可）' % r['name'])
    _print_route_guidance(r)
    for i, st in enumerate(r.get('steps') or [], 1):
        print('    %d) %s' % (i, st))
    if r.get('ref') and CS:
        e = CS.find(r['ref'])
        if e and e.get('where'):
            ap = e['where']
            if not os.path.isabs(ap):
                ap = os.path.join(HERE, ap)
            print('    工具：%s' % ap)


# ============================ 新手向导 ============================
GUIDE_CHEAT = os.path.join(HERE, 'README.md')


def _cs_entry_for_route(d):
    if not CS:
        return None
    try:
        return CS.find(str(d.get('ref') or ''))
    except Exception:
        return None


def _format_tool_location(where):
    """Turn a cheat-sheet location into a readable path without pretending it exists."""
    where = str(where or '').strip()
    if not where:
        return '（速查表没有记录可执行位置；按工具名在开始菜单搜索）'
    if where.startswith('（') or where.lower().startswith(('http://', 'https://')):
        return where
    looks_like_path = (':\\' in where or where.startswith('\\\\') or
                       '\\' in where or where.startswith('commander'))
    if looks_like_path and not os.path.isabs(where):
        parts = where.replace('\\', '/').split('/')
        where = os.path.join(HERE, *parts[1:]) if parts[0].lower() == 'commander' else os.path.join(KIT, *parts)
    if looks_like_path:
        if os.path.exists(where):
            return where
        return where + '  （当前路径不存在，请检查工具是否已安装）'
    return where + '（在开始菜单/工具菜单中搜索这个名称）'


def route_guidance(d):
    """Return exact tool, UI/document search terms, and tutorial section."""
    rid = str(d.get('id') or '')
    meta = {}
    if GM:
        meta = dict(getattr(GM, 'ROUTE_GUIDES', {}).get(rid) or {})
    if not meta:
        meta = dict((getattr(GM, 'CATEGORY_FALLBACK', {}) if GM else {}).get(d.get('cat'), {}))
    e = _cs_entry_for_route(d)
    where = (e or {}).get('where') or ''
    ref = str(d.get('ref') or '')
    return {
        'tool': meta.get('tool') or (e or {}).get('tool') or 'commander',
        'where': _format_tool_location(where),
        'search': meta.get('search') or '工具名 / 当前操作 / 报错信息',
        'doc_section': meta.get('doc') or d.get('name') or rid,
        'ref': ref,
    }


def guide_for_route(d):
    return GUIDE_CHEAT, '新手向导'


def _print_route_guidance(d):
    g = route_guidance(d)
    guide, section = guide_for_route(d)
    print('  推荐工具：%s%s' % (g['tool'], ('（速查 #%s）' % g['ref']) if g['ref'] else ''))
    print('  工具位置：%s' % g['where'])
    print('  工具说明/界面里搜：%s' % g['search'])
    print('  不会就看：%s' % guide)
    print('  教程里搜：%s' % section)


def _open_guide_tool(d):
    """Open the route's installed tool when its location is a real file/folder."""
    import subprocess
    g = route_guidance(d)
    where = g['where']
    print('  工具/位置：%s' % where)
    if where.lower().startswith(('http://', 'https://')):
        import webbrowser
        webbrowser.open(where)
        return
    p = where.split('  （', 1)[0].strip()
    if not p or not os.path.exists(p):
        print('  无法直接打开；请在开始菜单搜索「%s」，或先按「教程里搜」查看手工步骤。' % g['tool'])
        return
    try:
        if os.path.isdir(p):
            os.startfile(p)
        elif p.lower().endswith(('.html', '.htm')):
            import webbrowser
            webbrowser.open(p)
        elif p.lower().endswith('.jar'):
            subprocess.Popen([shutil.which('java') or 'java', '-jar', p])
        elif p.lower().endswith('.py'):
            subprocess.Popen([PY312, p], cwd=os.path.dirname(p))
        else:
            os.startfile(p)
        print('  已尝试打开：%s' % p)
    except Exception as e:
        print('  启动失败：%s；工具名是「%s」' % (e, g['tool']))


def show_novice_guide(path, eng, kind):
    """One-route-at-a-time beginner guidance, inspired by the reverse wizard."""
    if not RT:
        print('  路线库未加载。')
        return
    try:
        feats = route_features(path, kind, eng)
        ranked = _rank_routes(feats)
    except Exception as e:
        print('  路线排序失败：%s' % e)
        return
    if not ranked:
        print('  没有可推荐的路线，先输入「路线 全部」查看路线库。')
        return

    flags = list(eng.FLAGS.keys())
    idx = 0
    while True:
        d = ranked[min(idx, len(ranked) - 1)][2]
        print()
        print('  ' + '═' * 62)
        print('  ◆ 新手向导  [%d/%d]' % (min(idx + 1, len(ranked)), len(ranked)))
        print('  ' + '═' * 62)
        if flags:
            print('  可能答案：')
            for f in flags[:3]:
                print('    %s   ← %s' % (f, ', '.join(sorted(eng.FLAGS.get(f, [])))[:120]))
        else:
            print('  暂时没有直接答案，按下面这一条继续。')
        print()
        print('  当前只做这一步：%s' % d.get('name', ''))
        print('  为什么：%s' % d.get('when', ''))
        _print_route_guidance(d)
        print('  最多先做这 4 个动作：')
        for n, step in enumerate((d.get('steps') or [])[:4], 1):
            print('    %d. %s' % (n, step))
        report = getattr(S, 'diag_path', None)
        if report:
            print('  诊断报告：%s' % report)
        print()
        print('  ---------------- 只记这 5 个入口 ----------------')
        print('   1  打开当前推荐工具/位置')
        print('   2  看当前路线完整说明')
        print('   3  这一步没结果，换下一条路线')
        print('   路线 全部  查看全部路线')
        print('   w  生成题解      0  返回主菜单')
        print()
        try:
            c = input('  guide> ').strip().lower()
        except (EOFError, KeyboardInterrupt):
            return
        if c in ('0', 'q', ''):
            return
        if c == '1':
            _open_guide_tool(d)
        elif c == '2':
            show_route(d.get('id', ''))
        elif c in ('3', 'n', 'next'):
            if idx + 1 < len(ranked):
                idx += 1
                print('  已切换到下一条路线。')
            else:
                print('  已经是最后一条；可以输入「路线 全部」或换文件。')
        elif c in ('路线', 'routes'):
            show_routes(all_routes=True)
        elif c == 'w':
            save_writeup(eng)


# ============================ 产出 ============================
def save_outcome(path, mid_dir, eng):
    """最终产出：flag + 关键文件，收到 outcome/<题目名>/ """
    name = os.path.splitext(os.path.basename(path))[0]
    d = os.path.join(OUT_DIR, name)
    os.makedirs(d, exist_ok=True)
    got = []
    for v in list(eng.FLAGS.keys()):
        if v not in S.flags:
            S.flags[v] = name
        got.append(v)
    # flag 列表
    with open(os.path.join(d, 'flag.txt'), 'w', encoding='utf-8') as f:
        if got:
            for v in got: f.write(v + '\n')
        else:
            f.write('（这道题还没解出 flag —— 见 下一步.md）\n')
    # 关键中间文件复制过来（小文件）
    try:
        cnt = 0
        for root, _, files in os.walk(mid_dir):
            for fn in files:
                p = os.path.join(root, fn)
                if os.path.getsize(p) < 8 * 1024 * 1024 and cnt < 30:
                    shutil.copy2(p, os.path.join(d, fn)); cnt += 1
    except Exception:
        pass
    # 下一步
    with open(os.path.join(d, '下一步.md'), 'w', encoding='utf-8') as f:
        f.write('# 接下来可以尝试的\n\n')
        kind = guess_kind(path, eng)
        for t in NEXT_HINTS.get(kind, NEXT_HINTS['unknown']):
            f.write('- %s\n' % t)
    print('   ★ 最终产出 -> %s' % d)
    return d


def save_writeup(eng):
    """写题解 —— 从全程记录整理出来"""
    ts = time.strftime('%Y%m%d_%H%M%S')
    fn = os.path.join(WU_DIR, '题解_%s.md' % ts)
    with open(fn, 'w', encoding='utf-8') as f:
        f.write('# CTF 题解\n\n')
        f.write('- 时间：%s\n' % S.started)
        f.write('- 模式：%s\n' % ('教学模式' if S.mode == 'learn' else '解题模式'))
        f.write('- 分析过的文件：%s\n\n' % ('、'.join(os.path.basename(x) for x in S.items) or '（无）'))
        if S.diag_path:
            f.write('- 诊断报告：`%s`\n\n' % S.diag_path)
        f.write('## flag\n\n')
        if S.flags:
            for v, src in S.flags.items():
                f.write('- `%s`   ← 来自 %s\n' % (v, src))
        else:
            f.write('（还没解出 flag）\n')
        f.write('\n## 解题过程（工具自动记录）\n\n```\n')
        _rec = list(getattr(eng, 'NOTES', []) or []) + list(S.notes)
        if not _rec:
            _rec = ['（这次没有记录到步骤。下次把文件拖进来跑一遍就有了）']
        f.write('\n'.join(_rec[-500:]))
        f.write('\n```\n\n')
        f.write('## 我的思路（这部分要你自己写 —— 比赛要看的是"你怎么想的"）\n\n')
        f.write('1. 我拿到题目第一眼看到的是：\n2. 我第一个想到的方向：\n3. 为什么先试这个：\n4. 中间走了什么弯路：\n5. 最后怎么解出来的：\n\n')
        f.write('## 用到的工具\n\n')
        f.write('（比如：commander 的哪个功能、CyberChef、Wireshark……）\n')
    print('   ★ 题解 -> %s' % fn)
    return fn


def save_tutorial(eng):
    """写教程 —— 只教学模式有，从解释里提炼 """
    ts = time.strftime('%Y%m%d_%H%M%S')
    fn = os.path.join(WU_DIR, '教程_%s.md' % ts)
    _src = list(getattr(eng, 'NOTES', []) or []) + list(S.notes)
    whys = []
    for _l in _src:
        _t = _l.strip()
        if ('为什么' in _t or _t.startswith('(为什么')) and _t not in whys:
            whys.append(_t)
    with open(fn, 'w', encoding='utf-8') as f:
        f.write('# CTF 教程（做题学到的知识点）\n\n')
        f.write('- 时间：%s\n' % S.started)
        f.write('- 涉及文件：%s\n\n' % ('、'.join(os.path.basename(x) for x in S.items) or '（无）'))
        f.write('## 一、这次用到的知识点\n\n')
        if whys:
            for w in whys: f.write('- %s\n' % w.replace('（为什么:', '').rstrip('）'))
        else:
            f.write('（这次没有记录到解释 —— 下次用教学模式跑一遍）\n')
        f.write('\n## 二、这次实际做了什么（按顺序）\n\n')
        acts = [x.strip() for x in (getattr(eng, 'NOTES', []) or []) if x.strip().startswith('┌─')]
        if acts:
            for a in acts[:25]:
                f.write('- %s\n' % a.replace('┌─', '').strip('- '))
        else:
            f.write('（没记录到动作）\n')
        f.write('\n## 三、这类题的通用打法\n\n')
        kinds = set()
        for p in S.items:
            kinds.add(guess_kind(p, eng))
        for k in kinds:
            f.write('### %s 类\n\n' % {'image':'图片题','archive':'压缩包题','text':'编码/文本题',
                                       'exe':'逆向题','pcap':'流量题','web':'Web 题','unknown':'文件类型不明'}.get(k, k))
            for t in NEXT_HINTS.get(k, NEXT_HINTS['unknown'])[:4]:
                f.write('- %s\n' % t)
            f.write('\n')
        f.write('## 三、下次遇到同类题的顺序\n\n')
        f.write('1. 先判断文件到底是什么（看文件头，别信后缀）\n')
        f.write('2. 把它拖进commander，自动跑一遍\n')
        f.write('3. 没出 flag 就看「接下来可以尝试的点」，一条条试\n')
        f.write('4. 每试一步都记下来 —— 这就是题解\n')
    print('   ★ 教程 -> %s' % fn)
    return fn


# ============================ 大工具 ============================
def launch_tools():
    items = [
        ('1','CyberChef（在线）','URL','https://gchq.github.io/CyberChef/'),
        ('2','Wireshark','EXE',r'C:\Program Files\Wireshark\Wireshark.exe'),
        ('3','DetectItEasy','EXE',r'03-杂项与取证\DetectItEasy\die\die.exe'),
        ('4','ImHex（十六进制）','EXE',r'03-杂项与取证\ImHex\imhex.exe'),
        ('5','StegSolve（图片通道）','JAR',r'03-杂项与取证\StegSolve\stegsolve.jar'),
        ('6','dnSpy（.NET）','EXE',r'05-逆向\dnSpy\dnSpy.exe'),
        ('7','x64dbg（调试）','EXE',r'05-逆向\x64dbg\release\x96dbg.exe'),
        ('8','Ghidra（反编译）','EXE',r'05-逆向\Ghidra\ghidra_12.1.4_PUBLIC\ghidraRun.bat'),
        ('9','jadx（安卓）','EXE',r'05-逆向\jadx\jadx-gui-1.5.6.exe'),
        ('10','Audacity（音频）','EXE',r'C:\Program Files\Audacity 4\bin\Audacity4.exe'),
        ('11','打开中间文件目录','DIR',MID_BASE),
        ('12','打开产出目录','DIR',OUT_DIR),
    ]
    import subprocess
    while True:
        print()
        for k,n,kind,p in items: print('   %2s. %s' % (k,n))
        print('    0. 返回')
        try: sel = input('  编号: ').strip()
        except EOFError: return
        if sel in ('0',''): return
        it = next((x for x in items if x[0]==sel), None)
        if not it: print('  没这个编号'); continue
        _,n,kind,p = it
        try:
            if kind=='URL':
                import webbrowser; webbrowser.open(p); print('  已打开')
            elif kind=='DIR':
                if os.path.isdir(p): os.startfile(p); print('  已打开目录')
                else: print('  目录不存在: %s' % p)
            elif kind=='JAR':
                j=os.path.join(KIT,r'01-通用工具\Java21\bin\java.exe'); q=os.path.join(KIT,p)
                if os.path.isfile(j) and os.path.isfile(q): subprocess.Popen([j,'-jar',q]); print('  已启动 %s' % n)
                else: print('  缺 Java 或文件')
            else:
                q = p if os.path.isabs(p) else os.path.join(KIT,p)
                if os.path.isfile(q): subprocess.Popen([q], cwd=os.path.dirname(q)); print('  已启动 %s' % n)
                else: print('  找不到: %s' % q)
        except Exception as e: print('  启动失败: %s' % e)


# ============================ 小工具直调 ============================
def tool_map():
    """commander tools 目录下的所有小工具：名字 -> 路径"""
    d = {}
    try:
        for fn in os.listdir(TOOLS):
            if fn.endswith('.py') and not fn.startswith('_'):
                d[fn[:-3].lower()] = os.path.join(TOOLS, fn)
    except Exception:
        pass
    # 根目录下还有几个工具（放在这里，engine 直接 import 用）
    for _x in ('hunt', 'poly', 'ocr'):
        _fp = os.path.join(HERE, _x + '.py')
        if os.path.isfile(_fp):
            d[_x] = _fp
    return d


def run_tool(name, rest):
    """在commander里直接跑一个小工具：imgdeep 图.png / decode 密文.txt / rsa（交互）"""
    import subprocess
    m = tool_map()
    p = m.get((name or '').lower())
    if not p:
        return False
    args = [PY312, p]
    if (rest or '').strip():
        args.append(rest.strip().strip('"'))
    print()
    print('  > 跑工具：%s %s' % (os.path.basename(p), (rest or '').strip()))
    print('  ' + '-' * 56)
    try:
        subprocess.call(args, cwd=TOOLS)
    except Exception as e:
        print('  跑不动：%s' % e)
        print('  （手动跑：%s "%s" %s）' % (PY312, p, (rest or '').strip()))
    print('  ' + '-' * 56)
    return True


# ============================ 主流程 ============================
def analyze_one(path):
    if not os.path.isfile(path):
        print('  找不到文件: %s' % path); return
    name = os.path.splitext(os.path.basename(path))[0]
    mid = os.path.join(MID_BASE, name)
    S.items.append(path)
    print()
    print('  ' + '━' * 58)
    print('   开始分析：%s   (%d 字节)' % (os.path.basename(path), os.path.getsize(path)))
    print('   中间文件 -> %s' % mid)
    print('   模式：%s' % ('教学模式（会解释为什么）' if S.mode=='learn' else '解题模式'))
    print('  ' + '━' * 58)
    eng = run_engine(path, mid)
    kind = guess_kind(path, eng)
    # 收集 flag
    new = []
    for v in list(eng.FLAGS.keys()):
        if v not in S.flags:
            S.flags[v] = name; new.append(v)
    if new:
        HI = ('flag','ctf','fleg','c404','nss','buu','hgame','ctfshow','dasctf')
        hi = [v for v in new if v.split('{')[0].lower() in HI]
        lo = [v for v in new if v not in hi]
        print()
        def _src(v):
            try:
                ss = sorted(eng.FLAGS.get(v, []))
                return ('   ← ' + ', '.join(ss)[:110]) if ss else ''
            except Exception:
                return ''
        if hi:
            print('  ★★★ 高可信 flag（前缀是常见的 flag 格式）：')
            for v in hi: print('     %s%s' % (v, _src(v)))
        if lo:
            print()
            print('  ？ 形状像 flag 但不确定（也可能是文件里的巧合串）：')
            for v in lo[:8]: print('     %s%s' % (v, _src(v)))
            print('     （判断：看它像不像有人特意写进去的）')
    else:
        print()
        print('  （这次没直接扫出 flag —— 正常，往下看「接下来可以尝试的点」）')
    _parts = getattr(eng, 'PARTIALS', None)
    if _parts:
        print()
        print('  ⚠ 疑似 flag 的「一部分」（不完整，没有右花括号）：')
        for _v in list(_parts.keys())[:8]:
            print('     %s' % _v)
        print('     （题目常把 flag 拆成几段分开藏：这一段 + 别的段拼起来才是完整 flag）')
        print('     （把别的段找出来后，手动拼一下，或者把新文件再拖进来）')
    show_next_steps(path, eng, kind)
    diag_path = None
    try:
        if getattr(eng, 'DIAG', None):
            diag_path = eng.DIAG.write(eng.FLAGS or eng.FLAGS, NEXT_HINTS.get(kind, NEXT_HINTS['unknown']))
            S.diag_path = str(diag_path)
            print('   ★ 诊断报告 -> %s' % diag_path)
    except Exception as _de:
        print('  （诊断报告写入失败：%s）' % _de)
    save_outcome(path, mid, eng)
    try:
        S.last_ctx = {'path': path, 'kind': kind,
                      'features': sorted(route_features(path, kind, eng))}
        S.save()
    except Exception:
        pass
    if not new:
        try:
            show_routes()
        except Exception as _e:
            print('  （路线导航出错：%s）' % _e)
    S.save()          # 每分析完一个就存一次，防意外关窗口
    print()
    print('   ── 下一步 ──')
    print('   · 继续：把下一个文件（或你自己处理过的文件）拖进来')
    print('   · 输入 w  生成题解%s' % ('（教学模式还会生成教程）' if S.mode=='learn' else ''))
    print('   · 新手一站式：输入 向导（工具名、工具在哪、说明里搜什么、下一步都给）')
    print('   · 只看当前工具：输入 工具说明  · 想看全部步骤：输编号（例 12）  · ? 帮助  · q 退出')


def main():
    banner()
    # 命令行参数：mode + 文件
    args = sys.argv[1:]
    if '--learn' in args or '-l' in args:
        S.mode = 'learn'; args = [a for a in args if a not in ('--learn','-l')]
    elif '--solve' in args or '-s' in args:
        S.mode = 'solve'; args = [a for a in args if a not in ('--solve','-s')]
    else:
        S.mode = pick_mode()

    # ---- 读上次的进度，接上上下文 ----
    if S.load():
        print()
        print('  ' + '─' * 58)
        print('  ◆ 上次的进度（已自动接上）')
        if S.flags:
            print('    已经解出的 flag：')
            for v in list(S.flags.keys())[:6]:
                print('       %s' % v)
        if S.items:
            print('    处理过的文件：')
            for v in S.items[-6:]:
                print('       %s' % os.path.basename(v))
        if S.tried:
            print('    你已经试过（不再重复提示）的方向：%d 条' % len(S.tried))
        print('  ' + '─' * 58)
        print('  （想清空重来：输入 reset）')
    print()
    print('  模式：%s' % ('教学模式' if S.mode=='learn' else '解题模式'))
    print('  把题目文件拖进这个窗口，回车就开始（也可以直接拖到 commander.cmd 图标上）')
    print()

    for a in args:
        if os.path.isfile(a):
            analyze_one(a)

    while True:
        try:
            s = input('  commander> ').strip().strip('"')
        except (EOFError, KeyboardInterrupt):
            print(); break
        if not s:
            continue
        if s.lower() in ('q','quit','exit','0'):
            break
        if s.lower() == 'w':
            save_writeup(engine())
            if S.mode == 'learn': save_tutorial(engine())
            print('   （题解在 writeups 目录里，记得补上"我的思路"那部分）')
            continue
        _q = s.strip().lstrip('#').strip()
        if CS and (s.strip().startswith('#') or _q.isdigit()):
            _e = CS.find(_q)
            if _e:
                print(); print(CS.render(_e)); continue
            elif s.strip().startswith('#'):
                print('  没有 #%s 这个编号。输「表」看全部。' % _q); continue
        if s.lower() in ('表','list','ls','目录','速查'):
            print(); print('  ◆ 速查库（输编号看详细步骤）')
            print(CS.all_titles() if CS else '  （速查库没加载）'); continue
        if s.lower() in ('tools','t','工具'):
            launch_tools(); continue
        # 标记"这条建议我试过了"
        m2 = re.match(r'^(?:试过|试了|tried)\s*#?([Rr]?\d+)$', s)
        if m2:
            _tok = m2.group(1)
            if _tok.lower().startswith('r'):
                i = int(_tok[1:])
                if 1 <= i <= len(S.last_ranked):
                    _rid = S.last_ranked[i - 1]
                    if _rid not in S.tried:
                        S.tried.append(_rid); S.save()
                    print('  记下了：%s 已尝试。下次路线排序会把它排到后面。' % _rid)
                else:
                    print('  没有 R%s（当前路线共 %d 条）' % (i, len(S.last_ranked)))
                continue
            i = int(_tok)
            if 1 <= i <= len(S.suggestions):
                t = S.suggestions[i-1]
                if t not in S.tried:
                    S.tried.append(t); S.save()
                    print('  记下了：第 %d 条已尝试。下次不会再重复列。' % i)
                    print('     （如果试出了东西或拿到新文件，直接拖进来接着分析）')
            else:
                print('  编号超出范围（这轮一共 %d 条建议）' % len(S.suggestions))
            continue
        if s.lower() in ('history','h','进度','历史'):
            print()
            print('  ◆ 本次会话进度')
            print('    处理过的文件: %d 个' % len(S.items))
            for v in S.items[-10:]: print('       %s' % v)
            print('    解出的 flag: %d 个' % len(S.flags))
            for k, v in list(S.flags.items())[:10]: print('       %s   (来自 %s)' % (k, v))
            print('    试过的方向: %d 条' % len(S.tried))
            for v in S.tried[-8:]: print('       %s' % v[:60])
            continue
        if s.lower() in ('向导', 'guide', '新手向导', 'g'):
            if not S.items:
                print('  先拖入一个题目文件，再输入向导。')
            else:
                _p = S.items[-1]
                _e = engine()
                show_novice_guide(_p, _e, guess_kind(_p, _e))
            continue
        if s.lower() in ('工具说明', '当前工具', 'toolhelp'):
            if not S.last_ctx or not RT:
                print('  先拖入一个题目文件并完成分析。')
            else:
                _ranked = _rank_routes(set(S.last_ctx.get('features') or []))
                if _ranked:
                    _print_route_guidance(_ranked[0][2])
                    print('  接着输入「向导」，一次只做一条路线。')
                else:
                    print('  当前没有可推荐路线。')
            continue
        if s.lower() in ('诊断','诊断报告','diag'):
            if not getattr(S, 'diag_path', None):
                print('  还没有诊断报告。先分析一个文件。')
            else:
                print('  诊断报告：%s' % S.diag_path)
                try:
                    print(open(S.diag_path, encoding='utf-8').read()[-5000:])
                except Exception as e:
                    print('  读取失败：%s' % e)
            continue
        if s.lower() in ('flags','flag','旗子'):
            if S.flags:
                print()
                print('  ◆ 目前累积的 flag：')
                for k, v in S.flags.items(): print('     %s   (来自 %s)' % (k, v))
            else:
                print('  还没有解出 flag。')
            continue
        if s.lower() in ('reset','清空'):
            S.items = []; S.flags = {}; S.tried = []; S.suggestions = []; S.diag_path = None
            S.save()
            print('  已清空本次会话记录。')
            continue
        # ---- 直接在commander里跑一个小工具：imgdeep 图.png ----
        _m3 = re.match(r'^([A-Za-z][A-Za-z0-9_]*)\s+(\S.*)$', s)
        if _m3 and _m3.group(1).lower() in tool_map():
            if run_tool(_m3.group(1), _m3.group(2)):
                continue
        if s.lower() in tool_map():
            if run_tool(s, ''):
                continue
        # ---- 两张图做差：diff 图1 图2 ----
        _md = re.match(r'^(?:diff|做差|对比)\s+(.+?)\s+(.+)$', s, re.I)
        if _md:
            _f1 = _md.group(1).strip().strip('"')
            _f2 = _md.group(2).strip().strip('"')
            if os.path.isfile(_f1) and os.path.isfile(_f2):
                _eng = engine()
                _mid = os.path.join(MID_BASE, 'diff')
                os.makedirs(_mid, exist_ok=True)
                _eng.OUTDIR = _mid
                try:
                    _outs = _eng.image_diff(_f1, _f2)
                    for _p in _outs:
                        print('     -> %s' % _p)
                    if _eng.FLAGS:
                        print('  ★ 找到 flag：')
                        for _v in _eng.FLAGS: print('     %s' % _v)
                except Exception as _e:
                    print('  做差失败: %s' % _e)
            else:
                print('  用法: diff 图1 图2（两个文件都要存在）')
            continue
        # ---- Web 题：直接输 URL ----
        if re.match(r'^https?://', s):
            try:
                import subprocess
                print()
                print('  ▶ Web 一键体检：%s' % s)
                subprocess.call([PY312, os.path.join(TOOLS, 'webaudit.py'), s])
                S.last_ctx = {'path': s, 'kind': 'web',
                              'features': ['web', 'param', 'cookie', 'jwt', 'login']}
                S.save()
                show_routes()
            except Exception as _e:
                print('  Web 检查失败: %s' % _e)
            continue
        # ---- 路线导航 ----
        if s.lower() in ('路线', 'routes', 'route', 'r'):
            show_routes()
            continue
        if s.lower() in ('路线 全部', 'routes all', '全部路线'):
            show_routes(all_routes=True)
            continue
        _mr = re.match(r'^(?:跑|run)\s*[Rr]?(\d{1,2})$', s, re.I)
        if _mr:
            run_route(_mr.group(1))
            continue
        if re.fullmatch(r'[Rr]\d{1,2}', s.strip()):
            show_route(s.strip())
            continue
        if re.fullmatch(r'[A-Za-z]{2,4}-[A-Za-z0-9]{2,6}', s.strip()):
            show_route(s.strip())
            continue
        if s.lower() in ('小工具', 'mtools', 'tool', 'mt'):
            _ms = sorted(tool_map().keys())
            print()
            print('  * 可以直接在这里跑的小工具（输「名字 文件」）：')
            for _i in range(0, len(_ms), 4):
                print('     ' + '  '.join('%-12s' % x for x in _ms[_i:_i + 4]))
            print('    例：imgdeep 图.png    decode 密文.txt    rsa（不带参数=交互模式）')
            print('    （它们就是速查表里说的 tools 目录下的工具）')
            continue
        if s.lower() in ('?', 'help', '帮助'):
            print()
            print('  * 能用的话：')
            print('    拖文件进来          = 自动分析（先说结论，再给「接下来可以尝试的点」）')
            print('    #编号 或 直接输编号 = 看这条速查的 工具/位置/步骤/原理（例：12）')
            print('    表                  = 列出全部速查编号')
            print('    工具名 文件         = 直接跑某个小工具（例：imgdeep 图.png）')
            print('    小工具              = 列出所有小工具名字')
            print('    tools               = 打开大工具（StegSolve / Ghidra / Wireshark…）')
            print('    w                   = 生成题解（教学模式还会生成教程）')
            print('    试过 N              = 记下「第 N 条建议我试过了」（下次不再重复列）')
            print('    向导                = 一条一条带做：工具/位置/工具说明搜索词/教程章节/下一步')
            print('    工具说明            = 只显示当前路线用什么工具、在工具里搜什么')
            print('    诊断                = 查看最近一次诊断报告（证据/产物/手工接手点）')
            print('    history / flags     = 看进度 / 看已解出的 flag')
            print('    reset               = 清空本次会话')
            print('    q                   = 退出')
            continue
        if os.path.isfile(s):
            analyze_one(s); continue
        if os.path.isdir(s):
            print('  这是目录。如果里面是 .git，试试 tools\\gitdeep.py')
            continue
        print('  不认识了。可以：拖文件进来 / w=写题解 / tools=开大工具 / q=退出')

    print()
    if S.flags and not os.path.exists(WU_DIR):
        pass
    if S.flags or S.items:
        try:
            y = input('  要生成题解吗？(y/n，回车=y): ').strip().lower()
        except (EOFError, KeyboardInterrupt):
            y = 'n'
        if y in ('', 'y', 'yes'):
            save_writeup(engine())
            if S.mode == 'learn': save_tutorial(engine())
    S.save()
    print()
    print('  已退出（进度已存，下次打开会自动接上）。')
    print('  题解/教程在 %s' % WU_DIR)
    print('  最终产出在 %s' % OUT_DIR)


if __name__ == '__main__':
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print('\n  （中断）')
    except Exception as e:
        print('\n  [!] 出错了: %s' % e)
        print('  （把这段截图发我就能修）')
