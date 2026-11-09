# -*- coding: utf-8 -*-
"""速查库 —— commander的知识库

每个条目有编号。commander给建议时会带上编号，你输编号就能看到：
  · 用什么工具
  · 工具在哪
  · 怎么做（分步骤）
  · （为什么这么做 / 背后的逻辑）

这是"commander的外脑" —— 装了它，commander就能像老手一样告诉你去点哪里。
"""

import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.abspath(os.environ.get('COMMANDER_TOOLKIT_DIR') or os.path.join(HERE, 'toolkit'))
PY312 = sys.executable
JAVA = shutil.which('java') or 'java'

ENTRIES = [
# ================= 通用起手式 =================
dict(no='01', cat='通用', title='不认识这个文件是什么',
 tool='DetectItEasy', where=r'03-杂项与取证\DetectItEasy\die\die.exe',
 when='拿到任何一个题目文件的第一步',
 steps=['打开 die.exe（双击就行，免安装）','把文件拖进窗口','看三样东西：文件类型 / 编译器 / 有没有加壳'],
 why='后缀名是"贴的标签"，谁都能改；文件头是内容的特征，改不了。CTF 最爱用"改后缀"骗你，所以第一步永远看真身'),

dict(no='02', cat='通用', title='把文件拖进commander自动分析',
 tool='commander', where=r'commander\commander.cmd',
 when='任何题目，先花 10 秒让它跑一遍',
 steps=['双击桌面「commander」图标','选模式（1 教学 / 2 解题）','把题目文件拖进黑窗口，按回车','等它跑完，看最后的「接下来可以尝试的点」'],
 why='它把所有能自动做的都做一遍（认类型/解编码/解压缩/看图/找内嵌…），出不来 fa 也没关系，会给下一步方向'),

dict(no='03', cat='通用', title='看文件头判断真实类型',
 tool='ImHex', where=r'03-杂项与取证\ImHex\imhex.exe',
 when='DIE 不在手边时，或想亲手看字节',
 steps=['用 ImHex 打开文件','只看开头几个字节','对照片文件头表（50 4B=zip / 89 50 4E 47=png / FF D8 FF=jpg / 4D 5A=exe / 7F 45 4C 46=linux程序）'],
 why='文件开头几个字节是格式规范规定的，改后缀也改不了它 —— 这是最靠得住的判断依据'),

# ================= Misc 杂项 =================
dict(no='11', cat='Misc', title='一张图片，看不出线索',
 tool='多工具试一遍', where=r'commander\tools\stego.py',
 when='图片题没思路时，按这个顺序挨个试',
 steps=['① 看元数据：把图拖到「看图片信息.cmd」（或 tools\\stego.py 里的元数据部分）',
        '② 看结构：tools\\imgdeep.py —— 查宽高被改、尾部附加',
        '③ 位平面：tools\\stego.py —— 导出 8 张位平面图，打开看有没有图案',
        '④ 改后缀：把 .png 改成 .zip 用 7-Zip 打开',
        '⑤ 尾部：tools\\carve.py —— 把尾巴上接的东西切出来',
        '⑥ 通道：StegSolve（03-杂项与取证\\StegSolve）肉眼翻 R/G/B 和位平面'],
 why='这六步覆盖了初级赛 90% 的图片题。顺序是从"最省事"到"最费劲"，别一上来就上复杂工具'),

dict(no='12', cat='Misc', title='PNG 图片底部/右侧像被裁掉了',
 tool='tools\\imgdeep.py', where=r'commander\tools\imgdeep.py',
 when='图片内容看着不完整、或者尺寸比例很奇怪',
 steps=['python tools\\imgdeep.py 图片.png','它会算出"真实高度"并自动修复另存','打开修复后的图看底部'],
 why='PNG 的宽高写在文件里，出题人改小它，底部内容就被裁掉了。但 PNG 有 CRC 校验值，一算就对不上 —— 所以能反推出真实宽高'),

dict(no='13', cat='Misc', title='图片尾部好像接了别的文件',
 tool='tools\\carve.py', where=r'commander\tools\\carve.py',
 when='ImHex 拉到最后看到异常数据，或者 imgdeep 报告"尾部还有 N 字节"',
 steps=['python tools\\carve.py 文件','它会按文件头特征把里面嵌的东西切出来','切出来的文件再挨个分析（可以直接拖回commander）'],
 why='一个文件里可以塞多个文件（叫"复合文件"）。工具靠"文件头特征"定位每一段，再按格式算出真实结束位置切开'),

dict(no='14', cat='Misc', title='压缩包打不开 / 要密码 / 里面像藏了东西',
 tool='tools\\archive.py', where=r'commander\tools\archive.py',
 when='拿到 zip/rar/7z，解压不顺',
 steps=['python tools\\archive.py 压缩包.zip','先看它的"结构检查"结果','要密码 → 选 2 用字典爆破；提示"伪加密" → 选 1 生成修复版','修复版用 7-Zip 打开'],
 why='三种情况：① 伪加密（标了"加密"但其实没密码，改个标志位就好）② 弱口令（用字典爆）③ 尾部藏东西（用 carve.py）'),

dict(no='15', cat='Misc', title='一串 0 和 1（几万个）',
 tool='tools\\bits.py', where=r'commander\tools\bits.py',
 when='文件内容几乎全是 0/1',
 steps=['python tools\\bits.py 文件','它会自动算平方根拼成正方形','生成"正常"和"反色"两张图，并自动扫二维码','打开图片看'],
 why='每个 0/1 是一个像素点，总数是完全平方数才能拼成正方形。黑白像素画最常见的结果就是二维码；出题人常做反色，所以两种都生成'),

dict(no='16', cat='Misc', title='二维码扫不出来',
 tool='tools\\qr.py', where=r'commander\tools\qr.py',
 when='明显是二维码但手机/工具扫不出',
 steps=['python tools\\qr.py 图片','它会自动试 原图/反色/放大3倍/反色+放大 四种','还不行就手动：先反色（tools\\imtool.py -neg），再扫'],
 why='二维码规定"浅色=0、深色=1"，出题人常做反色；另外二维码四周必须有白色留白区（静默区），很多题目给的图没有，工具会自动补上'),

dict(no='17', cat='Misc', title='一长串表情符号（emoji）',
 tool='tools\\emoji.py', where=r'commander\tools\emoji.py',
 when='文件内容全是 emoji',
 steps=['python tools\\emoji.py 文件','它会试 8 种常见 emoji 编码方案','如果都没出，看它报的"种类数"'],
 why='emoji 也是一种编码：出题人把一串 emoji 当"数字"，按 base64/base32 那样拼。种类数是 16/26/32/64 就说明是换表编码'),

dict(no='18', cat='Misc', title='音频文件',
 tool='tools\\audio.py', where=r'commander\tools\audio.py',
 when='题目给的是 wav/mp3',
 steps=['python tools\\audio.py 音频文件','它会自动生成波形图 + 频谱图 + 高频区图','打开 2_频谱图.png 看有没有字母/图案','也可用 Audacity 打开，切"频谱图"视图'],
 why='音频能藏东西的地方：① 频谱（把文字"画"在高频区）② 波形（异常的哔声）③ 音频本身（摩斯/拨号音/慢放才听得懂）。第一类最常见'),

# ================= Crypto 密码 =================
dict(no='21', cat='Crypto', title='一串乱码/可疑字符',
 tool='tools\\decode.py', where=r'commander\tools\decode.py',
 when='看到不像明文的内容',
 steps=['python tools\\decode.py 文件（或直接粘贴内容）','它按"先标准后变种"试：base64/85/58/hex/摩斯/URL/ROT13 → 凯撒/换表 → 异或','出结果会直接标 ★'],
 why='标准编码能被程序判断出来，凯撒和换表属于"猜"，一上来就猜容易把正确答案顶掉，所以放后面'),

dict(no='22', cat='Crypto', title='字母被替换过（古典密码）',
 tool='tools\\classic.py', where=r'commander\tools\classic.py',
 when='内容是字母，但读不通',
 steps=['python tools\\classic.py 密文','它会试：凯撒26种 / 维吉尼亚 / 栅栏 / 培根 / Atbash / 仿射 / 摩斯','按"像不像正常英文"排序，第一个通常就是'],
 why='古典密码靠"规律"而不是密钥强度，所以暴力试是可行的。真 flag 的字母分布接近自然英语，工具靠这个排序'),

dict(no='23', cat='Crypto', title='手放在键盘上打歪了',
 tool='tools\\keyboard.py', where=r'commander\tools\keyboard.py',
 when='内容是 g;sh{...} 这种（比正常 flag 偏右一格）',
 steps=['python tools\\keyboard.py 密文','它试 8 种移动方向 + 左右镜像','看哪一行像正常 flag'],
 why='键盘密码不看字母表，看键盘位置。最常见是"整体往左/右挪一格"，其次是上下串行、左右镜像'),

dict(no='24', cat='Crypto', title='一堆大数字（RSA）',
 tool='tools\\rsa.py', where=r'commander\tools\rsa.py',
 when='题目给了 n / e / c / p / q 这些',
 steps=['python tools\\rsa.py','按你手上有什么选场景：有 p q 选 1；只有 n e c 选 2（自动分解）；e 很小选 3；同 n 两组 e 选 4','一个个把数字输进去'],
 why='RSA 的核心就一句：想办法把 n 拆成 p 和 q。拆出来就能算私钥 d，明文 m = c^d mod n。工具会试小因子、Fermat、sympy 三种分解法'),

dict(no='25', cat='Crypto', title='哈希值',
 tool='tools\\hash.py', where=r'commander\tools\hash.py',
 when='看到 32/40/64 位十六进制串',
 steps=['python tools\\hash.py 哈希值','先按长度判断类型（32=MD5 / 40=SHA1 / 64=SHA256）','自动试常见弱口令 + 查字典'],
 why='哈希是单向的（不能反推），只能"猜原文"—— 把你猜的东西也做一次哈希，对上了就是它。所以字典质量决定成败'),

dict(no='26', cat='Crypto', title='一段密文，试不出编码',
 tool='tools\\xor.py', where=r'commander\tools\xor.py',
 when='所有编码都试过都不对',
 steps=['python tools\\xor.py 密文（hex 或直接贴）','它先试 256 种单字节密钥','再试"重复密钥"（用"明文一定以 flag{ 开头"反推密钥）'],
 why='异或是最简单的加密（同一个数异或两次会还原）。密钥不超过 5 字节时基本都能猜对；更长的密钥有歧义，需要题目给线索'),

dict(no='27', cat='Crypto', title='多层嵌套（解一层还有一层）',
 tool='hunt.py', where=r'commander\hunt.py',
 when='解出来还是编码，层层套娃',
 steps=['在commander里直接输：hunt 密文   （等价于 python commander\\hunt.py 密文）','它会把所有变换层层组合（最多6层）自动铺开试','出 flag 会告诉你"解题路径"（比如 b64 → hex → 摩斯）'],
 why='编码题的本质是"有限种变换的组合"，工具能做全路线穷举。返回的"路径"就是你写题解时要写的东西'),

# ================= Web =================
dict(no='31', cat='Web', title='Web 题起手式',
 tool='tools\\web.py', where=r'commander\tools\web.py',
 when='题目给了一个网址',
 steps=['python tools\\web.py http://靶机:端口','它会扫 22 个"不该公开"的路径（.git / www.zip / .env / robots.txt…）','有 200 的马上打开看'],
 why='Web 题第一步永远是信息收集。源码备份、版本库、配置文件一旦能下载，题基本就通了 —— 这叫"源码泄露"'),

dict(no='32', cat='Web', title='浏览器 F12 该看什么',
 tool='浏览器开发者工具', where='按 F12',
 when='任何 Web 题',
 steps=['Network 标签：点几个功能，看每个请求发了什么参数','Application/Storage：看 Cookie、LocalStorage 有没有奇怪的值','Sources：翻 JS，找硬编码的 key、接口地址','Console：可以直接执行 JS 试东西'],
 why='前端代码是全公开的 —— 出题人有时把线索直接写在 JS 或 Cookie 里，等于白送'),

dict(no='33', cat='Web', title='扫目录找隐藏文件',
 tool='dirsearch / ffuf', where=r'04-Web\dirsearch  和  04-Web\ffuf',
 when='想找 /admin、/flag.php 这类没链接的页面',
 steps=['python 04-Web\\dirsearch\\dirsearch.py -u http://靶机/ -w 07-字典\\web-dir-small.txt','或 04-Web\\ffuf\\ffuf.exe -u http://靶机/FUZZ -w 07-字典\\web-common.txt','先用小字典，别一上来上百万行'],
 why='服务器上可能放着没做链接的页面/文件。靠字典一个个去"敲"这些路径，看哪些返回 200'),

dict(no='34', cat='Web', title='疑似 SQL 注入',
 tool='sqlmap', where=r'04-Web\sqlmap\sqlmap.py',
 when='网址带参数（?id=1 这种），或者手工试单引号报错',
 steps=['python 04-Web\\sqlmap\\sqlmap.py -u "http://靶机/?id=1" --batch --dbs','看数据库列表 → --tables → --columns → --dump'],
 why='注入的本质是"用户输入被拼进了 SQL 语句"。sqlmap 自动试各种 payload 判断并把数据拖出来'),

# ================= Reverse 逆向 =================
dict(no='41', cat='Reverse', title='程序是什么语言写的 / 有没有加壳',
 tool='DetectItEasy', where=r'03-杂项与取证\DetectItEasy\die\die.exe',
 when='拿到 exe/ELF 的第一步',
 steps=['打开 die.exe','把程序拖进去','看"编译器"（C/C++ / .NET / Go / Rust）和"加壳"（UPX 等）'],
 why='不同语言写的程序，逆向难度差很远：.NET 和 Python 打包的约等于"给你看源码"；C/C++ 编译的要费劲得多'),

dict(no='42', cat='Reverse', title='Python 打包的 exe（PyInstaller）',
 tool='tools\\pyreverse.py', where=r'commander\tools\pyreverse.py',
 when='DIE 显示 PyInstaller，或文件里有 "PyInstaller" 字样',
 steps=['python tools\\pyreverse.py 程序.exe','它会自动用 pyinstxtractor 拆包','拆出来的 .pyc 用反编译工具还原成 .py'],
 why='PyInstaller 把 Python 脚本编译成 .pyc 字节码塞进 exe 尾部，拆包就能拿回来。注意：如果打包时加了密（有 unknown_crypt 目录），PYZ 是加密的，常规手段拿不到源码'),

dict(no='43', cat='Reverse', title='.NET / C# 程序',
 tool='dnSpy', where=r'05-逆向\dnSpy\dnSpy.exe',
 when='DIE 显示 .NET',
 steps=['打开 dnSpy.exe','把 exe 拖进去','左侧能看到类和方法树，双击直接看 C# 源码'],
 why='.NET 程序编译成 IL 中间语言，保留了完整的类名/方法名/字符串 —— 等于给你看源码。这是初级赛最送分的逆向题'),

dict(no='44', cat='Reverse', title='Android apk',
 tool='jadx（看源码）+ apktool（解包/回包）+ Java21', where=r'05-逆向\jadx\jadx-gui-1.5.6.exe',
 when='题目给的是 .apk',
 steps=['先用 jadx-gui 打开 apk，直接看 Java 源码（最省事）','想改资源/重新打包用 apktool：java -jar apktool.jar d 题目.apk -o 输出目录','APK 本质是 zip，也可以直接改名成 .zip 解压看 assets/ 和 res/','flag 常被拆成几段：dex 里一段、assets/ 里一段 —— 拼起来才是完整的（commander会把片段都列出来）'],
 why='APK 里就是编译过的 Java（dex 格式）。jadx 把 dex 反编译回 Java，资源和配置都在 zip 结构里'),

dict(no='45', cat='Reverse', title='WebAssembly（.wasm）',
 tool='wabt', where=r'01-通用工具\wabt\wabt-1.0.42\bin',
 when='文件头是 \\0asm（前 4 字节 = 空字符+a+s+m），或题目名带 wasm',
 steps=['wasm2wat 程序.wasm -o 程序.wat   ← 反编译成可读的文本格式','wasm-objdump -x 程序.wasm  ← 看段结构和函数名（在commander里输：wasm 程序.wasm 全自动）','用记事本/VS Code 打开 .wat 找 flag 相关字符串'],
 why='wasm 是浏览器里跑的编译型字节码。wasm2wat 把二进制翻译成文本指令（类似汇编），比直接看二进制好读得多'),

dict(no='46', cat='Reverse', title='Linux 程序（ELF）',
 tool='strings + ImHex + readelf', where=r'commander\tools\strings_tool.py',
 when='文件头是 7F 45 4C 46',
 steps=['python tools\\strings_tool.py 程序   ← 先提字符串，经常直接看到 flag','用 ImHex 看文件头，确认是 ELF 还是加壳','有 UPX 壳 → 先脱壳（输 tools 里有 UPX）','剩下的逻辑用 Ghidra 反编译看'],
 why='ELF 是 Linux 的可执行格式。逆向的第一步永远是提字符串 —— flag、提示语、比较用的密码经常明文躺在里面'),

dict(no='47', cat='Reverse', title='程序加了 UPX 壳',
 tool='UPX', where=r'05-逆向\upx\upx-5.2.1-win64\upx.exe',
 when='DIE 显示 UPX，或 strings 里看到 UPX!',
 steps=['upx.exe -d 目标.exe','脱壳后再用 DIE 看语言，然后正常逆向'],
 why='加壳是为了压缩体积或增加逆向难度。UPX 是最好脱的壳 —— 一条命令就还原成原始程序'),

dict(no='48', cat='Reverse', title='逆向题通用第一步',
 tool='tools\\strings_tool.py', where=r'commander\tools\strings_tool.py',
 when='拿到任何程序，不知道从哪下手',
 steps=['python tools\\strings_tool.py 程序','看它标出"可疑"的那些（含 flag/key/password/wrong 的）','常常直接就有 flag 或线索'],
 why='程序里除了机器码还夹着大量可读文字：报错信息、函数名、常量字符串。逆向第一步永远是"先把字符串全捞出来看一眼"'),

# ================= 流量 / 取证 =================
dict(no='51', cat='流量', title='流量包（pcap）',
 tool='Wireshark + tshark', where=r'C:\Program Files\Wireshark',
 when='题目给的是 .pcap / .pcapng',
 steps=['用 Wireshark 打开（开始菜单搜）','Statistics → Protocol Hierarchy：看有哪些协议','File → Export Objects → HTTP：把所有传输的文件导出来，flag 常在里','右键任意包 → Follow → TCP Stream 看完整对话'],
 why='网络流量里常包含传输的文件。初级题 90% 是 HTTP，"导出对象"这一步就能出答案'),

dict(no='52', cat='流量', title='Wireshark 过滤语法',
 tool='Wireshark 顶部过滤框', where='Wireshark',
 when='包太多看不完',
 steps=['只看 HTTP：输入 http','只看 POST：http.request.method == "POST"','看某条流：tcp.stream eq 3','全局找关键字：frame contains "flag"','看 USB：usb'],
 why='过滤是为了"把没用的包藏起来"。找 flag 时先试 frame contains "flag"，命中率很高'),

dict(no='53', cat='流量', title='.git 源码泄露',
 tool='tools\\gitdeep.py', where=r'commander\tools\gitdeep.py',
 when='扫到 /.git/ 能访问，或题目给了个 .git 压缩包',
 steps=['python tools\\gitdeep.py 目录或压缩包','它会扫：所有提交 / 所有文件对象 / 悬空对象 / reflog','flag 常藏在"已经被删掉"的那次提交里'],
 why='git 会保留完整历史。代码"删了"不代表没了 —— 历史提交、被 reset 掉的提交、reflog 记录里都还能找回来。别人能访问 /.git/ 就能把整个仓库扒下来'),

dict(no='54', cat='取证', title='看数据有多"乱"（熵值）',
 tool='tools\\entropy.py', where=r'commander\tools\entropy.py',
 when='不确定文件是不是被加密/压缩了',
 steps=['python tools\\entropy.py 文件','看整体熵值（接近 8 = 加密或压缩）','看分块熵值，找"突然变乱"的那一段'],
 why='熵 = 混乱程度。普通文本约 4~5，base64 约 5~6，加密/压缩接近 8。分段算熵能定位到"藏东西的那一段"的位置'),

# ================= 通用补充（在线工具 / 比赛流程）=================
dict(no='04', cat='通用', title='常用在线工具 / 学习网站（联网时用）',
 tool='浏览器（决赛可以联网、挂梯子也行）',
 where='',
 when='不想装工具、想快速验一个想法、或看不懂题目想查知识点',
 steps=['CyberChef  https://gchq.github.io/CyberChef/   —— 万能编码转换（"赛博厨师"：左边选菜谱，右边出结果）',
        'CTF Wiki  https://ctf-wiki.org/   —— 各类题目的原理百科（看不懂题目时查这里）',
        'HelloCTF  https://hello-ctf.com/   —— 零基础入门教程',
        '吾爱破解工具  https://down.52pojie.cn/Tools/   —— 工具下载站（逆向工具基本都有）',
        'dCode  https://www.dcode.fr/en   —— 古典密码 / 各种编码的在线破解（凯撒、栅栏、维吉尼亚…）',
        '在线二维码  https://tool.oschina.net/qr   —— 扫不出时换个解码器再试（不同实现结果可能不同）'],
 why='同一件事不同网站实现不一样，一个出不来就换一个 —— 尤其二维码和古典密码。注意：决赛禁用 AI 对话工具，但浏览器查资料、用在线工具是允许的',
 next=['21', '16']),

dict(no='55', cat='通用', title='比赛当天的标准流程（照着走就行）',
 tool='commander + 本速查表', where=r'commander\commander.cmd',
 when='一拿到题目就按这个顺序来',
 steps=['① 先读题目名字 / 描述 / 附件类型（描述里的怪话往往就是提示）',
        '② 每道题的文件单独放好，直接拖进commander跑一遍（10 秒）',
        '③ 看它给的「接下来可以尝试的点」，每条都带 #编号',
        '④ 按编号挨个点开看 步骤 / 工具 / 原理；试过一条就在commander里输「试过 N」',
        '⑤ 试出来的结果或新文件再拖回来 —— 它记得前面的进度，不用从头再来',
        '⑥ 出 flag 先提交，然后输 w 生成题解，把「我的思路」补上（比赛要人工审核这个）',
        '⑦ 全程别删中间文件（在 .commander-work/ 里）—— 写题解和复盘都要用'],
 why='比赛不怕慢，怕乱。每道题都走同一条流水线，就不会卡死在一道题上；而且题解必须自己写，边做边记最省事',
 next=['02', '01', '04']),

dict(no='19', cat='Misc', title='JPEG / JPG 图片疑似藏东西',
 tool='ExifTool（看元数据）+ StegExpose（检测）+ F5（提取）',
 where=r'03-杂项与取证\图片隐写\StegExpose\StegExpose.jar',
 when='拿到 .jpg / .jpeg（PNG 类走 #11 那一套）',
 steps=['① 元数据：把图拖到 ExifTool.exe 上（03-杂项与取证\\ExifTool），看 Comment / Software / XPComment 字段',
        '② 检测：java -jar StegExpose.jar 图.jpg —— 跑完给一个"嫌疑度"分数，>0.5 基本有戏',
        '③ 提取：进 图片隐写\\F5 目录，java Extract 图.jpg（默认密码 abc123；不对再试空密码）',
        '④ 还不行：把 .jpg 改名成 .zip 用 7-Zip 打开；或用 tools\\carve.py 切尾部',
        '⑤ 顺带试"图里还有图"：tools\\carve.py 图.jpg'],
 why='JPEG 是有损压缩（每存一次像素都会变），所以不能像 PNG 那样直接改最低位 —— 得用 F5、JPHide 这类专门扛 JPEG 压缩的算法。检测和提取是两套工具，先检测再提取，别瞎试',
 next=['11', '13', '20']),

dict(no='20', cat='Misc', title='给了两张几乎一样的图（找不同 / 盲水印）',
 tool='imtool.py（做差）+ blind_watermark（盲水印）',
 where=r'03-杂项与取证\\图片隐写\\imtool.py',
 when='题目给了两张图，或"一张原图 + 一张被改过的图"',
 steps=['① 找不同：python 03-杂项与取证\\图片隐写\\imtool.py 图1.png 图2.png -diff',
        '② 结果图里亮的地方就是"被人动过"的像素，放大看通常是文字 / 图案',
        '③ 题目提到"盲水印"：bw-extract 带水印.png 原图.png 输出.png',
        '④ 叠图 / 异或：python imtool.py 图1.png 图2.png -xor',
        '⑤ 产出的图再拖回commander接着分析'],
 why='"两张图做差"能消掉相同背景，只留下差异像素 —— 肉眼找不出来，程序一秒出。盲水印是另一个套路：水印嵌在频域里，必须要原图才能提取',
 next=['11', '19']),

dict(no='28', cat='Crypto', title='内容是一堆奇怪符号（emoji / 星星 / 音符 / 扑克牌…）',
 tool='tools\\emoji.py + tools\\decode.py',
 where=r'commander\tools\emoji.py',
 when='文件里全是重复出现的图形 / 符号字符，看不出明文',
 steps=['① 先数"一共有几种符号"：python tools\\emoji.py 文件（它会直接报种类数）',
        '② 种类数是 16 / 26 / 32 / 64 → 基本就是换表编码（分别对应 hex / 字母 / base32 / base64）',
        '③ 按对照表换成普通字符，再丢给 tools\\decode.py 继续解',
        '④ 常见对照：emoji→数字（第一个=A 第二个=B…）、国旗→国家代码、扑克牌→52 进制、音符→音阶'],
 why='这类题都是"换了马甲的进制 / 编码"。关键不是认符号，而是数种类数 —— 种类数直接告诉你它背后是什么编码，这是通用套路',
 next=['17', '21', '26']),

dict(no='56', cat='流量', title='USB 流量（键盘 / 鼠标）',
 tool='Wireshark（+ 网上现成的 USB HID 脚本）',
 where=r'C:\Program Files\Wireshark\Wireshark.exe',
 when='pcap 里 usb 相关包很多，题目像在"记录操作"',
 steps=['① Wireshark 打开，过滤框输 usb 或 usb.transfer_type == 0x01',
        '② 看 "HID Data" 字段（键盘 / 鼠标的数据就在这里）',
        '③ 键盘：每次按键发 8 字节，第 3 个字节 = 按下的键的编号，按 HID 键值表翻成字符',
        '④ 鼠标：把 x / y 位移当坐标画出来，通常是签名或图形',
        '⑤ 懒得手算：GitHub 搜 "USB HID keyboard pcap"，有现成脚本'],
 why='USB 键盘每敲一下都会发一个包，包里直接带着"按下的是哪个键"的编号。把编号翻回字符就是打字内容 —— 流量题的高频套路',
 next=['51', '52']),

# ================= 新增工具（2026-10-12 官方下载，已通过安全验证）=================
dict(no='61', cat='Web', title='想批量扫网站漏洞（有几千个现成 POC）',
 tool='nuclei', where=r'11-新增工具\nuclei（Web 漏洞扫描）\nnuclei.exe',
 when='Web 题拿到靶机地址后，想快速看看有没有常见漏洞',
 steps=['打开 cmd，进入 11-新增工具 的 nuclei 目录',
        '跑：nuclei.exe -u http://靶机地址',
        '只扫某一类：nuclei.exe -u http://靶机 -tags sqli',
        '第一次跑会下载模板库（要联网），之后本地扫'],
 why='nuclei 靠"模板"工作 —— 社区写了几千个 POC，每个就是一个 yaml，挨个试。比手工点快几百倍'),

dict(no='62', cat='Web', title='想快速看一堆网址活没活 / 是什么',
 tool='httpx', where=r'11-新增工具\httpx（HTTP 探测）\httpx.exe',
 when='扫出来一堆地址，想快速筛出有用的',
 steps=['httpx.exe -u http://靶机 -title -status-code -tech-detect',
        '批量：httpx.exe -l 地址列表.txt -title -status-code'],
 why='扫目录或子域名会得到几百个结果，人工点开太慢。httpx 一次把标题/状态码/技术栈列出来，一眼挑出可疑的'),

dict(no='63', cat='Web', title='想爬网站，把所有接口和参数找出来',
 tool='katana', where=r'11-新增工具\katana（Web 爬虫）\katana.exe',
 when='不知道网站有哪些页面和接口时',
 steps=['katana.exe -u http://靶机',
        '带 JS 渲染：katana.exe -u http://靶机 -jc',
        '存文件：katana.exe -u http://靶机 -o 爬出来的.txt'],
 why='有些接口不在首页链接里，藏在 JS 里。先爬一遍拿到完整 URL 列表，再对着 F12 看，比瞎试快'),

dict(no='64', cat='Web', title='想用国内主流扫描器扫一遍',
 tool='xpoc（奇安信出的，前身 xray）', where=r'11-新增工具\xray-xpoc（Web 扫描）\xpoc.exe',
 when='想要傻瓜式一键扫描',
 steps=['xpoc.exe -t http://靶机',
        '看输出里的告警列表',
        '注意：扫描器只对你自己的靶机用'],
 why='xpoc 是 xray 的新版命令行，规则偏国内常见漏洞（弱口令/未授权/注入），对国内比赛靶机命中率高'),

dict(no='65', cat='Web', title='题目给了 JWT 令牌（一长串 xxx.yyy.zzz）',
 tool='jwt_tool', where=r'11-新增工具\jwt_tool（JWT 攻击）\jwt_tool.py',
 when='登录后拿到一串 eyJ 开头的令牌',
 steps=['python jwt_tool.py 令牌',
        '试 alg=none 绕过：jwt_tool.py 令牌 -X a',
        '爆破弱密钥：jwt_tool.py 令牌 -C -d 07-字典\\pass-top10000.txt'],
 why='JWT 只是 base64 拼的，不是加密。常见考点：算法改成 none、弱密钥爆破、改 payload 不重签名'),

dict(no='66', cat='Reverse', title='想要图形界面逆向（不会用命令行）',
 tool='Cutter', where=r'11-新增工具\Cutter（逆向 GUI）\Cutter-v2.5.0-Windows-x86_64\cutter.exe',
 when='Ghidra 太重、想快速看反汇编',
 steps=['双击 cutter.exe',
        '把程序拖进去',
        '左边是函数列表，中间是反汇编，按 F5 看伪代码',
        '顶部搜索框搜字符串（flag / wrong）'],
 why='Cutter 是 radare2 的图形版，比 Ghidra 轻、启动快，适合快速看一眼程序在干嘛'),

dict(no='67', cat='Reverse', title='想在命令行里分析二进制 / 写脚本自动化',
 tool='radare2', where=r'11-新增工具\radare2（命令行逆向）\r2blob.static.exe',
 when='要批量分析，或想精确控制',
 steps=['r2blob.static.exe -A 目标程序   （-A = 自动分析）',
        '进去后：afl 看所有函数 / iz 看字符串 / pdf @ main 看 main',
        'q 退出'],
 why='命令行能管道、能脚本化。逆向老手基本都用 r2 或它的衍生品'),

dict(no='68', cat='Reverse', title='.NET / C# 程序，想直接看源码',
 tool='ILSpy', where=r'11-新增工具\ILSpy（.NET 反编译）\ILSpy.exe',
 when='DIE 显示 .NET，或 dnSpy 跑不起来时',
 steps=['双击 ILSpy.exe',
        'File - Open 选程序',
        '左侧列出所有类，点开就是源码',
        '变量名方法名都在，跟源码差不多'],
 why='.NET 编译后带着完整元数据（类名/方法名），反编译出来几乎就是源码 —— 逆向最送分的类型'),

dict(no='69', cat='Reverse', title='程序里的字符串全被混淆 / 加密了',
 tool='FLOSS（Mandiant 出品）', where=r'11-新增工具\FLOSS（自动解混淆字符串）\floss.exe',
 when='strings 出来的全是乱码，或只有零星几个字',
 steps=['floss.exe 目标程序',
        '它会自动解 base64、解 XOR、提取栈上字符串',
        '在输出里找 flag / 提示语'],
 why='很多程序故意把字符串加密存放，运行时才解密。FLOSS 模拟执行那些解密函数把明文挖出来 —— 普通 strings 看不到'),

dict(no='70', cat='Reverse', title='安卓 apk，想还原成可读代码',
 tool='apktool', where=r'01-通用工具\apktool\apktool.jar',
 when='题目给的是 .apk',
 steps=['java -jar apktool.jar d 目标.apk',
        '解出来的 smali 在 目标\\smali\\ 下',
        '只想找字符串：直接看 目标\\res\\values\\strings.xml',
        '看 Java 源码：用 jadx（05-逆向\\jadx）'],
 why='apk 本质是 zip。apktool 还原资源和 smali，jadx 直接还原 Java 源码 —— 看代码用 jadx，改包用 apktool'),

dict(no='71', cat='Reverse', title='有内存泄露的地址，想知道是哪个 libc 版本',
 tool='libc-database', where=r'11-新增工具\libc-database（libc 识别）',
 when='pwn 题泄露了函数地址，要在 libc 库里反查',
 steps=['需要 WSL 或 Linux 环境（它是 shell 脚本）',
        './find puts 6f0    （6f0 是地址低 12 位）',
        './get ubuntu 得到对应 libc 文件'],
 why='pwn 题常给一个泄露地址但不说 libc 版本。低 12 位在同一个 libc 里固定，用它反查就能定位版本'),

dict(no='72', cat='Crypto', title='RSA 的大数分解不动',
 tool='yafu', where=r'11-新增工具\yafu（大数分解）\yafu.exe',
 when='RsaCtfTool 也分不出来，但 n 不算特别大（几百位）',
 steps=['yafu.exe "factor(大整数n)"',
        '它用 Pollard rho / SIQS 等算法，比试除快得多',
        '结果会打印 p 和 q'],
 why='分解大整数有专门算法（椭圆曲线法、二次筛法）。yafu 自动挑最合适的算法，比手写 python 快'),

dict(no='73', cat='Crypto', title='加密的 zip，但你知道里面某个文件的内容',
 tool='bkcrack', where=r'11-新增工具\bkcrack-win64（ZIP 明文攻击）\bkcrack-1.8.1-win64\bkcrack.exe',
 when='zip 有密码，但你知道里面某个文件的开头（png 文件头、已知 txt 等）',
 steps=['先看有啥可用明文：bkcrack.exe -C 包.zip -z',
        'bkcrack.exe -C 包.zip -c 已知文件 -p 已知明文.txt   （至少 12 字节）',
        '拿到 key 后改密码：bkcrack.exe -C 包.zip -k k1 k2 k3 -U 解出.zip 新密码'],
 why='ZIP 传统加密（ZipCrypto）很弱：知道 12 字节明文就能反推内部密钥，不需要密码。PNG/JPG 文件头是天然已知明文'),

dict(no='74', cat='取证', title='要从磁盘镜像 / 大文件里挖数据',
 tool='bulk_extractor', where=r'11-新增工具\bulk_extractor（取证 carving）\bulk_extractor64.exe',
 when='给了一个很大的镜像 / 内存转储 / 奇怪的大文件',
 steps=['bulk_extractor64.exe -o 输出目录 目标文件',
        '看 输出目录 下的 email.txt / url.txt 等',
        '文件碎片按类型存在 carved 相关目录'],
 why='它不管文件系统，直接在原始字节里按特征扫描（邮箱/URL/图片头），能挖出被删或藏在缝隙里的数据'),

dict(no='75', cat='流量', title='想在命令行里看流量包（不用开 Wireshark）',
 tool='termshark', where=r'11-新增工具\termshark（终端流量分析）\termshark_2.4.0_windows_x64\termshark.exe',
 when='想快速看 pcap 的包列表，或跟一条流',
 steps=['termshark.exe -r 题目.pcap',
        '进去后按 / 输入过滤串（语法和 Wireshark 一样，比如 http）',
        '回车看包详情，q 退出'],
 why='有些环境不方便开 GUI，或只想快速 grep。termshark 就是终端版 Wireshark，过滤语法完全一样'),

dict(no='05', cat='通用', title='文本题到底该用哪个解码器（插件已自动全试）',
 tool='commander 编码链（自动）', where=r'commander\commander.py',
 when='拿到一串看不懂的字符（Base64/十六进制/摩斯/栅栏/培根/键盘/Atbash/零宽…）',
 steps=['直接把文件拖进 commander，它会把 40 多种编码/古典密码逐层全试一遍',
        '看输出里"编码链N层"的候选和最后的 flag 列表（每个 flag 后面有 ← 来源）',
        '如果有多条，优先选来源是 Base64/Base32/Hex/摩斯/Atbash/Bacon 的（不是凯撒/键盘变形出来的）',
        '想单独试：tools\\decode.py / classic.py / keyboard.py / zerowidth.py'],
 why='编码题本质是有限种变换的组合；插件用 BFS 把每层所有可能都列出来再扫 flag，不会"选错一条路就卡死"',
 next=['21','22','23','26','27','29']),

dict(no='29', cat='Crypto', title='文本隐写：零宽字符 / 空白 / 变体选择符',
 tool='commander（自动）+ tools\\zerowidth.py', where=r'commander\tools\zerowidth.py',
 when='文本看起来正常，但复制粘贴后长度不对 / 怎么都找不到东西',
 steps=['把文件拖进 commander —— 它会自动试：零宽字符(200B/200C/200D)、空格/制表符、Unicode 变体选择符(FE00-FE0F / E0100-E01EF)',
        '看输出里"零宽字符 / 空白字符 / 变体选择符"这几种解码器有没有出结果',
        '也可以单独跑 python tools\\zerowidth.py 文件'],
 why='零宽字符和变体选择符在屏幕上完全不显示，肉眼和普通编辑器都看不出来；把它们映射成 0/1 再拼字节就能还原',
 next=['21','27']),

dict(no='35', cat='Web', title='Web 题一键体检（先跑这一条）',
 tool='tools\\webaudit.py', where=r'commander\tools\webaudit.py',
 when='拿到一个网址（http://靶机:端口/）',
 steps=['在 commander 里直接输：webaudit http://靶机:端口/',
        '它会自动查：首页注释/JS/链接、robots.txt、.git、.env、备份文件、www.zip、phpinfo',
        '还会试：SQL 注入、SSTI({{7*7}})、LFI(../../etc/passwd)、命令注入(;id)、SSRF、路径穿越',
        '再试常见弱口令(admin/admin 等)、Cookie 改成 role=admin、JWT 解码、X-Forwarded-For 伪造',
        '按输出里的"疑似泄露/漏洞点"逐个打开，flag 常常就在里面'],
 why='Web 初级题 90% 是"信息收集 + 一个经典漏洞"；这套检查覆盖了最常见的十几类，先自动扫一遍能省一半时间',
 next=['31','32','33','34','61','65']),

dict(no='49', cat='Misc', title='音频：LSB / 摩尔斯 / 频谱',
 tool='commander（自动）+ Audacity', where=r'01-通用工具\Audacity 或 tools\audio.py',
 when='题目给 wav/mp3，听不出东西',
 steps=['拖进 commander：它会读原始 WAV 采样，自动试 LSB（最低位）和"声音长短→摩尔斯"',
        '同时生成频谱图/波形图/倒放版本到 .commander-work/<题目>\\',
        '打开频谱图看有没有文字/图案（很多题把 flag 画在高频区）',
        '还不行就用 Audacity 打开，切"频谱图"视图，放大看'],
 why='音频能藏东西的地方：采样最低位、频谱图案、声音长短(摩尔斯)、倒放；插件先把能自动的三样跑完，剩下的人眼看频谱',
 next=['18','21']),

dict(no='57', cat='流量', title='流量：USB HID 键盘 / ICMP 外带',
 tool='commander（自动）+ Wireshark', where=r'C:\Program Files\Wireshark\Wireshark.exe',
 when='pcap 里 usb 包很多，或只有 icmp 包',
 steps=['拖进 commander：USB 流量会自动提取 HID Data 并按键值表翻译成字符',
        'ICMP 流量会自动把 data.data 拼成十六进制再还原文字',
        '结果在输出里（"USB HID 键盘解码"/"ICMP"），源文件在 .commander-work/<题目>\\',
        '鼠标流量：用 Wireshark 导出 x/y 坐标，按坐标画图（插件只自动解键盘）'],
 why='USB 键盘每个包第 3 个字节就是"按下的键"的编号；ICMP 每包能带几十字节数据，是常见的隐蔽信道',
 next=['51','52','56']),

dict(no='06', cat='通用', title='一串只有 A/C/G/T 的 DNA 序列',
 tool='commander（自动 DNA-Goldman/2bit/base4）', where=r'commander\engine.py',
 when='文件里是一长串 ACGT（可能还附一张 A/C/G/T × 0/1/2 的表）',
 steps=['直接拖进 commander —— 它会试 DNA-Goldman（相邻碱基查旋转表→三进制，6 位→1 字节）',
        '也会试 DNA-2bit（A=00 C=01 G=10 T=11）和 DNA-base4',
        '看输出里"DNA-Goldman -> ..."那一行'],
 why='Goldman et al. 2013 的 DNA 存储方案：相邻两个碱基查旋转表得到一个三进制位，6 个三进制位正好拼 1 字节',
 next=['21','27']),

dict(no='58', cat='取证', title='PDF 取证：内嵌文件 / 加密',
 tool='commander（自动解流+递归）+ pypdf', where=r'commander\engine.py',
 when='题目给 PDF，正文看起来"没什么东西"',
 steps=['拖进 commander：它会解压所有 FlateDecode 流，遇到内嵌 PDF/ZIP/图片会递归分析',
        '如果 PDF 有 /Encrypt：它会先用小字典试密码（弱口令 + RC4 很常见）',
        '看中间文件目录的 pdf_stream_*.bin / pdf_decrypted.txt',
        '还不行：用 john/hashcat 的 PDF 模式 + rockyou 爆密码，再 pypdf 解密'],
 why='PDF 正文和附件都是压缩流；很多题把"加密的机密报告"作为内嵌文件塞进外层 PDF，密码又是弱口令',
 next=['54','74']),

dict(no='07', cat='通用', title='任意小字母表：emoji / 星星 / 扑克牌 / 自造符号',
 tool='commander 通用符号表分析（自动）', where=r'commander\engine.py',
 when='一整段文本只由少量符号组成（2~64 种），但看不出是什么编码',
 steps=['直接拖进 commander —— 它会统计符号种类数',
        '自动尝试：每符号 k 位（小字母表枚举所有映射）、base-N 大整数、n 个符号拼字节',
        '还会试"完整字母表比观察到的大"（例如 8 种 emoji 只出现 6 种）',
        '看"通用符号表分析"里 ★ 的候选；多个候选时按语义挑最像的'],
 why='这类题本质都是"符号→数值→比特/进制→字节"，不需要认识具体符号；插件枚举映射和分组方式，按可打印率/flag 形状排序',
 next=['06','28','21']),

dict(no='08', cat='通用', title='一遍没解出来：用「路线导航」自己遍历',
 tool='commander 路线导航（R1/R2…）', where=r'commander\commander.py',
 when='分析完没出 flag，或者出了候选但不确定',
 steps=['拖文件分析（Web 题直接输 URL，会跑 webaudit）后，会列出 R1/R2… 路线',
        '每条路线都写了：常见度（★）、命中的线索、什么时候用',
        '输 R1 看详细步骤（自动接上速查表 #编号 + 工具路径 + 命令）',
        '试一条就输「试过 R1」；试完把结果文件再拖回来，进度会接上',
        '想换方向：输「路线 全部」看全部路线；输「跑 R1」看该路线的命令/操作'],
 why='路线是按"文件类型 + 观察到的线索 + 考点常见度"排的通用手法，不是预设题目；你可以按建议顺序遍历，也可以自己跳着试',
 next=['02','07','35']),

]

# 按编号/关键词查
def find(q):
    q = str(q).strip().lstrip('#')
    for e in ENTRIES:
        if e['no'] == q:
            return e
    # 关键词模糊匹配
    hits = [e for e in ENTRIES if q and q in e['title']]
    return hits[0] if hits else None

def tool_abspath(e):
    """把条目里的 where 变成能直接复制的绝对路径"""
    w = (e.get('where') or '').strip()
    if not w:
        return ''
    first = w.split('  ')[0].strip() if '  ' in w else w
    if len(first) > 1 and first[1] == ':':
        return first
    # GUI 指令或软件名不是文件路径，例如“按 F12 / Wireshark”。
    if not ('\\' in first or '/' in first or first.lower().startswith('commander')):
        return first
    parts = first.replace('\\', '/').split('/')
    return os.path.join(HERE, *parts[1:]) if parts[0].lower() == 'commander' else os.path.join(KIT, *parts)


def _filelike(p):
    name = p.replace('/', '\\').rsplit('\\', 1)[-1]
    return '.' in name


def cmd_for(e):
    """自动生成一条能照抄的命令（小白最需要这个）"""
    if e.get('cmd'):
        return e['cmd']
    ap = tool_abspath(e)
    if not ap:
        return ''
    low = ap.lower()
    if low.endswith('.py'):
        return PY312 + ' "' + ap + '" 你的文件'
    if low.endswith('.jar'):
        return JAVA + ' -jar "' + ap + '" 你的文件'
    if low.endswith('.exe'):
        return '"' + ap + '" 你的文件'
    return ''


def _siblings(e, limit=5):
    return [x for x in ENTRIES if x['cat'] == e['cat'] and x['no'] != e['no']][:limit]


def render(e):
    """把一个条目渲染成给人看的文本"""
    bar = '=' * 62
    L = []
    L.append('  ' + bar)
    L.append('  #%s  %s' % (e['no'], e['title']))
    L.append('  ' + bar)
    L.append('  [分类] %s' % e['cat'])
    L.append('  [什么时候用] %s' % e['when'])
    L.append('  [用什么工具] %s' % e['tool'])
    ap = tool_abspath(e)
    if ap:
        L.append('  [工具在哪] %s' % ap)
        if _filelike(ap) and not os.path.exists(ap):
            L.append('              (注意：这个位置现在没找到它 —— 可能没下载，或被清理过)')
    L.append('  [怎么做]')
    sw = e.get('stepwhy') or STEP_WHY.get(e['no']) or []
    for i, s in enumerate(e['steps'], 1):
        L.append('     %d) %s' % (i, s))
        if i - 1 < len(sw) and sw[i - 1]:
            L.append('        (%s)' % sw[i - 1])
    c = cmd_for(e)
    if c:
        L.append('  [照抄这条命令]（把"你的文件"换成真实路径；路径带空格就加引号）')
        L.append('     ' + c)
    L.append('  [为什么 / 逻辑]')
    L.append('     (%s)' % e['why'])
    nxt = []
    for n in (e.get('next') or []):
        t = find(n)
        if t:
            nxt.append(t)
    if not nxt:
        nxt = _siblings(e)
    if nxt:
        L.append('  [接着看] ' + '   '.join('#%s %s' % (t['no'], t['title']) for t in nxt))
        L.append('           （在commander里直接输编号就能看，比如输 %s）' % nxt[0]['no'])
    L.append('  ' + bar)
    return '\n'.join(L)


CAT_ORDER = ['通用', 'Misc', 'Crypto', 'Web', 'Reverse', '流量', '取证']


def all_titles():
    """列出全部条目：按分类分组，组内按编号排序"""
    cats = []
    for e in ENTRIES:
        if e['cat'] not in cats:
            cats.append(e['cat'])
    order = [x for x in CAT_ORDER if x in cats] + [x for x in cats if x not in CAT_ORDER]
    out = []
    for c in order:
        out.append('')
        out.append('-- %s --' % c)
        for e in sorted([x for x in ENTRIES if x['cat'] == c], key=lambda x: x['no']):
            out.append('  #%-4s %s' % (e['no'], e['title']))
    return '\n'.join(out)


# ============================================================
#  每一步「为什么要这么做」—— 渲染时会跟在对应步骤后面
#  （和 steps 一一对应；没有的就不显示）
# ============================================================
STEP_WHY = {
 '01': ['免安装，双击就跑，不用配环境',
        '拖进去它会自己读文件头 —— 这一步不需要你懂什么',
        '这三样决定后面走哪条路：.NET 等于给你看源码、UPX 要先脱壳、C/C++ 才需要动调试器'],
 '02': ['cmd 入口会自动切到 UTF-8，免得中文乱码',
        '教学模式每一步都带解释（对你现在最有用）；解题模式只给结论，快',
        '它会对同一份文件自动做几十种尝试，你什么都不用选',
        '这一步的重点不是结果，而是它告诉你的"下一步方向"'],
 '11': ['先捡最便宜的：EXIF 里偶尔直接写着 flag 或提示',
         '宽高被改 / 尾部塞了东西，是图片题最常见的两种小动作',
         '最低位改动肉眼完全看不出来，但单独画成图就现形',
         '图片格式允许在后面接别的数据；改名成 zip 就能当压缩包打开',
         '一个文件可以同时是好几个文件，靠"文件头特征"能定位每一段的起止',
         '出题人常只在某一个颜色通道里藏东西，工具一次生成多张对比图，你只管挑'],
 '12': ['真实高度是靠文件里的 CRC 校验值反算出来的 —— 改小了高度，校验就对不上',
         '另存新文件，不覆盖原图，免得手滑把证据弄丢',
         '被裁掉的那几行像素，内容就在里面'],
 '13': ['按文件头特征扫描，比肉眼找快得多',
         '每一段都按格式算出真实结束位置，所以是精确切割，不是随便截断',
         '切出来的是独立文件，可以直接再拖回commander接着分析'],
 '14': ['先让它认出这是哪种包（zip / rar / 7z），不同格式的坑不一样',
         '这一步用来分清"伪加密"还是"真要密码"—— 两种情况处理方式完全相反',
         '"要密码"多半是弱口令，先用小字典几秒出结果；"伪加密"其实没密码，只是标志位被写成了已加密',
         '修复版才是真正能正常解开的包，用 7-Zip 打开最稳'],
 '19': ['JPEG 的 EXIF 能塞注释字段，出题人爱把提示写在这里',
         'JPEG 是有损压缩，硬改像素会留下统计痕迹 —— 这个工具就靠统计特征判断有没有藏',
         'F5 是专门针对 JPEG 的隐写算法，必须用配套工具才能提出来',
         '藏不了就换思路：也许根本不是隐写，而是"图里接了另一个文件"',
         '复合文件很常见：一张图后面可以直接跟着一个完整压缩包'],
 '21': ['标准编码有固定特征，程序判断比肉眼准得多',
         'base64 这类解码结果唯一；凯撒/换表要靠"猜"，一上来就猜容易把正确答案顶掉',
         '工具按"解出来像不像正常文本/像不像 flag"打分，★ 就是它觉得最可能的'],
 '24': ['有 p、q 就不需要分解 n，直接算最快 —— 先把手上的条件看清楚再选',
         'RSA 的全部安全性都压在"n 难分解"上，题目必然给了一个好分解的弱 n（太小 / 两个因子挨得近）',
         'm = c^d mod n 是 RSA 的定义式，算出 d 代进去就行'],
 '26': ['密钥只有一个字节时总共只有 256 种可能，全试一遍就是最快解法',
         '工具按"解出来像不像英文/像不像 flag"排序，你从上往下看就行',
         '密钥是多字节时，先猜长度，再把它当成若干个单字节分别爆破'],
 '41': ['和 #01 是同一个工具 —— 逆向的第一步永远是先认门牌号',
         '语言和壳直接决定路线：.NET 用 dnSpy、Python 打包用 pyreverse、UPX 先脱壳',
         '先看懂再动手，比一上来就开调试器省 90% 时间'],
 '42': ['拆包用的是 pyinstxtractor，它专门认 PyInstaller 的结构',
         '拆出来的 .pyc 是 Python 字节码，反编译回 .py 才看得懂',
         '如果打包时加了密（出现 unknown_crypt / 无 PYZ 里的可读内容），常规手段拿不到源码，这属于题目设计'],
 '44': ['jadx 把 dex 反编译回 Java，还带资源文件，是看安卓代码最省事的路',
         'apktool 是"改完要重新打包安装"才需要的；只是看代码/找 flag 用不到它',
         'APK 本质就是 zip，解压后 assets/ 和 res/ 里是原始文件，常常直接写着明文',
         '有些题故意把 flag 拆开：一段在 dex、一段在 assets，拼起来才完整'],
 '51': ['Wireshark 开始菜单就能搜到，双击打开',
         '先看协议分布，就知道这题考的是 HTTP 还是 USB 还是别的',
         'HTTP 传输的文件能一键全导出来，flag 常常就在里面',
         '某一个流看不懂时，"追踪流"能把整段对话拼成一段可读文本'],
 '55': ['描述里的怪话（比如"折在最里面那一页"）往往就是解法提示，先读它',
         '题目一多最容易乱；一题一个文件，赛后写题解也方便',
         '花 10 秒就能拿到"下一步方向"，比自己瞎试快得多',
         '每条都写清了工具和步骤，照着做，不用记忆力',
         '它靠会话存档记进度，你不用记住中间做过什么',
         '比赛按提交时间计分，先落袋为安；题解是赛后审核用的，可以慢慢补',
         '题解要还原解题过程，中间文件就是证据 —— 删了就说不清了'],
}
