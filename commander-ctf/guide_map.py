# -*- coding: utf-8 -*-
"""route -> exact tool, search terms, and documentation section.

这不是题目答案库，而是新手路线索引。每条路线只回答：
用什么工具、工具界面/说明里搜什么、教程里看哪一节。
"""

ROUTE_GUIDES = {
    # 文本 / 编码 / Crypto
    'TXT-SYM': {'tool': 'CyberChef + commander', 'search': 'Magic / From Base / From Charset', 'doc': 'M3：emoji/自造符号/任意符号表'},
    'TXT-B64': {'tool': 'CyberChef + commander', 'search': 'From Base64 / Magic / Operations', 'doc': 'M1：编码/多层套娃'},
    'TXT-CLASSIC': {'tool': 'CyberChef + commander', 'search': 'ROT13 / Vigenere Decode / Bacon Decode', 'doc': 'M2：古典密码'},
    'TXT-KEYBOARD': {'tool': 'commander 的 keyboard 工具', 'search': 'keyboard / 键盘密码 / 8 方向', 'doc': 'M2：古典密码；再搜 keyboard'},
    'TXT-MORSE': {'tool': 'CyberChef + commander', 'search': 'From Morse Code / Morse', 'doc': 'M1：编码/多层套娃'},
    'TXT-XOR': {'tool': 'CyberChef + commander', 'search': 'XOR / XOR Brute Force', 'doc': 'M1：编码/多层套娃；再搜 XOR'},
    'TXT-HASH': {'tool': 'commander hash 工具 + hashcat', 'search': 'hash mode / -m / rockyou', 'doc': 'M1：编码/多层套娃；再搜 hash'},
    'TXT-RSA': {'tool': 'commander rsa 工具 + CyberChef', 'search': 'RSA / factor / modular exponent', 'doc': 'M1：编码/多层套娃；再搜 RSA'},
    'TXT-JWT': {'tool': 'jwt_tool + CyberChef', 'search': 'JWT Decode / alg=none / crack', 'doc': 'W11：JWT'},
    'TXT-INVISIBLE': {'tool': 'commander zerowidth 工具', 'search': 'zero width / Variation Selector', 'doc': 'M4：零宽/空白/变体选择符'},
    'TXT-EMOJI': {'tool': 'commander emoji 工具', 'search': 'emoji / symbol table / base', 'doc': 'M3：emoji/自造符号/任意符号表'},

    # 图片
    'IMG-META': {'tool': 'ExifTool + commander', 'search': '-a -u -g1 / Comment / Software', 'doc': 'M5：图片元数据/注释'},
    'IMG-LSB': {'tool': 'StegSolve + zsteg + commander', 'search': 'Analyse / Data Extract / bit plane / zsteg -a', 'doc': 'M7：LSB/位平面/颜色通道'},
    'IMG-WH': {'tool': 'commander imgdeep + pngcheck', 'search': 'IHDR / CRC / width / height', 'doc': 'M6：PNG 宽高被改'},
    'IMG-TAIL': {'tool': 'commander carve + ImHex + 7-Zip', 'search': '50 4B 03 04 / trailing / carve / PK', 'doc': 'M8：图片尾部/复合文件'},
    'IMG-CHANNEL': {'tool': 'StegSolve + commander', 'search': 'Red / Green / Blue / XOR / bit plane', 'doc': 'M7：LSB/位平面/颜色通道'},
    'IMG-QR': {'tool': 'commander qr 工具 + 二维码扫描器', 'search': 'reverse color / quiet zone / QR', 'doc': 'M10：二维码/0-1'},
    'IMG-GIF': {'tool': 'ffmpeg + ImageMagick + commander', 'search': 'coalesce / frames / comment', 'doc': 'M9：JPEG/GIF'},
    'IMG-JPEG': {'tool': 'StegExpose + F5 + ExifTool', 'search': 'detect / extraction / password / Comment', 'doc': 'M9：JPEG/GIF'},
    'IMG-DIFF': {'tool': 'commander diff + ImageMagick compare', 'search': 'difference / XOR / blind watermark', 'doc': 'M9：JPEG/GIF；再搜 找不同/盲水印'},
    'IMG-OCR': {'tool': 'RapidOCR + tesseract + commander', 'search': 'OCR / language / psm', 'doc': 'M5：图片元数据/注释；再搜 OCR'},

    # 压缩包
    'ZIP-FAKE': {'tool': 'commander archive + 7-Zip', 'search': 'pseudo encryption / general purpose bit flag', 'doc': 'M11：ZIP 伪加密'},
    'ZIP-WEAK': {'tool': 'John the Ripper + hashcat + rockyou', 'search': 'zip2john / -m 17200 / -a 0 / rockyou', 'doc': 'M12：ZIP 弱口令'},
    'ZIP-COMMENT': {'tool': '7-Zip + commander archive', 'search': 'Comment / Archive properties', 'doc': 'M11：ZIP 伪加密；再搜 注释'},
    'ZIP-PLAIN': {'tool': 'bkcrack', 'search': 'known plaintext / -C -c -p / recover', 'doc': 'M13：ZIP 已知明文攻击'},
    'ZIP-NEST': {'tool': '7-Zip + commander carve', 'search': 'nested archive / trailing bytes / recursive', 'doc': 'M11：ZIP 伪加密；再搜 嵌套/尾部'},

    # 音频
    'AUD-SPEC': {'tool': 'Audacity + Sonic Visualiser + commander', 'search': 'Spectrogram / high frequency / track', 'doc': 'M14：音频'},
    'AUD-LSB': {'tool': 'commander audio + Python wave', 'search': 'LSB / sample / PCM / WAV', 'doc': 'M14：音频'},
    'AUD-MORSE': {'tool': 'Audacity + commander', 'search': 'Morse / short-long / duration', 'doc': 'M14：音频'},
    'AUD-REV': {'tool': 'Audacity + sox + commander', 'search': 'Reverse / channel split / invert', 'doc': 'M14：音频'},

    # 流量
    'PCAP-HTTP': {'tool': 'Wireshark + tshark', 'search': 'Export Objects -> HTTP / Follow TCP Stream / http', 'doc': 'M15：PCAP 流量'},
    'PCAP-DNS': {'tool': 'Wireshark + tshark', 'search': 'dns / dns.qry.name / base32', 'doc': 'M15：PCAP 流量'},
    'PCAP-USB': {'tool': 'Wireshark + USB HID 脚本', 'search': 'usb / HID / leftover capture data', 'doc': 'M15：PCAP 流量'},
    'PCAP-ICMP': {'tool': 'Wireshark + tshark', 'search': 'icmp / data.data', 'doc': 'M15：PCAP 流量'},
    'PCAP-STREAM': {'tool': 'Wireshark', 'search': 'Protocol Hierarchy / Follow TCP Stream / tcp.stream', 'doc': 'M15：PCAP 流量'},

    # 取证
    'DOC-PDF': {'tool': 'qpdf + pdf-parser + commander', 'search': 'streams / embedded files / decrypt', 'doc': 'M16：PDF'},
    'DOC-OFFICE': {'tool': '7-Zip + commander', 'search': 'word/document.xml / xl / ppt', 'doc': 'M17：Office 文档'},
    'DOC-SQLITE': {'tool': 'DB Browser for SQLite + commander', 'search': 'Browse Data / Execute SQL / sqlite_master', 'doc': 'M19：SQLite'},
    'FIS-CARVE': {'tool': 'binwalk + foremost + commander carve', 'search': 'signature / offset / extract / carve', 'doc': 'M20：磁盘镜像/大文件雕刻'},
    'FIS-GIT': {'tool': 'Git + commander gitdeep', 'search': 'log / reflog / fsck --unreachable', 'doc': 'M18：Git 取证'},
    'FIS-DISK': {'tool': 'bulk_extractor + ImHex', 'search': 'features / carve / partition', 'doc': 'M20：磁盘镜像/大文件雕刻'},

    # 逆向
    'REV-LANG': {'tool': 'DetectItEasy + commander', 'search': 'File type / Compiler / Packer', 'doc': '按题型查工具和教程 -> 先认文件类型/壳'},
    'REV-STR': {'tool': 'strings + FLOSS + commander', 'search': 'ASCII / UTF-16 / flag / key / password / wrong', 'doc': '按题型查工具和教程 -> 字符串交叉引用'},
    'REV-PY': {'tool': 'commander pyreverse + pyinstxtractor', 'search': 'PyInstaller / PYZ / decompile', 'doc': '按题型查工具和教程 -> Python/PyInstaller'},
    'REV-NET': {'tool': 'dnSpy 或 ILSpy', 'search': 'Assembly Explorer / Decompile / search string', 'doc': '按题型查工具和教程 -> .NET'},
    'REV-UPX': {'tool': 'UPX + DetectItEasy', 'search': 'upx -d / packer / OEP', 'doc': '按题型查工具和教程 -> UPX/脱壳'},

    # Web
    'WEB-SOURCE': {'tool': 'commander webaudit + 浏览器 F12', 'search': '.git / .env / backup / robots / Sources', 'doc': 'W1：源码/配置/备份泄露'},
    'WEB-DIR': {'tool': 'ffuf + dirsearch', 'search': 'FUZZ / -w / status code / 200', 'doc': 'W2：目录扫描'},
    'WEB-COOKIE': {'tool': '浏览器 DevTools + commander webaudit', 'search': 'Application -> Cookies / Local Storage / base64', 'doc': 'W10：Cookie/会话篡改'},
    'WEB-JWT': {'tool': 'jwt_tool + CyberChef', 'search': 'jwt_tool -t / alg=none / crack', 'doc': 'W11：JWT'},
    'WEB-SQLI': {'tool': 'sqlmap + 浏览器', 'search': '-u / --batch / --dbs / --dump', 'doc': 'W4：SQL 注入'},
    'WEB-SSTI': {'tool': '浏览器 + ffuf', 'search': '{{7*7}} / ${7*7} / Jinja2 / Twig', 'doc': 'W5：模板注入 SSTI'},
    'WEB-LFI': {'tool': '浏览器 + curl + PHP filter', 'search': '?file= / ?page= / php://filter', 'doc': 'W6：文件包含/路径穿越'},
    'WEB-CMD': {'tool': '浏览器 + curl', 'search': '?cmd= / ?ip= / ;id / |id', 'doc': 'W7：命令注入'},
    'WEB-SSRF': {'tool': '浏览器 + curl', 'search': '?url= / 127.0.0.1 / file://', 'doc': 'W8：SSRF'},
    'WEB-LOGIN': {'tool': '浏览器 + Burp Suite 或 ZAP', 'search': 'admin/admin / SQL injection / Cookie', 'doc': 'W9：登录框/弱口令/登录绕过'},
}

CATEGORY_FALLBACK = {
    '文本': {'tool': 'commander + CyberChef', 'search': 'Magic / Operations', 'doc': 'M1：编码/多层套娃'},
    '图片': {'tool': 'commander + StegSolve + ExifTool', 'search': 'Analyse / Data Extract / metadata', 'doc': 'M7：LSB/位平面/颜色通道'},
    '压缩包': {'tool': 'commander + 7-Zip', 'search': 'Archive properties / password / comment', 'doc': 'M11：ZIP 伪加密'},
    '音频': {'tool': 'commander + Audacity', 'search': 'Spectrogram / Reverse / channel', 'doc': 'M14：音频'},
    '流量': {'tool': 'Wireshark + tshark', 'search': 'Protocol Hierarchy / Follow Stream / Export Objects', 'doc': 'M15：PCAP 流量'},
    '取证': {'tool': 'commander + ImHex', 'search': 'signature / embedded / extract', 'doc': 'M20：磁盘镜像/大文件雕刻'},
    '逆向': {'tool': 'DetectItEasy + strings', 'search': 'Compiler / Packer / strings', 'doc': '按题型查工具和教程'},
    'Web': {'tool': '浏览器 F12 + curl', 'search': 'Network / Sources / Application / Response', 'doc': 'W0：Web 起手式'},
}
