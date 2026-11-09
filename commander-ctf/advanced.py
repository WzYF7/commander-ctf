"""Generic, challenge-agnostic analyzers used by commander.

No challenge names, flags, or per-problem branches belong in this module.
"""
from __future__ import annotations

import io
import math
import os
import re
import struct
import subprocess
import sys
import zlib
from pathlib import Path


FLAG_RE = re.compile(r"[A-Za-z][A-Za-z0-9_\-]{1,24}\{[^{}\r\n\t]{2,200}\}")


def _decompress_zip_entry(method: int, raw: bytes) -> bytes:
    if method == 0:
        return raw
    if method == 8:
        try:
            return zlib.decompress(raw, -15)
        except Exception:
            return raw
    return raw


def zip_polyglot_views(data: bytes) -> list[dict]:
    """Follow every plausible EOCD -> central directory -> local header view.

    Polyglot ZIPs can expose different central directories while keeping many
    local file headers.  Archive tools disagree about which view they pick.
    """
    views: list[dict] = []
    seen: set[tuple[int, int, int]] = set()
    for eocd in range(len(data) - 21):
        if data[eocd : eocd + 4] != b"PK\x05\x06":
            continue
        if eocd + 22 > len(data):
            continue
        try:
            _, disk, cd_disk, cd_num, total, cd_size, cd_off, com_len = struct.unpack_from(
                "<IHHHHIIH", data, eocd
            )
        except struct.error:
            continue
        if eocd + 22 + com_len > len(data):
            continue
        if not (0 <= cd_off < len(data) and 0 < cd_num <= 4096):
            continue
        key = (eocd, cd_off, cd_num)
        if key in seen:
            continue
        seen.add(key)
        chunks: list[bytes] = []
        names: list[str] = []
        pos = cd_off
        ok = True
        for _ in range(min(cd_num, total or cd_num)):
            if data[pos : pos + 4] != b"PK\x01\x02":
                ok = False
                break
            try:
                name_len, extra_len, comment_len = struct.unpack_from("<HHH", data, pos + 28)
                rel_off = struct.unpack_from("<I", data, pos + 42)[0]
            except struct.error:
                ok = False
                break
            raw_name = data[pos + 46 : pos + 46 + name_len]
            name = raw_name.decode("utf-8", "replace")
            names.append(name)
            if data[rel_off : rel_off + 4] != b"PK\x03\x04":
                ok = False
                break
            try:
                flags, method = struct.unpack_from("<HH", data, rel_off + 6)
                comp_len = struct.unpack_from("<I", data, rel_off + 18)[0]
                local_name_len, local_extra_len = struct.unpack_from("<HH", data, rel_off + 26)
            except struct.error:
                ok = False
                break
            if flags & 1:
                ok = False
                break
            start = rel_off + 30 + local_name_len + local_extra_len
            raw = data[start : start + comp_len]
            chunks.append(_decompress_zip_entry(method, raw))
            pos += 46 + name_len + extra_len + comment_len
        if ok and chunks:
            views.append(
                {
                    "eocd": eocd,
                    "cd_offset": cd_off,
                    "entries": len(chunks),
                    "names": names,
                    "data": b"".join(chunks),
                }
            )
            if len(views) >= 64:
                break
    return views


def zip_local_entries(data: bytes, max_entries: int = 2048) -> list[dict]:
    """Enumerate all LFH entries, including ones invisible to zipfile."""
    out: list[dict] = []
    pos = 0
    while len(out) < max_entries:
        i = data.find(b"PK\x03\x04", pos)
        if i < 0:
            break
        pos = i + 4
        try:
            flags, method = struct.unpack_from("<HH", data, i + 6)
            comp_len = struct.unpack_from("<I", data, i + 18)[0]
            name_len, extra_len = struct.unpack_from("<HH", data, i + 26)
        except struct.error:
            continue
        raw_name = data[i + 30 : i + 30 + name_len]
        name = raw_name.decode("utf-8", "replace")
        start = i + 30 + name_len + extra_len
        raw = data[start : start + comp_len]
        out.append(
            {
                "offset": i,
                "flags": flags,
                "method": method,
                "name": name,
                "data": _decompress_zip_entry(method, raw) if not (flags & 1) else raw,
                "encrypted": bool(flags & 1),
            }
        )
    return out


def jpeg_segments(data: bytes) -> list[dict]:
    """Parse JPEG marker segments and SOF dimensions/sampling factors."""
    out: list[dict] = []
    if not data.startswith(b"\xff\xd8"):
        return out
    i = 2
    while i + 4 <= len(data):
        if data[i] != 0xFF:
            i += 1
            continue
        while i < len(data) and data[i] == 0xFF:
            i += 1
        if i >= len(data):
            break
        marker = data[i]
        i += 1
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            continue
        if i + 2 > len(data):
            break
        seg_len = struct.unpack_from(">H", data, i)[0]
        if seg_len < 2 or i + seg_len > len(data):
            break
        item = {"marker": marker, "marker_hex": f"FF{marker:02X}", "offset": i - 2, "length": seg_len}
        if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            if seg_len >= 8:
                item["precision"] = data[i + 2]
                item["height"] = struct.unpack_from(">H", data, i + 3)[0]
                item["width"] = struct.unpack_from(">H", data, i + 5)[0]
                item["components"] = data[i + 7]
                sampling = []
                for c in range(item["components"]):
                    base = i + 8 + c * 3
                    if base + 2 < len(data):
                        hv = data[base + 1]
                        sampling.append((hv >> 4, hv & 0x0F))
                item["sampling"] = sampling
                item["sof_data_offset"] = i
        out.append(item)
        i += seg_len
        if marker == 0xDA:
            break
    return out


def jpeg_repair_candidates(path: str, data: bytes, outdir: str) -> list[dict]:
    """Generate MCU-aligned width/height candidates for truncated JPEGs."""
    results: list[dict] = []
    for seg in jpeg_segments(data):
        if "width" not in seg:
            continue
        width, height = seg["width"], seg["height"]
        sampling = seg.get("sampling") or []
        max_h = max((h for h, _ in sampling), default=1)
        max_v = max((v for _, v in sampling), default=1)
        mcu_w, mcu_h = 8 * max_h, 8 * max_v
        candidates = []
        if mcu_w > 1:
            candidates.extend(
                [
                    ((width + mcu_w - 1) // mcu_w) * mcu_w,
                    max(mcu_w, (width // mcu_w) * mcu_w),
                    width + mcu_w,
                ]
            )
        if mcu_h > 1:
            candidates.extend(
                [
                    ((height + mcu_h - 1) // mcu_h) * mcu_h,
                    max(mcu_h, (height // mcu_h) * mcu_h),
                    height + mcu_h,
                ]
            )
        seen = set()
        for new_w in candidates:
            if not (1 <= new_w <= 65535) or new_w == width or new_w in seen:
                continue
            seen.add(new_w)
            patched = bytearray(data)
            struct.pack_into(">H", patched, seg["sof_data_offset"] + 5, new_w)
            out = os.path.join(outdir, f"jpeg_width_{new_w}.jpg")
            try:
                os.makedirs(outdir, exist_ok=True)
                Path(out).write_bytes(patched)
                from PIL import Image

                with Image.open(io.BytesIO(patched)) as im:
                    im.load()
                    png = os.path.join(outdir, f"jpeg_width_{new_w}.png")
                    im.convert("RGB").save(png)
                results.append(
                    {
                        "old_width": width,
                        "new_width": new_w,
                        "height": height,
                        "mcu": (mcu_w, mcu_h),
                        "jpg": out,
                        "png": png,
                    }
                )
            except Exception:
                continue
        for new_h in candidates:
            if not (1 <= new_h <= 65535) or new_h == height or ("h", new_h) in seen:
                continue
            seen.add(("h", new_h))
            patched = bytearray(data)
            struct.pack_into(">H", patched, seg["sof_data_offset"] + 3, new_h)
            out = os.path.join(outdir, f"jpeg_height_{new_h}.jpg")
            try:
                os.makedirs(outdir, exist_ok=True)
                Path(out).write_bytes(patched)
                from PIL import Image

                with Image.open(io.BytesIO(patched)) as im:
                    im.load()
                    png = os.path.join(outdir, f"jpeg_height_{new_h}.png")
                    im.convert("RGB").save(png)
                results.append(
                    {
                        "old_width": width,
                        "new_width": width,
                        "height": new_h,
                        "mcu": (mcu_w, mcu_h),
                        "jpg": out,
                        "png": png,
                    }
                )
            except Exception:
                continue
    return results


def _bytes_from_bits(bits: str) -> bytes:
    bits = bits[: len(bits) // 8 * 8]
    return bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))


def mirror_stego_candidates(arr) -> list[dict]:
    """Decode mirrored-image stego by comparing left and reversed right half."""
    try:
        import numpy as np
        h, w = arr.shape[:2]
        if w % 2 or w < 4:
            return []
    except Exception:
        return []
    candidates = []
    seen = set()
    left = arr[:, : w // 2, :].astype("int16")
    right = arr[:, ::-1, :][:, : w // 2, :].astype("int16")
    diff = right - left
    changed = np.any(diff != 0, axis=2).reshape(-1)
    for channel in (2, 1, 0):
        stream = (diff[:, :, channel].reshape(-1)[changed] != 0).astype("uint8")
        for start in range(8):
            bits = stream[start:]
            usable = len(bits) // 8 * 8
            if not usable:
                continue
            raw = np.packbits(bits[:usable]).tobytes()
            for enc in ("utf-8", "latin-1"):
                try:
                    text = raw.decode(enc)
                except Exception:
                    continue
                for m in FLAG_RE.finditer(text):
                    key = (channel, start, m.group(0))
                    if key not in seen:
                        seen.add(key)
                        candidates.append(
                            {
                                "channel": "BGR"[channel] if channel < 3 else str(channel),
                                "skip": start,
                                "flag": m.group(0),
                            }
                        )
    return candidates


def estimated_jpeg_size(data: bytes) -> tuple[int, int] | None:
    for seg in jpeg_segments(data):
        if "width" in seg:
            return seg["width"], seg["height"]
    return None


def source_audit(text: str) -> list[dict]:
    """Small, generic audit heuristics for beginner Web/source challenges."""
    findings: list[dict] = []
    lines = text.splitlines()
    for idx, line in enumerate(lines, 1):
        lower = line.lower()
        context = "\n".join(lines[max(0, idx - 3) : min(len(lines), idx + 3)])
        add = lambda kind, why, nxt: findings.append(
            {"type": kind, "line": idx, "code": line.strip(), "why": why, "next": nxt}
        )
        if any(x in lower for x in ("os.popen", "subprocess.", "exec(", "eval(", "system(")):
            if any(x in context for x in ("request", "req.", "filename", "param", "input", "fname")):
                add(
                    "命令执行/命令拼接",
                    "用户可控内容进入了系统命令或动态执行接口。",
                    "先定位可控参数，使用无害回显如 whoami/id，再按回显调整。",
                )
        if any(x in lower for x in ("select ", "insert ", "update ", "delete ")):
            if any(x in lower for x in ("${", " + ", "format(", "%s", "f\"")) or (
                idx > 1 and ("execute" in lower or "db.all" in lower or "query" in lower)
            ):
                add(
                    "SQL 注入",
                    "SQL 字符串看起来由请求参数拼接，而不是参数化查询。",
                    "先输入单引号观察报错，再试恒真条件；确认后用 sqlmap 或手工 UNION。",
                )
        if ("request.headers" in lower or "req.get(" in lower or "rawheaders" in lower) and (
            "select " in context.lower() or "where " in context.lower()
        ):
            add(
                "Header SQL 注入",
                "请求头值进入了 SQL 查询，重点测试自定义 Header。",
                "用 Burp/curl 修改对应 Header；观察 SQLite/MySQL 报错和布尔差异。",
            )
        if "rawheaders" in lower and any(x in context.lower() for x in ("length", "totalheaders", "duplicate")):
            add(
                "HTTP 解析/请求走私",
                "代码直接处理原始 Header，且对长度或重复头有限制；不同前端/后端可能解析不一致。",
                "记录前端代理与后端对重复 Content-Length/Transfer-Encoding 的解释，优先做无害差异探测。",
            )
        if "parse_qsl" in lower and any(x in context.lower() for x in ("int(", "currency", "amount", "balance")):
            add(
                "业务逻辑/数值校验",
                "表单被解析后直接转数字，需检查负数、重复字段、类型转换和边界值。",
                "先正常提交一次，再只改动一个数值；检查服务端是否允许负数或重复参数。",
            )
        if any(x in lower for x in ("unquote(", "os.path.join", "path.join", "filename")):
            if any(x in context for x in (".save(", "open(", "readfile", "send_file", "fname")):
                add(
                    "路径/文件处理",
                    "文件名或路径来自用户输入，需检查 `../`、编码绕过、换行和归档解压路径。",
                    "在副本上测试路径穿越和特殊文件名；观察服务端返回和目录列表。",
                )
        if any(x in lower for x in ("pickle.loads", "yaml.load", "marshal.loads")):
            add(
                "反序列化",
                "不可信数据可能进入反序列化接口。",
                "只对授权靶机测试；先确认数据来源和是否能控制序列化内容。",
            )
    return findings


def source_routes(text: str) -> list[dict]:
    """Inventory Flask/FastAPI/Express-style routes from provided source."""
    routes = []
    lines = text.splitlines()
    patterns = [
        (re.compile(r"@(?:app|router)\.(get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]", re.I), "python"),
        (re.compile(r"@(?:app|bp)\.route\(\s*['\"]([^'\"]+)['\"]", re.I), "flask"),
        (re.compile(r"\b(?:app|router)\.(get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]", re.I), "js"),
    ]
    for i, line in enumerate(lines, 1):
        for pattern, kind in patterns:
            m = pattern.search(line)
            if not m:
                continue
            if kind == "flask":
                method, path = "ANY", m.group(1)
            else:
                method, path = m.group(1).upper(), m.group(2)
            routes.append({"method": method, "path": path, "line": i, "code": line.strip()})
    # De-duplicate exact route declarations.
    return list({(r["method"], r["path"], r["line"]): r for r in routes}.values())


def missing_letters(text: str) -> list[str]:
    """Return lowercase ASCII letters absent from a sufficiently long text."""
    if len(text) < 500:
        return []
    seen = {c.lower() for c in text if c.isascii() and c.isalpha()}
    return [c for c in "abcdefghijklmnopqrstuvwxyz" if c not in seen]


def convolution_candidates_from_source(source_path: Path, source: str, outdir: str) -> list[dict]:
    """Infer a simple randomized convolution kernel and run Wiener deconvolution.

    This covers the common CTF pattern: source exposes `random.seed(...)`,
    `randint(a,b)`, a square kernel size, and one saved/degraded image.
    """
    if not all(token in source for token in ("random.seed", "randint", "range(")):
        return []
    if not any(token in source.lower() for token in ("kernel", "convol", "interp", "imsave")):
        return []
    images = []
    for ext in ("*.png", "*.jpg", "*.jpeg", "*.tif", "*.tiff"):
        images.extend(sorted(source_path.parent.glob(ext)))
    images = [p for p in images if p.resolve() != source_path.resolve()]
    if len(images) != 1:
        return []
    mseed = re.search(r"random\.seed\(\s*(\d+)\s*\)", source)
    mrange = re.search(r"randint\(\s*(-?\d+)\s*,\s*(-?\d+)\s*\)", source)
    mrange_n = re.search(r"range\(\s*(\d+)\s*\)", source)
    if not (mseed and mrange and mrange_n):
        return []
    import random
    import numpy as np
    from PIL import Image

    seed = int(mseed.group(1))
    lo, hi = int(mrange.group(1)), int(mrange.group(2))
    size = int(mrange_n.group(1))
    if not (2 <= size <= 63 and size <= 512):
        return []
    random.seed(seed)
    kernel = np.array([[float(random.randint(lo, hi)) for _ in range(size)] for _ in range(size)])
    if not np.isfinite(kernel).all() or abs(float(kernel.sum())) < 1e-12:
        return []
    kernel = np.flip(kernel)
    kernel /= kernel.sum()
    image = Image.open(images[0]).convert("RGB")
    arr = np.asarray(image)
    results = []
    for channel in range(min(3, arr.shape[2])):
        base = arr[:, :, channel].astype(np.float64)
        # Source commonly maps values back into -10..10.  Keep raw values when
        # that exact mapping is not present.
        if "-10" in source and "10" in source and "interp" in source:
            raw = np.interp(base, (0, 256), (-10.0, 10.0))
        else:
            raw = base
        h, w = raw.shape
        padded = np.zeros((h, w), dtype=np.float64)
        kh, kw = kernel.shape
        if kh > h or kw > w:
            continue
        padded[:kh, :kw] = kernel
        padded = np.roll(padded, (-(kh // 2), -(kw // 2)), axis=(0, 1))
        f_img = np.fft.fft2(raw)
        f_psf = np.fft.fft2(padded)
        for noise in (1e-4, 3e-4, 1e-3, 3e-3, 0.01, 0.03, 0.1, 0.3, 1.0, 10.0):
            rec = np.fft.ifft2(f_img * np.conj(f_psf) / (np.abs(f_psf) ** 2 + noise)).real
            rec -= rec.min()
            mx = rec.max()
            if mx > 0:
                rec = rec / mx * 255.0
            out = Path(outdir) / f"deconv_c{channel}_n{noise}.png"
            out.parent.mkdir(parents=True, exist_ok=True)
            Image.fromarray(np.clip(rec, 0, 255).astype(np.uint8)).save(out)
            results.append({"png": str(out), "channel": channel, "noise": noise})
    return results


def morse_flag_candidates(text: str) -> list[str]:
    """Recover a flag when Morse output lost braces/underscores and case.

    Example shape: a known prefix followed by a continuous leetspeak phrase.
    Word boundaries are inferred locally with wordninja; no network/LLM call.
    """
    if not text:
        return []
    candidates = []
    prefixes = ("UMDCTF", "C404", "CTF", "FLAG", "PICO")
    upper = text.strip().upper()
    for prefix in prefixes:
        if not upper.startswith(prefix):
            continue
        tail = upper[len(prefix):].strip("{}_ ")
        if not tail or not re.fullmatch(r"[A-Z0-9_\-]+", tail):
            continue
        leet = tail.translate(str.maketrans({"0": "O", "1": "I", "3": "E", "4": "A", "5": "S", "7": "T"}))
        words = []
        if "_" in tail:
            words = [x for x in re.split(r"_+", leet) if x]
        else:
            try:
                import wordninja
                words = wordninja.split(leet.lower())
            except Exception:
                words = [leet.lower()]
        if words and all(re.fullmatch(r"[a-z0-9]+", w) for w in words):
            candidates.append(prefix + "{" + "_".join(words) + "}")
            # Preserve the original leetspeak spelling while using the inferred
            # word lengths to restore underscores.
            preserved = []
            cursor = 0
            for word in words:
                n = len(word)
                preserved.append(tail[cursor:cursor + n].lower())
                cursor += n
            if cursor == len(tail):
                candidates.append(prefix + "{" + "_".join(preserved) + "}")
    return list(dict.fromkeys(candidates))


def _vigenere_decrypt(text: str, key: str) -> str:
    out = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            shift = ord(key[ki % len(key)].upper()) - ord("A")
            out.append(chr((ord(ch) - base - shift) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def vigenere_url_candidates(text: str) -> list[dict]:
    """Use a prose-provided key clue (e.g. `Fremen (ARE KEY)`) to decode URLs."""
    keys = []
    for m in re.finditer(r"([A-Za-z]{3,24})\s*\(\s*ARE\s+KEY\s*\)", text, re.I):
        key = m.group(1)
        if key.lower() not in [x.lower() for x in keys]:
            keys.append(key)
    out = []
    for key in keys:
        for line in text.splitlines():
            if not line.strip():
                continue
            plain = _vigenere_decrypt(line, key)
            for u in re.findall(r"https?://[^\s)>]+", plain, re.I):
                out.append({"key": key, "url": u.rstrip(".,"), "plain": plain.strip()})
    return out


def download_public_video(url: str, outdir: str) -> str | None:
    """Download a public video/audio URL with yt-dlp into a local cache."""
    import hashlib
    cache = Path(outdir) / ("remote_" + hashlib.sha256(url.encode()).hexdigest()[:12])
    cache.mkdir(parents=True, exist_ok=True)
    existing = [p for p in cache.iterdir() if p.is_file() and p.stat().st_size > 1024]
    if existing:
        return str(existing[0])
    cmd = [
        sys.executable, "-m", "yt_dlp", "--no-playlist", "--no-warnings",
        "-f", "bestaudio/best", "-o", str(cache / "media.%(ext)s"), url,
    ]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except Exception:
        return None
    files = [p for p in cache.iterdir() if p.is_file() and p.stat().st_size > 1024]
    return str(files[0]) if files else None
