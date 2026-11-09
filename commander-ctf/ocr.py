# -*- coding: utf-8 -*-
"""ocr -- local OCR for beginner CTF image challenges.

Uses RapidOCR when available and falls back to pytesseract.  No online API is
used.
"""
import re

_ENGINE = None


def available():
    try:
        import rapidocr_onnxruntime  # noqa: F401
        return True
    except Exception:
        pass
    try:
        import pytesseract  # noqa: F401
        return True
    except Exception:
        return False


def _rapid():
    global _ENGINE
    if _ENGINE is None:
        from rapidocr_onnxruntime import RapidOCR
        _ENGINE = RapidOCR()
    return _ENGINE


def ocr_array(gray):
    """Return visible text lines from a grayscale/color numpy image."""
    out = []
    try:
        import numpy as np
        arr = np.asarray(gray)
        if arr.dtype != np.uint8:
            if arr.size and float(arr.max()) <= 1.0:
                arr = arr * 255
            arr = np.clip(arr, 0, 255).astype("uint8")
        try:
            result, _ = _rapid()(arr)
            for item in result or []:
                if len(item) >= 3 and float(item[2]) >= 0.35:
                    text = str(item[1]).strip()
                    if text:
                        out.append(text)
            if out:
                return out
        except Exception:
            pass
        try:
            import pytesseract
            from PIL import Image
            im = Image.fromarray(arr)
            im = im.resize((max(1, im.width * 2), max(1, im.height * 2)))
            txt = pytesseract.image_to_string(im, lang="eng")
            out = [line.strip() for line in txt.splitlines() if line.strip()]
        except Exception:
            pass
    except Exception:
        return []
    return out


def guess_passwords(text):
    """Extract plausible short passwords from OCR text."""
    out = []
    for m in re.finditer(r"[A-Za-z0-9_\-!@#$%^&*]{3,48}", text or ""):
        word = m.group()
        out.append(word)
    seen, result = set(), []
    for word in sorted(out, key=lambda w: (abs(len(w) - 8), w)):
        if word not in seen:
            seen.add(word)
            result.append(word)
    return result[:30]
