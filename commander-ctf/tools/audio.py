# -*- coding: utf-8 -*-
"""音频隐写分析 —— 自动生成频谱图 + 波形图。

（原理：音频文件里能藏东西的地方主要有三处：
  ① 频谱图 —— 把频率画成图，出题人常把文字/图案"画"在高频部分
     （用 Audacity 打开切"频谱图"也是看这个）
  ② 波形 —— 时域图，看有没有异常的"哔"声
  ③ 音频本身 —— 可能是摩斯/拨号音/慢放才听得懂）
  这个工具自动把前两个画出来，你打开图看就行。）

用法: python audio.py 音频文件 [输出目录]
"""
import sys, os, wave, struct, math
try: sys.stdout.reconfigure(encoding='utf-8')
except Exception: pass

def load_wav(path):
    w = wave.open(path, 'rb')
    n, ch, sw, sr = w.getnframes(), w.getnchannels(), w.getsampwidth(), w.getframerate()
    raw = w.readframes(n); w.close()
    if sw == 2:
        data = struct.unpack('<%dh' % (len(raw)//2), raw)
    elif sw == 1:
        data = struct.unpack('<%dB' % len(raw), raw)
    else:
        data = struct.unpack('<%di' % (len(raw)//4), raw)
    if ch > 1:
        data = data[::ch]
    return list(data), sr, ch, sw

def main():
    path = ' '.join(sys.argv[1:]).strip().strip('"')
    if not path: path = input('  把音频文件拖进来再回车: ').strip().strip('"')
    if not os.path.isfile(path): print('  找不到:', path); return
    outdir = os.path.splitext(path)[0] + '_音频分析'
    os.makedirs(outdir, exist_ok=True)
    print('  文件: %s  (%d 字节)' % (os.path.basename(path), os.path.getsize(path)))

    try:
        import numpy as np
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        from scipy import signal as sps
    except ImportError as e:
        print('  缺库:', e)
        print('  执行: python -m pip install numpy matplotlib scipy')
        return

    # ---- 读音频 ----
    if path.lower().endswith('.wav'):
        try:
            data, sr, ch, sw = load_wav(path)
        except Exception as e:
            print('  读 wav 失败:', e); return
    else:
        print('  （不是 wav，尝试用 scipy 读...）')
        try:
            from scipy.io import wavfile
            sr, arr = wavfile.read(path)
            data = arr.tolist() if hasattr(arr, 'tolist') else list(arr)
            if isinstance(data[0], (list, tuple)): data = [x[0] for x in data]
        except Exception as e:
            print('  读不了这个格式:', e)
            print('  提示：先用别的工具转成 wav（比如 ffmpeg -i 输入 输出.wav）'); return

    print('  采样率 %d Hz，共 %d 个采样点（约 %.1f 秒）' % (sr, len(data), len(data)/sr))
    a = np.array(data, dtype=float)
    if a.size > 2_000_000: a = a[:2_000_000]

    # ---- 波形图 ----
    try:
        plt.figure(figsize=(14, 3))
        plt.plot(np.arange(len(a))/sr, a, linewidth=0.4)
        plt.title('Waveform (time domain)'); plt.xlabel('sec'); plt.tight_layout()
        f1 = os.path.join(outdir, '1_波形图.png'); plt.savefig(f1, dpi=110); plt.close()
        print('  ✔ 波形图 -> %s' % f1)
    except Exception as e: print('  波形图失败:', e)

    # ---- 频谱图（重点）----
    try:
        f, t, S = sps.spectrogram(a, sr, nperseg=1024, noverlap=768)
        plt.figure(figsize=(14, 6))
        plt.pcolormesh(t, f, 10*np.log10(S + 1e-12), shading='gouraud', cmap='inferno')
        plt.ylabel('Frequency (Hz)'); plt.xlabel('Time (sec)')
        plt.title('Spectrogram - look for text/patterns here')
        plt.tight_layout()
        f2 = os.path.join(outdir, '2_频谱图.png'); plt.savefig(f2, dpi=120); plt.close()
        print('  ✔ 频谱图 -> %s' % f2)
        print('     （打开这张图，把图片放大/拉长看，出题人常把文字画在高频区）')
    except Exception as e: print('  频谱图失败:', e)

    # ---- 只看高频（有些题只有高频有东西）----
    try:
        f, t, S = sps.spectrogram(a, sr, nperseg=512, noverlap=384)
        hi = f > (sr / 8)
        if hi.sum() > 0:
            plt.figure(figsize=(14, 5))
            plt.pcolormesh(t, f[hi], 10*np.log10(S[hi, :] + 1e-12), shading='gouraud', cmap='magma')
            plt.ylabel('Freq (Hz)'); plt.xlabel('Time (sec)')
            plt.title('High frequency only'); plt.tight_layout()
            f3 = os.path.join(outdir, '3_高频区.png'); plt.savefig(f3, dpi=120); plt.close()
            print('  ✔ 高频区图 -> %s' % f3)
    except Exception as e: pass

    print('')
    print('  下一步：')
    print('   1. 打开 2_频谱图.png 看有没有字母/图案')
    print('   2. 听一遍原音频（倒放、慢放、加速都试试）')
    print('   3. 感觉像摩斯的"哔哔"声 → 用「编码解码」按摩斯解')
    print('   4. 结果目录: %s' % outdir)

if __name__ == '__main__':
    try: main()
    except (EOFError, KeyboardInterrupt): print('\n  （输入中断）')
    except Exception as e: print('\n  [!] 出错: %s' % e)