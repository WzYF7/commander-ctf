# Commander CTF 教学向导

Commander 是一个 Windows 命令行练习工具。它识别本地练习文件，给出候选分析路线，并解释这一步该用什么工具和为什么。

## 快速上手

需要 Windows 和 Python 3.12 或更高版本。先在 PowerShell 中进入仓库目录，再创建一份演示材料：

```powershell
Set-Content -LiteralPath .commander-demo.txt -Value 'SGVsbG8gQ29tbWFuZGVy' -Encoding ascii
python commander.py --learn .commander-demo.txt
```

在 commander 提示符后输入「向导」查看推荐路线。输入 0 回到主界面，再输入 q 退出。也可以把自己的 CTF 练习文件拖到 commander.cmd 上。

## 新手向导

完成一次分析后，输入「向导」查看一条路线。界面会列出推荐工具、搜索词和下一步操作。输入「表」查看速查编号，再输入编号可以读完整步骤。输入「诊断」查看分析报告，输入 w 导出题解草稿。

## 配置外部工具

基础文本练习只需要 Python。图像、音频、压缩包等进阶路线可能需要 Pillow、NumPy、OpenCV、Java 或相应的命令行程序。已有的外部工具目录可通过 COMMANDER_TOOLKIT_DIR 指定。工具未安装时，可以先按向导显示的关键词手工操作。

PyInstaller 拆包路线需要使用者另行获取上游的 pyinstxtractor.py，放在 tools 目录下。

练习记录和生成文件放在项目里的 session.json、.commander-work/、outcome/ 与 writeups/。请使用你有权分析的 CTF、靶场或本地练习材料。
