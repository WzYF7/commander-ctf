# -*- coding: utf-8 -*-
"""Structured, human-readable diagnostics for commander.

The goal is not to make every analysis automatic.  The goal is to make every
automatic step inspectable: what was assumed, what evidence was observed, where
the artifacts are, and what a human should do next if the step fails.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path


class Diagnostics:
    def __init__(self, outdir: str, target: str, mode: str = "solve"):
        self.outdir = Path(outdir)
        self.target = target
        self.mode = mode
        self.started = time.strftime("%Y-%m-%d %H:%M:%S")
        self.steps: list[dict] = []

    def add(
        self,
        phase: str,
        status: str,
        title: str,
        *,
        why: str = "",
        assumption: str = "",
        evidence: str = "",
        artifacts: list[str] | None = None,
        next_action: str = "",
        confidence: str = "",
    ) -> None:
        self.steps.append(
            {
                "time": time.strftime("%H:%M:%S"),
                "phase": str(phase),
                "status": str(status),
                "title": str(title),
                "why": str(why),
                "assumption": str(assumption),
                "evidence": str(evidence),
                "artifacts": list(artifacts or []),
                "next_action": str(next_action),
                "confidence": str(confidence),
            }
        )

    def markdown(self, flags=None, manual_next=None) -> str:
        flags = list((flags or {}).keys())
        manual_next = list(manual_next or [])
        lines = [
            "# commander 诊断报告",
            "",
            f"- 目标：`{self.target}`",
            f"- 开始：{self.started}",
            f"- 模式：{self.mode}",
            f"- 步骤数：{len(self.steps)}",
            "",
            "## 结论",
            "",
        ]
        if flags:
            lines.append("✅ 已发现 flag 候选：")
            lines.extend(f"- `{x}`" for x in flags)
        else:
            lines.append("⚠ 本轮没有直接产出 flag。下面保留每一步的证据和手工接手点。")
        lines.extend(["", "## 分析轨迹", ""])
        for i, item in enumerate(self.steps, 1):
            lines.append(f"### {i}. [{item['status']}] {item['title']}")
            if item["confidence"]:
                lines.append(f"- 置信度：{item['confidence']}")
            if item["why"]:
                lines.append(f"- 为什么做：{item['why']}")
            if item["assumption"]:
                lines.append(f"- 本步假设：{item['assumption']}")
            if item["evidence"]:
                lines.append(f"- 观察证据：{item['evidence']}")
            if item["artifacts"]:
                lines.append("- 中间产物：")
                lines.extend(f"  - `{x}`" for x in item["artifacts"])
            if item["next_action"]:
                lines.append(f"- 下一步手工检查：{item['next_action']}")
            lines.append("")
        lines.extend(["## 手工接手清单", ""])
        if manual_next:
            lines.extend(f"- {x}" for x in manual_next)
        else:
            lines.append("- 如果已有 flag，先核对格式和来源；如果没有，按路线导航继续。")
        lines.extend(
            [
                "",
                "## 诊断原则",
                "",
                "- 自动结果是候选，不等于已证明的答案。",
                "- 中间产物和证据优先于黑盒结论。",
                "- 任何失败都应落到“下一步看哪里/试什么”，而不是只输出空结果。",
            ]
        )
        return "\n".join(lines) + "\n"

    def write(self, flags=None, manual_next=None) -> Path:
        self.outdir.mkdir(parents=True, exist_ok=True)
        jsonl = self.outdir / "诊断日志.jsonl"
        with jsonl.open("w", encoding="utf-8") as f:
            for item in self.steps:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
        report = self.outdir / "诊断报告.md"
        report.write_text(self.markdown(flags, manual_next), encoding="utf-8")
        return report
