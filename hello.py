#!/usr/bin/env python3
"""hello.py：最小示例脚本。

用法：
    python hello.py           # 打印 Hello, World!
    python hello.py 张三      # 打印 Hello, 张三!
"""
from __future__ import annotations

import sys


def greet(name: str = "World") -> str:
    """返回一句问候语。"""
    return f"Hello, {name}!"


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    name = args[0] if args else "World"
    print(greet(name))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
