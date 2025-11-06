#!/usr/bin/env python3
import re
import sys
import json
import argparse
from pathlib import Path
from typing import Iterable, Dict, List

# Matches:
#   CAM-UTIL: cam_io_w_mb: 36: 0xffffff8009198058 00000001
#   CAM-UTIL: cam_io_w: 25:   0xffffff8009198064 ffffffff
#   CAM-UTIL: cam_io_r_mb: 73: 0xffffff800919805c 80000000
#   CAM-UTIL: cam_io_r: 56:    0xffffff80091e0008 00001210
PATTERN = re.compile(
    r'cam_io_(?P<op>r|w)(?:_mb)?:\s*\d+:\s*(?P<addr>0x[0-9a-fA-F]+)\s+(?P<val>[0-9a-fA-F]+)',
    re.IGNORECASE
)

def _norm_hex(s: str) -> str:
    s = s.strip()
    if not s.lower().startswith("0x"):
        s = "0x" + s
    return s.lower()

def parse_lines(lines: Iterable[str]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    for ln in lines:
        m = PATTERN.search(ln)
        if not m:
            continue
        op = m.group("op").lower()
        addr = _norm_hex(m.group("addr"))
        val = _norm_hex(m.group("val"))
        out.append({
            "type": "read" if op == "r" else "write",
            "address": addr,
            "value": val
        })
    return out

def main():
    ap = argparse.ArgumentParser(
        description="Parse Android CAM-UTIL cam_io_{r,w}[_mb] logs and emit JSON with type/address/value."
    )
    ap.add_argument("input", nargs="?", help="Log file path. If omitted, read from stdin.")
    ap.add_argument("-o", "--output", help="Write JSON to this file instead of stdout.")
    ap.add_argument("--minify", action="store_true", help="Compact JSON (no pretty-print).")
    args = ap.parse_args()

    if args.input:
        text = Path(args.input).read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
    else:
        lines = sys.stdin.read().splitlines()

    entries = parse_lines(lines)
    data = json.dumps(entries, indent=None if args.minify else 2)

    if args.output:
        Path(args.output).write_text(data, encoding="utf-8")
    else:
        sys.stdout.write(data + ("\n" if not data.endswith("\n") else ""))

if __name__ == "__main__":
    main()
