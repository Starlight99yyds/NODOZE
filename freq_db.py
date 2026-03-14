"""Event Frequency Database 生成器（对应论文 §VII-A）。

从 ndjson 历史日志中读取抽象后的依赖事件，
按 “主机 + 日窗口” 去重统计：
  - Freq(E)      := <SRC, DST, REL> 在多少 (host, day) 上出现
  - Freq_src_rel := <SRC, REL> 在多少 (host, day) 上出现
并写入 SQLite，供打分算法使用。
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Dict, Tuple

from events import DependencyEvent, iter_dependency_events_from_file

CONFIG_PATH = Path(__file__).resolve().parent / "config.json"


def load_config() -> dict:
    """从 config.json 加载配置，若不存在则返回空字典。"""
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def _parse_day(ts: str) -> str:
    """把 ISO8601 时间戳解析为 'YYYY-MM-DD'。"""
    if not ts:
        return "1970-01-01"
    try:
        d = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return d.date().isoformat()
    except Exception:
        return ts[:10]


def build_event_frequency_db(
    ndjson_path: str,
    sqlite_path: str = "event_freq.db",
) -> None:
    """从 ndjson 构建事件频率数据库（SQLite）。"""

    seen_triples: Dict[Tuple[str, str, str, str, str], bool] = {}
    seen_src_rel: Dict[Tuple[str, str, str, str], bool] = {}

    freq_event: Dict[Tuple[str, str, str], int] = defaultdict(int)
    freq_src_rel: Dict[Tuple[str, str], int] = defaultdict(int)

    for ev in iter_dependency_events_from_file(ndjson_path):
        assert isinstance(ev, DependencyEvent)
        day = _parse_day(ev.timestamp)

        triple_key = (ev.host, day, ev.src.id, ev.dst.id, ev.rel)
        if triple_key not in seen_triples:
            seen_triples[triple_key] = True
            freq_event[(ev.src.id, ev.dst.id, ev.rel)] += 1

        sr_key = (ev.host, day, ev.src.id, ev.rel)
        if sr_key not in seen_src_rel:
            seen_src_rel[sr_key] = True
            freq_src_rel[(ev.src.id, ev.rel)] += 1

    conn = sqlite3.connect(sqlite_path)
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS event_freq (
            src   TEXT NOT NULL,
            dst   TEXT NOT NULL,
            rel   TEXT NOT NULL,
            count INTEGER NOT NULL,
            PRIMARY KEY (src, dst, rel)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS event_freq_src_rel (
            src   TEXT NOT NULL,
            rel   TEXT NOT NULL,
            count INTEGER NOT NULL,
            PRIMARY KEY (src, rel)
        )
        """
    )
    cur.execute("DELETE FROM event_freq")
    cur.execute("DELETE FROM event_freq_src_rel")

    cur.executemany(
        "INSERT OR REPLACE INTO event_freq (src, dst, rel, count) VALUES (?, ?, ?, ?)",
        [(s, d, r, c) for (s, d, r), c in freq_event.items()],
    )
    cur.executemany(
        "INSERT OR REPLACE INTO event_freq_src_rel (src, rel, count) VALUES (?, ?, ?)",
        [(s, r, c) for (s, r), c in freq_src_rel.items()],
    )

    conn.commit()
    conn.close()


def main() -> None:
    cfg = load_config()
    parser = argparse.ArgumentParser(
        description="构建 Event Frequency Database（基于 ndjson 历史日志）"
    )
    parser.add_argument(
        "--ndjson",
        default=cfg.get("baseline_ndjson_path"),
        help="基线日志文件路径（可从 config.json 的 baseline_ndjson_path 读取）",
    )
    parser.add_argument(
        "--db",
        default=cfg.get("db_path", "event_freq.db"),
        help="输出 SQLite 数据库路径（可从 config.json 读取）",
    )
    args = parser.parse_args()

    if not args.ndjson:
        parser.error("请指定 --ndjson，或在 config.json 中设置 baseline_ndjson_path")
    print(f"从 {args.ndjson} 构建事件频率数据库 -> {args.db}")
    build_event_frequency_db(args.ndjson, args.db)
    print("完成。")


if __name__ == "__main__":
    main()

