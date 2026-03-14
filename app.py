"""
NODOZE Web 前端 API 服务。

提供配置管理、频率库构建、告警 Triage 等接口，
供前端界面调用。
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# 确保项目根目录在 Python 路径中
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))
os.chdir(PROJECT_ROOT)

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder="static", static_url_path="")
CORS(app)


@app.errorhandler(404)
@app.errorhandler(500)
@app.errorhandler(Exception)
def json_error(e):
    """确保所有错误都返回 JSON，避免前端解析 HTML 报错。"""
    code = 500
    if hasattr(e, "code"):
        code = e.code
    return jsonify({"ok": False, "error": str(e)}), code

CONFIG_PATH = PROJECT_ROOT / "config.json"
DATA_DIR = PROJECT_ROOT / "data"


def load_config() -> dict:
    """加载 config.json。"""
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_config(cfg: dict) -> None:
    """保存 config.json。"""
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


@app.route("/")
def index():
    """前端入口。"""
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/config", methods=["GET"])
def get_config():
    """获取当前配置。"""
    return jsonify(load_config())


CONFIG_KEYS = {
    "baseline_ndjson_path", "triage_ndjson_path", "db_path",
    "tau_l", "tau_m", "tau_d", "top_n", "window_lines",
}


@app.route("/api/config", methods=["POST"])
def update_config():
    """更新配置。"""
    data = request.get_json(silent=True) or {}
    cfg = load_config()
    for k, v in data.items():
        if k in CONFIG_KEYS:
            cfg[k] = v
    save_config(cfg)
    return jsonify(cfg)


@app.route("/api/datasets", methods=["GET"])
def list_datasets():
    """列出 data/ 目录下可用的 ndjson 文件。"""
    files = []
    if DATA_DIR.exists():
        for f in sorted(DATA_DIR.glob("*.ndjson")):
            files.append({
                "name": f.name,
                "path": str(f.relative_to(PROJECT_ROOT)).replace("\\", "/"),
            })
    return jsonify({"datasets": files})


@app.route("/api/build-db", methods=["POST"])
def build_db():
    """构建事件频率数据库。"""
    from freq_db import build_event_frequency_db

    cfg = load_config()
    baseline = cfg.get("baseline_ndjson_path")
    db_path = cfg.get("db_path", "event_freq.db")

    if not baseline:
        return jsonify({"ok": False, "error": "未配置 baseline_ndjson_path"}), 400

    full_baseline = PROJECT_ROOT / baseline
    if not full_baseline.exists():
        return jsonify({"ok": False, "error": f"基线文件不存在: {baseline}"}), 400

    try:
        build_event_frequency_db(str(full_baseline), str(PROJECT_ROOT / db_path))
        return jsonify({"ok": True, "message": "频率库构建完成"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/triage", methods=["POST"])
def run_triage_api():
    """执行告警 Triage，返回排序后的结果。"""
    from triage import run_triage

    cfg = load_config()
    ndjson_path = cfg.get("triage_ndjson_path")
    db_path = cfg.get("db_path", "event_freq.db")
    tau_l = cfg.get("tau_l", 5)
    tau_m = cfg.get("tau_m", 0.1)
    tau_d = cfg.get("tau_d")
    window_lines = cfg.get("window_lines", 500)
    top_n = cfg.get("top_n")

    # 允许请求体覆盖
    data = request.get_json(silent=True) or {}
    if data.get("triage_ndjson_path"):
        ndjson_path = data["triage_ndjson_path"]
    if data.get("top_n") is not None:
        top_n = data["top_n"]

    if not ndjson_path:
        return jsonify({"ok": False, "error": "未配置 triage_ndjson_path"}), 400

    full_ndjson = PROJECT_ROOT / ndjson_path
    full_db = PROJECT_ROOT / db_path

    if not full_ndjson.exists():
        return jsonify({"ok": False, "error": f"待检测文件不存在: {ndjson_path}"}), 400
    if not full_db.exists():
        return jsonify({"ok": False, "error": "频率数据库不存在，请先构建"}), 400

    try:
        results = run_triage(
            str(full_ndjson),
            str(full_db),
            tau_l=tau_l,
            tau_m=tau_m,
            tau_d=tau_d,
            window_lines=window_lines,
        )
        if top_n:
            results = results[:top_n]

        # 序列化为可 JSON 化的结构
        out = []
        for r in results:
            out.append({
                "alert_index": r.alert_index,
                "rule_id": r.rule_id,
                "rule_desc": r.rule_desc,
                "host": r.host,
                "aggregate_score": round(r.aggregate_score, 4),
                "path_count": r.path_count,
                "edges": [
                    {"src": s, "dst": d, "rel": rel}
                    for s, d, rel in r.concise_graph_edges
                ],
            })
        return jsonify({"ok": True, "results": out, "total": len(out)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
