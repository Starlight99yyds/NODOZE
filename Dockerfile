# NODOZE - 告警 Triage Web 服务
FROM python:3.11-slim

WORKDIR /app

# 安装依赖
COPY requirements-docker.txt .
RUN pip install --no-cache-dir -r requirements-docker.txt

# 复制应用代码（不含 PyETWkit、.git 等，由 .dockerignore 排除）
COPY app.py config.json ./
COPY events.py freq_db.py graph.py scoring.py triage.py ./
COPY static/ ./static/
COPY data/ ./data/

# 可选：复制数据生成脚本
COPY scripts/ ./scripts/

EXPOSE 5000

# 生产环境建议使用 gunicorn，开发可用 flask run
ENV FLASK_APP=app.py
CMD ["python", "-m", "flask", "run", "--host=0.0.0.0", "--port=5000"]
