FROM python:3.11-slim

LABEL maintainer="nuclei-bridge"
LABEL version="2.1.0"

# 安全更新 + 安装依赖（--no-install-recommends 减小体积）
# 合并 RUN 层减少镜像层数
RUN apt-get update \
    && apt-get install -y --no-install-recommends wget unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 安装 Nuclei（固定版本，可重复构建）
ARG NUCLEI_VERSION=3.3.7
RUN wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -O /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

WORKDIR /app

# 先复制依赖文件，利用 Docker 层缓存
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码
COPY app/ ./app/

# 创建非 root 用户运行（安全最佳实践）
RUN useradd -r -s /bin/false nuclei \
    && mkdir -p /home/nuclei/.config/nuclei \
    && chown -R nuclei:nuclei /home/nuclei /app
USER nuclei

# 预下载 Nuclei 模板（构建时一次，运行时不再更新）
RUN nuclei -update-templates 2>/dev/null || true

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

CMD ["python", "-m", "app.main"]
