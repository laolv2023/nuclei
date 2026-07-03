# -*- coding: utf-8 -*-
"""
Nuclei-Bridge 配置模块

从环境变量加载所有配置项，支持 Docker/K8s 部署。
"""
import os
import logging

logger = logging.getLogger("nuclei-bridge")

# ── MongoDB ──
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/akto")

# ── Nuclei 目标 Collection ID（必填）──
NUCLEI_TARGET_COLLECTION_ID = os.getenv("NUCLEI_TARGET_COLLECTION_ID", "0")

# ── 目标服务地址 ──
TARGET_SCHEME = os.getenv("TARGET_SCHEME", "http")
TARGET_HOST = os.getenv("TARGET_HOST", "localhost")
TARGET_PORT = int(os.getenv("TARGET_PORT", "80"))

# ── Nuclei 扫描参数 ──
NUCLEI_PATH = os.getenv("NUCLEI_PATH", "nuclei")
SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "600"))
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "10"))
MAX_CONCURRENCY = int(os.getenv("MAX_CONCURRENCY", "25"))
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "5"))

# ── 日志 ──
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# ── 扫描模板 ──
_DEFAULT_TEMPLATES_STR = os.getenv(
    "DEFAULT_TEMPLATES",
    "cves/,misconfiguration/,exposures/,default-logins/"
)
DEFAULT_TEMPLATES = [t.strip() for t in _DEFAULT_TEMPLATES_STR.split(",") if t.strip()]

# ── Nuclei 模板路径 → Akto TestCategory 映射 ──
# Akto 硬编码枚举: XSS, INJ, SM, SSRF, EDE (GlobalEnums.java 源码实证)
NUCLEI_TEMPLATE_TO_AKTO = {
    "cves/":              "SM",
    "vulnerabilities/":   "INJ",
    "misconfiguration/":  "SM",
    "exposures/":         "EDE",
    "default-logins/":    "INJ",
    "dns/":               "SM",
    "takeovers/":         "SM",
    "technologies/":      "SM",
    "tokens/":            "EDE",
    "files/":             "EDE",
}

# ── Nuclei 严重级别 → Akto severity ──
NUCLEI_SEVERITY_MAP = {
    "critical": "HIGH",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "low":      "LOW",
    "info":     "LOW",
}

# ── 默认 Akto 分类（未匹配时的兜底）──
DEFAULT_AKTO_SUB_TYPE = "SM"

# ── Akto Java 类名（MongoDB _class 字段）──
AKTO_TEST_RESULT_CLASS = "com.akto.dto.testing.TestResult"


def build_target_url(path: str) -> str:
    """构造目标 URL，支持 scheme + host + port"""
    port_str = f":{TARGET_PORT}" if TARGET_PORT not in (80, 443) else ""
    return f"{TARGET_SCHEME}://{TARGET_HOST}{port_str}{path}"
