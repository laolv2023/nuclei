# -*- coding: utf-8 -*-
"""
Nuclei-Bridge 配置模块

从环境变量加载所有配置项，支持 Docker/K8s 部署。
所有配置在导入时即完成校验，配置错误时启动即失败（fail-fast）。
"""
import os
from urllib.parse import urlparse

# ── 版本 ──
__version__ = "2.1.0"

# ── 默认 HTTP 端口（不显示在 URL 中）──
_DEFAULT_HTTP_PORTS = (80, 443)


def _get_int_env(name: str, default: int, min_val: int = 0, max_val: int = 2**31 - 1) -> int:
    """安全读取 int 环境变量，带范围校验。配置错误抛 ValueError（含友好提示）。"""
    raw = os.getenv(name)
    if raw is None or raw == "":
        value = default
    else:
        try:
            value = int(raw)
        except (TypeError, ValueError):
            raise ValueError(
                f"环境变量 {name} 必须是整数，当前值: {raw!r}"
            )
    if value < min_val or value > max_val:
        raise ValueError(
            f"环境变量 {name}={value} 超出允许范围 [{min_val}, {max_val}]"
        )
    return value


def _get_str_env(name: str, default: str, allow_empty: bool = True) -> str:
    """安全读取 str 环境变量。"""
    value = os.getenv(name, default)
    if not allow_empty and not value:
        raise ValueError(f"环境变量 {name} 不能为空")
    return value


# ── MongoDB ──
MONGO_URI = _get_str_env("MONGO_URI", "mongodb://localhost:27017/akto")

# ── Nuclei 目标 Collection ID（必填，非0）──
NUCLEI_TARGET_COLLECTION_ID = _get_str_env("NUCLEI_TARGET_COLLECTION_ID", "0")

# ── 目标服务地址 ──
TARGET_SCHEME = _get_str_env("TARGET_SCHEME", "http")
TARGET_HOST = _get_str_env("TARGET_HOST", "localhost")
TARGET_PORT = _get_int_env("TARGET_PORT", 80, min_val=1, max_val=65535)

# ── Nuclei 扫描参数 ──
NUCLEI_PATH = _get_str_env("NUCLEI_PATH", "nuclei")
# 别名：NUCLEI_BIN（与 NUCLEI_PATH 等价，兼容不同命名习惯）
NUCLEI_BIN = NUCLEI_PATH
SCAN_TIMEOUT = _get_int_env("SCAN_TIMEOUT", 600, min_val=1)
REQUEST_TIMEOUT = _get_int_env("REQUEST_TIMEOUT", 10, min_val=1)
MAX_CONCURRENCY = _get_int_env("MAX_CONCURRENCY", 25, min_val=1, max_val=500)
POLL_INTERVAL = _get_int_env("POLL_INTERVAL", 5, min_val=1, max_val=3600)

# ── Nuclei 模板路径（逗号分隔，空则用默认）──
NUCLEI_TEMPLATES = _get_str_env("NUCLEI_TEMPLATES", "")

# ── Nuclei 严重级别过滤（逗号分隔）──
NUCLEI_SEVERITY = _get_str_env("NUCLEI_SEVERITY", "high,medium")

# ── 任务恢复：RUNNING 状态超时阈值（秒），超时则回收 ──
TASK_RUNNING_TIMEOUT = _get_int_env("TASK_RUNNING_TIMEOUT", 3600, min_val=60)

# ── 日志 ──
LOG_LEVEL = _get_str_env("LOG_LEVEL", "INFO")
LOG_JSON = _get_str_env("LOG_JSON", "false").lower() in ("1", "true", "yes", "on")

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

# ── 默认置信度 ──
DEFAULT_CONFIDENCE = "HIGH"
DEFAULT_CONFIDENCE_PERCENTAGE = 100
DEFAULT_PERCENTAGE_MATCH = 100


def sanitize_mongo_uri(uri: str) -> str:
    """脱敏 MongoDB URI，隐藏密码部分。用于日志输出。"""
    if not uri:
        return ""
    try:
        parsed = urlparse(uri)
        if parsed.password:
            # 替换密码为 ***
            netloc = f"{parsed.username}:***@" if parsed.username else "***@"
            if parsed.hostname:
                netloc += parsed.hostname
            if parsed.port:
                netloc += f":{parsed.port}"
            return parsed._replace(netloc=netloc).geturl()
    except Exception:
        # 解析失败时返回脱敏的原始串（移除可能的密码子串）
        if "://" in uri and "@" in uri:
            scheme = uri.split("://")[0]
            rest = uri.split("://", 1)[1]
            if "@" in rest:
                host_part = rest.split("@", 1)[1]
                return f"{scheme}://***@{host_part}"
    return uri


# 别名：mask_mongo_uri（与 sanitize_mongo_uri 等价）
mask_mongo_uri = sanitize_mongo_uri


def build_target_url(path: str) -> str:
    """
    构造目标 URL，支持 scheme + host + port。
    path 会确保以 / 开头；host 中的特殊字符会被 URL 编码。
    """
    if path is None:
        path = "/"
    if not path.startswith("/"):
        path = "/" + path
    port_str = f":{TARGET_PORT}" if TARGET_PORT not in _DEFAULT_HTTP_PORTS else ""
    return f"{TARGET_SCHEME}://{TARGET_HOST}{port_str}{path}"


def validate_config() -> None:
    """
    启动时校验关键配置。失败抛 ValueError。
    """
    if TARGET_SCHEME not in ("http", "https"):
        raise ValueError(
            f"TARGET_SCHEME 必须是 http 或 https，当前值: {TARGET_SCHEME!r}"
        )
    if not TARGET_HOST:
        raise ValueError("TARGET_HOST 不能为空")
    try:
        cid = int(NUCLEI_TARGET_COLLECTION_ID)
        if cid <= 0:
            raise ValueError
    except (TypeError, ValueError):
        raise ValueError(
            f"NUCLEI_TARGET_COLLECTION_ID 必须是正整数，当前值: {NUCLEI_TARGET_COLLECTION_ID!r}"
        )
