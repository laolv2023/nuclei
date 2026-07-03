# -*- coding: utf-8 -*-
"""日志模块

显式配置 root logger，避免被其他库的 basicConfig 抢占。
支持 JSON 结构化日志（生产环境便于 ELK 采集）。
"""
import json
import logging
import sys
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    """JSON 结构化日志格式器"""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            log_entry["exc_info"] = self.formatException(record.exc_info)
        if record.__dict__.get("extra"):
            log_entry["extra"] = record.__dict__["extra"]
        return json.dumps(log_entry, ensure_ascii=False)


_TEXT_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


def setup_logging(level: str = "INFO", json_format: bool = False):
    """
    初始化日志配置。显式操作 root logger，确保幂等。

    Args:
        level: 日志级别字符串
        json_format: 是否使用 JSON 结构化日志（生产环境推荐）
    """
    log_level = getattr(logging, (level or "INFO").upper(), logging.INFO)

    root = logging.getLogger()
    # 清除可能存在的 handlers，确保我们的配置生效
    for h in list(root.handlers):
        root.removeHandler(h)

    handler = logging.StreamHandler(sys.stdout)
    if json_format:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter(_TEXT_FORMAT))
    root.addHandler(handler)
    root.setLevel(log_level)

    # 降低第三方库噪音
    logging.getLogger("pymongo").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
