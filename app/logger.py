# -*- coding: utf-8 -*-
"""日志模块"""
import logging
import sys


def setup_logging(level: str = "INFO"):
    """初始化日志配置"""
    log_level = getattr(logging, (level or "INFO").upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stdout,
    )


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
