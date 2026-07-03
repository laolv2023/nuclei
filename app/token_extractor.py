# -*- coding: utf-8 -*-
"""
Token 提取器

从 Akto SampleData 中提取 Authorization Token。
支持大小写不敏感的 HTTP 头匹配，防御性处理异常样本。
"""
import re
import logging
from typing import Optional

logger = logging.getLogger("nuclei-bridge")

# 大小写不敏感匹配 Authorization 头，捕获行尾完整值
# \S+ 只匹配第一个单词（如 "Bearer"），改为 [^\r\n]+ 捕获整行剩余内容
_AUTH_PATTERN = re.compile(r"Authorization:\s*([^\r\n]+)", re.IGNORECASE)


def extract_token(sample_doc: dict) -> Optional[str]:
    """
    从 SampleData 文档中提取 Authorization Token。

    Args:
        sample_doc: Akto SampleData 文档

    Returns:
        Token 字符串（如 "Bearer xxx"），无则 None
    """
    if not sample_doc:
        return None

    samples = sample_doc.get("samples")
    # 防御性：samples 必须是列表
    if not isinstance(samples, list):
        logger.debug("SampleData.samples 非列表类型: %s", type(samples).__name__)
        return None
    if not samples:
        return None

    for sample in samples:
        if not isinstance(sample, str):
            continue
        # 大小写不敏感搜索
        match = _AUTH_PATTERN.search(sample)
        if match:
            token = match.group(1).strip()
            if token:
                logger.debug("提取到 Authorization Token")
                return token

    logger.debug("SampleData 中未找到 Authorization Token")
    return None
