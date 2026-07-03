# -*- coding: utf-8 -*-
"""
结果构造器

将 Nuclei JSON 输出转换为 Akto TestingRunResult 文档。
完全重写（不复用 ZAP-Bridge），适配 Nuclei v3 字段名:
  - matched-at (非 matched_at)
  - template-id (非 templateID)
  - info.severity
  - info.description
"""
import logging
from typing import List, Dict
from bson import ObjectId

logger = logging.getLogger("nuclei-bridge")

# Akto severity 映射
_SEVERITY_MAP = {
    "critical": "HIGH",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "LOW",
    "unknown": "LOW",
}

# 默认置信度/百分比（Nuclei 无此概念，固定值）
_DEFAULT_PERCENTAGE = 100


def _map_severity(nuclei_severity: str) -> str:
    """Nuclei severity → Akto severity"""
    if not nuclei_severity:
        return "LOW"
    return _SEVERITY_MAP.get(nuclei_severity.lower(), "LOW")


def _get_matched_url(finding: Dict) -> str:
    """兼容获取 matched URL（Nuclei v3 用 matched-at，旧版用 matched_at）"""
    return finding.get("matched-at") or finding.get("matched_at") or ""


def _get_template_id(finding: Dict) -> str:
    """兼容获取 template id"""
    return finding.get("template-id") or finding.get("templateID") or ""


def build_result(
    finding: Dict,
    task_id,
    summary_id,
    api_collection_id: int,
    api_key: dict,
    url_to_api_key: Dict[str, dict],
) -> Dict:
    """
    将单个 Nuclei finding 转换为 Akto TestingRunResult 文档。

    Args:
        finding: Nuclei JSON 输出
        task_id: TestingRun._id
        summary_id: TestingRunResultSummary._id
        api_collection_id: 目标 Collection ID
        api_key: ApiInfo._id 子文档 {apiCollectionId, method, url}
        url_to_api_key: {url: api_key} 映射，用于精确匹配
    """
    matched_url = _get_matched_url(finding)
    template_id = _get_template_id(finding)
    info = finding.get("info", {}) or {}
    severity = _map_severity(info.get("severity", "unknown"))
    description = info.get("description", "") or template_id

    # 精确匹配 api_key（优先精确，其次后缀匹配）
    matched_api_key = _match_api_key(matched_url, url_to_api_key, api_key)

    return {
        "_id": ObjectId(),
        "_class": "com.akto.dto.testing.TestResult",
        "apiInfoKey": {
            "apiCollectionId": int(api_collection_id),
            "method": matched_api_key.get("method", "GET"),
            "url": matched_api_key.get("url", matched_url),
            "version": 0,
        },
        "testRunId": task_id,
        "testRunResultSummaryId": summary_id,
        "originalApiInfoId": {
            "apiCollectionId": int(api_collection_id),
            "method": matched_api_key.get("method", "GET"),
            "url": matched_api_key.get("url", matched_url),
            "version": 0,
        },
        "message": description,
        "severity": severity,
        "confidence": severity,
        "title": template_id,
        "description": description,
        "matchedUrl": matched_url,
        "matchedUrlType": "URL",
        "matchedUrlMethod": matched_api_key.get("method", "GET"),
        "vulnerable": True,
        "percentageMatch": _DEFAULT_PERCENTAGE,
        "confidencePercentage": _DEFAULT_PERCENTAGE,
        "source": "NUCLEI",
        "metadata": {
            "template-id": template_id,
            "type": finding.get("type", ""),
            "host": finding.get("host", ""),
            "ip": finding.get("ip", ""),
            "curl-command": finding.get("curl-command", ""),
        },
    }


def _match_api_key(matched_url: str, url_to_api_key: Dict[str, dict],
                   default_api_key: dict) -> dict:
    """
    精确匹配 matched_url 对应的 api_key。
    精确失败时尝试后缀匹配（防 path 末尾斜杠差异）。
    """
    if not matched_url:
        return default_api_key
    # 精确匹配
    if matched_url in url_to_api_key:
        return url_to_api_key[matched_url]
    # 后缀匹配（去掉末尾斜杠后重试）
    normalized = matched_url.rstrip("/")
    for url, key in url_to_api_key.items():
        if url.rstrip("/") == normalized:
            return key
    return default_api_key


def count_by_severity(findings: List[Dict]) -> Dict[str, int]:
    """统计各 severity 数量"""
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        info = f.get("info", {}) or {}
        sev = _map_severity(info.get("severity", "unknown"))
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def deduplicate_findings(findings: List[Dict]) -> List[Dict]:
    """
    扫描结果去重。同一 url + template-id 只保留一条。
    空 matched-at 时用 host + template-id 防误删。
    """
    seen = set()
    unique = []
    for f in findings:
        matched = _get_matched_url(f)
        tpl = _get_template_id(f)
        host = f.get("host", f.get("ip", ""))
        if matched:
            key = f"{matched}:{tpl}"
        else:
            key = f"__no_url__:{host}:{tpl}"
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
