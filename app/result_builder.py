# -*- coding: utf-8 -*-
"""
结果构造

将 Nuclei finding (JSON) 构造为 Akto TestingRunResult 文档。
"""
import time
import logging
from typing import Dict, List

from . import config

logger = logging.getLogger("nuclei-bridge")


def map_nuclei_to_akto_sub_type(template_path: str) -> str:
    """
    将 Nuclei 模板路径映射到 Akto TestCategory。
    """
    for prefix, akto_type in config.NUCLEI_TEMPLATE_TO_AKTO.items():
        if prefix in (template_path or ""):
            return akto_type
    return config.DEFAULT_AKTO_SUB_TYPE


def map_severity(nuclei_severity: str) -> str:
    """Nuclei severity → Akto severity"""
    return config.NUCLEI_SEVERITY_MAP.get(
        (nuclei_severity or "info").lower(), "LOW"
    )


def build_result_from_finding(
    finding: dict,
    api_info_key: dict,
    test_run_id,
    summary_id,
    start_time: int,
) -> dict:
    """
    将单个 Nuclei finding 构造为 Akto TestingRunResult 文档。

    对齐 ZAP-Bridge V10.0 的 BSON 数据契约:
      - 集合名: TestingRunResult (大驼峰)
      - _class: com.akto.dto.testing.TestResult
      - apiInfoKey 外层必需
      - vulnerable / confidence 父类字段
    """
    template_path = finding.get("template-path", finding.get("template-url", ""))
    template_id = finding.get("template-id", finding.get("templateID", ""))
    akto_sub_type = map_nuclei_to_akto_sub_type(template_path)
    severity = map_severity(finding.get("severity", "info"))

    return {
        "testRunId": test_run_id,
        "testRunResultSummaryId": summary_id,

        # 外层必需字段
        "apiInfoKey": api_info_key,
        "testSuperType": "DAST",
        "testSubType": akto_sub_type,

        # 时间戳
        "startTimestamp": start_time,
        "endTimestamp": int(time.time()),

        # 父类字段 (GenericTestResult)
        "vulnerable": True,
        "confidence": "HIGH",
        "confidencePercentage": 100,

        # 测试结果数组
        "testResults": [{
            "_class": config.AKTO_TEST_RESULT_CLASS,
            "message": finding.get("description", "") or template_id,
            "originalMessage": finding.get("matched-at", finding.get("matched_at", "")),
            "errors": [],
            "percentageMatch": 100,
        }],

        # 漏洞元数据
        "severity": severity,
        "originalMessage": finding.get("matched-at", ""),
    }


def count_by_severity(results: List[dict]) -> dict:
    """统计各严重级别的漏洞数量"""
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in results:
        sev = r.get("severity", "LOW")
        if sev in counts:
            counts[sev] += 1
        else:
            counts["LOW"] += 1
    return counts


def deduplicate_findings(findings: List[dict]) -> List[dict]:
    """
    扫描结果去重。
    同一 url + template-id 只保留一条。
    """
    seen = set()
    unique = []
    for f in findings:
        key = f"{f.get('matched-at', '')}:{f.get('template-id', '')}"
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
