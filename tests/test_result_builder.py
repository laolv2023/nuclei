# -*- coding: utf-8 -*-
"""
result_builder 单元测试

覆盖:
  - build_result（基本结构/severity映射/字段缺失/精确匹配/后缀匹配）
  - count_by_severity
  - deduplicate_findings
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from bson import ObjectId
from app.result_builder import (
    build_result, count_by_severity, deduplicate_findings, _map_severity,
)


class TestMapSeverity(unittest.TestCase):
    def test_critical(self):
        self.assertEqual(_map_severity("critical"), "HIGH")

    def test_high(self):
        self.assertEqual(_map_severity("high"), "HIGH")

    def test_medium(self):
        self.assertEqual(_map_severity("medium"), "MEDIUM")

    def test_low(self):
        self.assertEqual(_map_severity("low"), "LOW")

    def test_info(self):
        self.assertEqual(_map_severity("info"), "LOW")

    def test_unknown(self):
        self.assertEqual(_map_severity("unknown"), "LOW")

    def test_none(self):
        self.assertEqual(_map_severity(None), "LOW")

    def test_empty(self):
        self.assertEqual(_map_severity(""), "LOW")

    def test_case_insensitive(self):
        self.assertEqual(_map_severity("HIGH"), "HIGH")
        self.assertEqual(_map_severity("High"), "HIGH")


class TestBuildResult(unittest.TestCase):
    def setUp(self):
        self.finding = {
            "template-id": "CVE-2024-1234",
            "template-path": "cves/2024/CVE-2024-1234.yaml",
            "matched-at": "http://target.com/api/v1/users",
            "info": {
                "severity": "high",
                "description": "SQL injection vulnerability",
            },
            "host": "target.com",
            "ip": "1.2.3.4",
            "type": "http",
            "curl-command": "curl -X GET http://target.com/api/v1/users",
        }
        self.api_key = {"url": "/api/v1/users", "method": "GET"}
        self.url_to_api_key = {
            "http://target.com/api/v1/users": self.api_key,
        }
        self.task_id = ObjectId()
        self.summary_id = ObjectId()
        self.collection_id = 123

    def test_basic_structure(self):
        result = build_result(
            self.finding, self.task_id, self.summary_id,
            self.collection_id, self.api_key, self.url_to_api_key
        )
        self.assertEqual(result["testRunId"], self.task_id)
        self.assertEqual(result["testRunResultSummaryId"], self.summary_id)
        self.assertEqual(result["apiInfoKey"]["apiCollectionId"], 123)
        self.assertEqual(result["apiInfoKey"]["method"], "GET")
        self.assertEqual(result["apiInfoKey"]["url"], "/api/v1/users")
        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["severity"], "HIGH")
        self.assertEqual(result["confidence"], "HIGH")
        self.assertEqual(result["source"], "NUCLEI")

    def test_class_field(self):
        """_class 字段必须是 com.akto.dto.testing.TestResult"""
        result = build_result(
            self.finding, self.task_id, self.summary_id,
            self.collection_id, self.api_key, self.url_to_api_key
        )
        self.assertEqual(result["_class"], "com.akto.dto.testing.TestResult")

    def test_severity_mapping_medium(self):
        self.finding["info"]["severity"] = "medium"
        result = build_result(
            self.finding, self.task_id, self.summary_id,
            self.collection_id, self.api_key, self.url_to_api_key
        )
        self.assertEqual(result["severity"], "MEDIUM")

    def test_severity_mapping_low(self):
        self.finding["info"]["severity"] = "low"
        result = build_result(
            self.finding, self.task_id, self.summary_id,
            self.collection_id, self.api_key, self.url_to_api_key
        )
        self.assertEqual(result["severity"], "LOW")

    def test_missing_fields(self):
        """空 finding 不应崩溃"""
        result = build_result(
            {}, self.task_id, self.summary_id,
            self.collection_id, self.api_key, self.url_to_api_key
        )
        self.assertEqual(result["severity"], "LOW")
        self.assertEqual(result["title"], "")  # template-id 为空
        self.assertEqual(result["matchedUrl"], "")

    def test_matched_url_exact(self):
        """精确匹配 url_to_api_key"""
        result = build_result(
            self.finding, self.task_id, self.summary_id,
            self.collection_id, self.api_key, self.url_to_api_key
        )
        self.assertEqual(result["apiInfoKey"]["url"], "/api/v1/users")
        self.assertEqual(result["apiInfoKey"]["method"], "GET")

    def test_matched_url_suffix(self):
        """后缀匹配（末尾斜杠差异）"""
        self.finding["matched-at"] = "http://target.com/api/v1/users/"
        result = build_result(
            self.finding, self.task_id, self.summary_id,
            self.collection_id, self.api_key, self.url_to_api_key
        )
        # 后缀匹配应找到 api_key
        self.assertEqual(result["apiInfoKey"]["url"], "/api/v1/users")

    def test_matched_url_no_match(self):
        """无匹配时用 default api_key（其 url 为 /api/v1/users）"""
        self.finding["matched-at"] = "http://other.com/unknown"
        result = build_result(
            self.finding, self.task_id, self.summary_id,
            self.collection_id, self.api_key, self.url_to_api_key
        )
        # 无匹配时回退到 default api_key
        self.assertEqual(result["apiInfoKey"]["url"], "/api/v1/users")

    def test_metadata(self):
        result = build_result(
            self.finding, self.task_id, self.summary_id,
            self.collection_id, self.api_key, self.url_to_api_key
        )
        self.assertEqual(result["metadata"]["template-id"], "CVE-2024-1234")
        self.assertEqual(result["metadata"]["host"], "target.com")
        self.assertEqual(result["metadata"]["ip"], "1.2.3.4")

    def test_percentage_fields(self):
        result = build_result(
            self.finding, self.task_id, self.summary_id,
            self.collection_id, self.api_key, self.url_to_api_key
        )
        self.assertEqual(result["percentageMatch"], 100)
        self.assertEqual(result["confidencePercentage"], 100)

    def test_collection_id_int_cast(self):
        """apiCollectionId 必须是 int"""
        result = build_result(
            self.finding, self.task_id, self.summary_id,
            "123", self.api_key, self.url_to_api_key  # 传字符串
        )
        self.assertEqual(result["apiInfoKey"]["apiCollectionId"], 123)
        self.assertIsInstance(result["apiInfoKey"]["apiCollectionId"], int)


class TestCountBySeverity(unittest.TestCase):
    def test_basic(self):
        findings = [
            {"info": {"severity": "high"}},
            {"info": {"severity": "high"}},
            {"info": {"severity": "medium"}},
            {"info": {"severity": "low"}},
        ]
        counts = count_by_severity(findings)
        self.assertEqual(counts["HIGH"], 2)
        self.assertEqual(counts["MEDIUM"], 1)
        self.assertEqual(counts["LOW"], 1)

    def test_empty(self):
        counts = count_by_severity([])
        self.assertEqual(counts["HIGH"], 0)
        self.assertEqual(counts["MEDIUM"], 0)
        self.assertEqual(counts["LOW"], 0)

    def test_unknown_severity(self):
        counts = count_by_severity([{"info": {"severity": "unknown"}}])
        self.assertEqual(counts["LOW"], 1)

    def test_missing_info(self):
        counts = count_by_severity([{}])
        self.assertEqual(counts["LOW"], 1)


class TestDeduplicateFindings(unittest.TestCase):
    def test_dedup(self):
        findings = [
            {"matched-at": "http://a.com/", "template-id": "CVE-1"},
            {"matched-at": "http://a.com/", "template-id": "CVE-1"},
            {"matched-at": "http://a.com/", "template-id": "CVE-2"},
        ]
        unique = deduplicate_findings(findings)
        self.assertEqual(len(unique), 2)

    def test_empty(self):
        self.assertEqual(deduplicate_findings([]), [])

    def test_empty_url_different_host(self):
        """空 matched-at 时不同 host 不应被误删"""
        findings = [
            {"matched-at": "", "template-id": "CVE-1", "host": "a.com"},
            {"matched-at": "", "template-id": "CVE-1", "host": "b.com"},
        ]
        unique = deduplicate_findings(findings)
        self.assertEqual(len(unique), 2)

    def test_matched_at_legacy_field(self):
        """兼容旧版 matched_at 字段"""
        findings = [
            {"matched_at": "http://a.com/", "template-id": "CVE-1"},
            {"matched_at": "http://a.com/", "template-id": "CVE-1"},
        ]
        unique = deduplicate_findings(findings)
        self.assertEqual(len(unique), 1)


if __name__ == "__main__":
    unittest.main()
