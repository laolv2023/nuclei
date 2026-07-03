# -*- coding: utf-8 -*-
"""
result_builder 单元测试
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from app.result_builder import (
    map_nuclei_to_akto_sub_type, map_severity,
    build_result_from_finding, count_by_severity, deduplicate_findings,
)


class TestMapNucleiToAkto(unittest.TestCase):
    def test_cves_mapping(self):
        self.assertEqual(map_nuclei_to_akto_sub_type("cves/2024/CVE-2024-1234.yaml"), "SM")

    def test_vulnerabilities_mapping(self):
        self.assertEqual(map_nuclei_to_akto_sub_type("vulnerabilities/sql-injection.yaml"), "INJ")

    def test_exposures_mapping(self):
        self.assertEqual(map_nuclei_to_akto_sub_type("exposures/config.yaml"), "EDE")

    def test_unknown_template(self):
        self.assertEqual(map_nuclei_to_akto_sub_type("unknown/"), "SM")

    def test_empty(self):
        self.assertEqual(map_nuclei_to_akto_sub_type(""), "SM")


class TestMapSeverity(unittest.TestCase):
    def test_critical(self):
        self.assertEqual(map_severity("critical"), "HIGH")

    def test_high(self):
        self.assertEqual(map_severity("high"), "HIGH")

    def test_medium(self):
        self.assertEqual(map_severity("medium"), "MEDIUM")

    def test_low(self):
        self.assertEqual(map_severity("low"), "LOW")

    def test_info(self):
        self.assertEqual(map_severity("info"), "LOW")

    def test_unknown(self):
        self.assertEqual(map_severity("unknown"), "LOW")

    def test_none(self):
        self.assertEqual(map_severity(None), "LOW")


class TestBuildResult(unittest.TestCase):
    def setUp(self):
        self.finding = {
            "template-id": "CVE-2024-1234",
            "template-path": "cves/2024/CVE-2024-1234.yaml",
            "matched-at": "http://target.com/api/v1/users",
            "severity": "high",
            "description": "SQL injection vulnerability",
        }
        self.api_key = {"apiCollectionId": 123, "url": "/api/v1/users", "method": "GET"}

    def test_basic_structure(self):
        result = build_result_from_finding(
            self.finding, self.api_key, "task1", "summary1", 1700000000
        )
        self.assertEqual(result["testRunId"], "task1")
        self.assertEqual(result["testRunResultSummaryId"], "summary1")
        self.assertEqual(result["apiInfoKey"], self.api_key)
        self.assertEqual(result["testSuperType"], "DAST")
        self.assertEqual(result["testSubType"], "SM")
        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["confidence"], "HIGH")

    def test_test_results_class(self):
        result = build_result_from_finding(
            self.finding, self.api_key, "task1", "summary1", 1700000000
        )
        self.assertEqual(result["testResults"][0]["_class"], "com.akto.dto.testing.TestResult")

    def test_severity_mapping(self):
        self.finding["severity"] = "medium"
        result = build_result_from_finding(
            self.finding, self.api_key, "task1", "summary1", 1700000000
        )
        self.assertEqual(result["severity"], "MEDIUM")

    def test_missing_fields(self):
        result = build_result_from_finding(
            {}, self.api_key, "task1", "summary1", 1700000000
        )
        self.assertEqual(result["testSubType"], "SM")
        self.assertEqual(result["severity"], "LOW")


class TestCountBySeverity(unittest.TestCase):
    def test_basic(self):
        results = [
            {"severity": "HIGH"},
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
            {"severity": "LOW"},
        ]
        counts = count_by_severity(results)
        self.assertEqual(counts["HIGH"], 2)
        self.assertEqual(counts["MEDIUM"], 1)
        self.assertEqual(counts["LOW"], 1)

    def test_empty(self):
        counts = count_by_severity([])
        self.assertEqual(counts["HIGH"], 0)

    def test_unknown_severity(self):
        counts = count_by_severity([{"severity": "UNKNOWN"}])
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


if __name__ == "__main__":
    unittest.main()
