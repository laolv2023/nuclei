# -*- coding: utf-8 -*-
"""
token_extractor 单元测试

覆盖:
  - extract_token（正常/大小写/空/异常样本/非列表samples）
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from app.token_extractor import extract_token


class TestExtractToken(unittest.TestCase):
    def test_normal_bearer(self):
        doc = {"samples": ["GET /api HTTP/1.1\nAuthorization: Bearer abc123\n"]}
        self.assertEqual(extract_token(doc), "Bearer abc123")

    def test_normal_basic(self):
        doc = {"samples": ["Authorization: Basic dXNlcjpwYXNz\n"]}
        self.assertEqual(extract_token(doc), "Basic dXNlcjpwYXNz")

    def test_case_insensitive_header(self):
        """HTTP 头不区分大小写"""
        doc = {"samples": ["authorization: Bearer xyz\n"]}
        self.assertEqual(extract_token(doc), "Bearer xyz")

    def test_case_insensitive_mixed(self):
        doc = {"samples": ["AuThOrIzAtIoN: Token123\n"]}
        self.assertEqual(extract_token(doc), "Token123")

    def test_multiple_samples_first_wins(self):
        doc = {"samples": [
            "GET /a HTTP/1.1\n",
            "Authorization: Bearer first\n",
            "Authorization: Bearer second\n",
        ]}
        self.assertEqual(extract_token(doc), "Bearer first")

    def test_no_auth_header(self):
        doc = {"samples": ["GET /api HTTP/1.1\nHost: a.com\n"]}
        self.assertIsNone(extract_token(doc))

    def test_empty_samples(self):
        doc = {"samples": []}
        self.assertIsNone(extract_token(doc))

    def test_no_samples_key(self):
        doc = {}
        self.assertIsNone(extract_token(doc))

    def test_none_doc(self):
        self.assertIsNone(extract_token(None))

    def test_empty_doc(self):
        self.assertIsNone(extract_token({}))

    def test_samples_not_list(self):
        """samples 非列表不应崩溃"""
        doc = {"samples": "not a list"}
        self.assertIsNone(extract_token(doc))

    def test_samples_none(self):
        doc = {"samples": None}
        self.assertIsNone(extract_token(doc))

    def test_sample_not_string(self):
        """单个 sample 非字符串不应崩溃"""
        doc = {"samples": [123, None, {"x": 1}, "Authorization: Bearer ok\n"]}
        self.assertEqual(extract_token(doc), "Bearer ok")

    def test_empty_token_value(self):
        """Authorization: 后无值应跳过"""
        doc = {"samples": ["Authorization: \n", "Authorization: Bearer real\n"]}
        self.assertEqual(extract_token(doc), "Bearer real")

    def test_token_with_special_chars(self):
        doc = {"samples": ["Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIi\n"]}
        self.assertEqual(extract_token(doc), "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIi")


if __name__ == "__main__":
    unittest.main()
