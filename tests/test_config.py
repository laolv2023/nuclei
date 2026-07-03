# -*- coding: utf-8 -*-
"""
config 单元测试

覆盖:
  - build_target_url（端口默认/非默认/path处理）
  - mask_mongo_uri（含密码/无密码/异常）
  - validate_config（合法/非法scheme/空host/非法collection_id）
  - _get_int_env（合法/非法/范围）
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from unittest.mock import patch


class TestBuildTargetUrl(unittest.TestCase):
    @patch.dict(os.environ, {
        "TARGET_SCHEME": "http", "TARGET_HOST": "example.com", "TARGET_PORT": "80",
    }, clear=False)
    def test_default_port_80(self):
        from importlib import reload
        from app import config
        reload(config)
        url = config.build_target_url("/api/v1/users")
        self.assertEqual(url, "http://example.com/api/v1/users")

    @patch.dict(os.environ, {
        "TARGET_SCHEME": "https", "TARGET_HOST": "example.com", "TARGET_PORT": "8443",
    }, clear=False)
    def test_non_default_port(self):
        from importlib import reload
        from app import config
        reload(config)
        url = config.build_target_url("/api/v1/users")
        self.assertEqual(url, "https://example.com:8443/api/v1/users")

    @patch.dict(os.environ, {
        "TARGET_SCHEME": "http", "TARGET_HOST": "example.com", "TARGET_PORT": "80",
    }, clear=False)
    def test_path_without_slash(self):
        from importlib import reload
        from app import config
        reload(config)
        url = config.build_target_url("api/v1/users")
        self.assertEqual(url, "http://example.com/api/v1/users")

    @patch.dict(os.environ, {
        "TARGET_SCHEME": "http", "TARGET_HOST": "example.com", "TARGET_PORT": "80",
    }, clear=False)
    def test_path_none(self):
        from importlib import reload
        from app import config
        reload(config)
        url = config.build_target_url(None)
        self.assertEqual(url, "http://example.com/")


class TestMaskMongoUri(unittest.TestCase):
    def test_with_password(self):
        from app.config import mask_mongo_uri
        masked = mask_mongo_uri("mongodb://user:secret@host:27017/db")
        self.assertNotIn("secret", masked)
        self.assertIn("host", masked)
        self.assertIn("***", masked)

    def test_without_password(self):
        from app.config import mask_mongo_uri
        masked = mask_mongo_uri("mongodb://host:27017/db")
        self.assertEqual(masked, "mongodb://host:27017/db")

    def test_with_special_chars(self):
        from app.config import mask_mongo_uri
        masked = mask_mongo_uri("mongodb://user:p@ss:word@host:27017/db")
        self.assertNotIn("p@ss:word", masked)

    def test_empty(self):
        from app.config import mask_mongo_uri
        self.assertEqual(mask_mongo_uri(""), "")

    def test_invalid_uri(self):
        """无效 URI 不应崩溃"""
        from app.config import mask_mongo_uri
        masked = mask_mongo_uri("not-a-uri")
        self.assertIsNotNone(masked)


class TestValidateConfig(unittest.TestCase):
    @patch.dict(os.environ, {
        "TARGET_SCHEME": "http", "TARGET_HOST": "example.com",
        "NUCLEI_TARGET_COLLECTION_ID": "123",
    }, clear=False)
    def test_valid(self):
        from importlib import reload
        from app import config
        reload(config)
        config.validate_config()  # 不抛异常

    @patch.dict(os.environ, {
        "TARGET_SCHEME": "ftp", "TARGET_HOST": "example.com",
        "NUCLEI_TARGET_COLLECTION_ID": "123",
    }, clear=False)
    def test_invalid_scheme(self):
        from importlib import reload
        from app import config
        reload(config)
        with self.assertRaises(ValueError):
            config.validate_config()

    @patch.dict(os.environ, {
        "TARGET_SCHEME": "http", "TARGET_HOST": "",
        "NUCLEI_TARGET_COLLECTION_ID": "123",
    }, clear=False)
    def test_empty_host(self):
        from importlib import reload
        from app import config
        reload(config)
        with self.assertRaises(ValueError):
            config.validate_config()

    @patch.dict(os.environ, {
        "TARGET_SCHEME": "http", "TARGET_HOST": "example.com",
        "NUCLEI_TARGET_COLLECTION_ID": "0",
    }, clear=False)
    def test_zero_collection_id(self):
        from importlib import reload
        from app import config
        reload(config)
        with self.assertRaises(ValueError):
            config.validate_config()

    @patch.dict(os.environ, {
        "TARGET_SCHEME": "http", "TARGET_HOST": "example.com",
        "NUCLEI_TARGET_COLLECTION_ID": "abc",
    }, clear=False)
    def test_non_int_collection_id(self):
        from importlib import reload
        from app import config
        reload(config)
        with self.assertRaises(ValueError):
            config.validate_config()


class TestGetIntEnv(unittest.TestCase):
    def test_valid_int(self):
        from app.config import _get_int_env
        with patch.dict(os.environ, {"TEST_INT": "42"}):
            self.assertEqual(_get_int_env("TEST_INT", 0), 42)

    def test_default(self):
        from app.config import _get_int_env
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(_get_int_env("TEST_INT_ABSENT", 99), 99)

    def test_empty_string_uses_default(self):
        from app.config import _get_int_env
        with patch.dict(os.environ, {"TEST_INT_EMPTY": ""}):
            self.assertEqual(_get_int_env("TEST_INT_EMPTY", 99), 99)

    def test_invalid_raises(self):
        from app.config import _get_int_env
        with patch.dict(os.environ, {"TEST_INT_BAD": "abc"}):
            with self.assertRaises(ValueError):
                _get_int_env("TEST_INT_BAD", 0)

    def test_out_of_range_raises(self):
        from app.config import _get_int_env
        with patch.dict(os.environ, {"TEST_INT_RANGE": "0"}):
            with self.assertRaises(ValueError):
                _get_int_env("TEST_INT_RANGE", 0, min_val=1)

    def test_port_range(self):
        from app.config import _get_int_env
        with patch.dict(os.environ, {"TEST_PORT": "70000"}):
            with self.assertRaises(ValueError):
                _get_int_env("TEST_PORT", 80, min_val=1, max_val=65535)


if __name__ == "__main__":
    unittest.main()
