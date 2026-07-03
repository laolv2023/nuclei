# -*- coding: utf-8 -*-
"""
mongo_client 单元测试

覆盖:
  - connect（成功/失败重试）
  - claim_task（找到/未找到）
  - create_summary / complete_summary / fail_summary
  - complete_task / fail_task
  - get_api_endpoints（含 cursor.close）
  - insert_results
  - recover_stale_tasks
  - close
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from unittest.mock import patch, MagicMock, call
from bson import ObjectId

from app.mongo_client import AktoMongoClient, _with_retry
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError, OperationFailure


class TestAktoMongoClient(unittest.TestCase):
    @patch("app.mongo_client.MongoClient")
    def setUp(self, mock_client_cls):
        self.mock_client = MagicMock()
        mock_client_cls.return_value = self.mock_client
        self.mock_db = MagicMock()
        self.mock_client.__getitem__.return_value = self.mock_db
        self.akto = AktoMongoClient("mongodb://localhost:27017/akto")

    def test_connect_success(self):
        self.akto.connect()
        self.mock_client.admin.command.assert_called_once_with("ping")

    @patch("app.mongo_client.time.sleep")
    def test_connect_retry_on_failure(self, mock_sleep):
        """连接失败应重试"""
        self.mock_client.admin.command.side_effect = [
            ConnectionFailure("conn fail"),
            True,  # 第二次成功
        ]
        self.akto.connect()
        self.assertEqual(self.mock_client.admin.command.call_count, 2)

    def test_claim_task_found(self):
        task = {"_id": "task1", "state": "SCHEDULED"}
        self.mock_db.TestingRun.find_one_and_update.return_value = task
        result = self.akto.claim_task(123)
        self.assertEqual(result, task)
        self.mock_db.TestingRun.find_one_and_update.assert_called_once()

    def test_claim_task_not_found(self):
        self.mock_db.TestingRun.find_one_and_update.return_value = None
        result = self.akto.claim_task(123)
        self.assertIsNone(result)

    def test_claim_task_filters_collection_id(self):
        """claim_task 必须按 collection_id 过滤"""
        self.mock_db.TestingRun.find_one_and_update.return_value = None
        self.akto.claim_task(456)
        args = self.mock_db.TestingRun.find_one_and_update.call_args
        query = args[0][0]
        self.assertEqual(query["testingEndpoints.apiCollectionId"], 456)
        self.assertEqual(query["state"], "SCHEDULED")

    def test_create_summary(self):
        self.mock_db.TestingRunResultSummary.insert_one.return_value = MagicMock()
        summary_id = self.akto.create_summary("task1", 1700000000)
        self.assertIsNotNone(summary_id)
        self.assertIsInstance(summary_id, ObjectId)
        self.mock_db.TestingRunResultSummary.insert_one.assert_called_once()

    def test_complete_summary(self):
        self.akto.complete_summary("summary1", 1700000100, {"HIGH": 2})
        self.mock_db.TestingRunResultSummary.update_one.assert_called_once()

    def test_complete_summary_idempotent(self):
        """complete_summary 幂等：只在非 COMPLETED 时更新"""
        self.akto.complete_summary(ObjectId(), 1700000100, {"HIGH": 2})
        args = self.mock_db.TestingRunResultSummary.update_one.call_args
        query = args[0][0]
        self.assertIn("state", query)
        self.assertEqual(query["state"], {"$ne": "COMPLETED"})

    def test_fail_summary(self):
        self.akto.fail_summary(ObjectId(), 1700000100, "scan error")
        self.mock_db.TestingRunResultSummary.update_one.assert_called_once()

    def test_complete_task(self):
        self.akto.complete_task("task1", 1700000100, 100)
        self.mock_db.TestingRun.update_one.assert_called_once()

    def test_complete_task_idempotent(self):
        self.akto.complete_task("task1", 1700000100, 100)
        args = self.mock_db.TestingRun.update_one.call_args
        query = args[0][0]
        self.assertEqual(query["state"], {"$ne": "COMPLETED"})

    def test_fail_task(self):
        self.akto.fail_task("task1", 1700000100, "error msg")
        self.mock_db.TestingRun.update_one.assert_called_once()

    def test_get_api_endpoints(self):
        endpoints = [{"_id": {"apiCollectionId": 123, "url": "/api", "method": "GET"}}]
        cursor = MagicMock()
        cursor.__iter__ = MagicMock(return_value=iter(endpoints))
        # find().batch_size() 返回 cursor（链式调用）
        self.mock_db.ApiInfo.find.return_value.batch_size.return_value = cursor
        result = self.akto.get_api_endpoints(123)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["_id"]["apiCollectionId"], 123)
        cursor.close.assert_called_once()

    def test_get_api_endpoints_empty(self):
        cursor = MagicMock()
        cursor.__iter__ = MagicMock(return_value=iter([]))
        self.mock_db.ApiInfo.find.return_value.batch_size.return_value = cursor
        result = self.akto.get_api_endpoints(123)
        self.assertEqual(result, [])

    def test_get_api_endpoints_exception(self):
        """查询异常应返回空列表，不抛出"""
        self.mock_db.ApiInfo.find.side_effect = OperationFailure("db error")
        result = self.akto.get_api_endpoints(123)
        self.assertEqual(result, [])

    def test_insert_results_success(self):
        results = [{"_id": ObjectId()}, {"_id": ObjectId()}]
        mock_res = MagicMock()
        mock_res.inserted_ids = [r["_id"] for r in results]
        self.mock_db.TestingRunResult.insert_many.return_value = mock_res
        count = self.akto.insert_results(results)
        self.assertEqual(count, 2)

    def test_insert_results_empty(self):
        count = self.akto.insert_results([])
        self.assertEqual(count, 0)

    def test_insert_results_partial_failure(self):
        """ordered=False 部分失败应返回 0（简化处理）"""
        self.mock_db.TestingRunResult.insert_many.side_effect = OperationFailure("dup key")
        count = self.akto.insert_results([{"_id": ObjectId()}])
        self.assertEqual(count, 0)

    def test_recover_stale_tasks(self):
        mock_res = MagicMock()
        mock_res.modified_count = 3
        self.mock_db.TestingRun.update_many.return_value = mock_res
        count = self.akto.recover_stale_tasks(123, 3600)
        self.assertEqual(count, 3)

    def test_recover_stale_tasks_none(self):
        mock_res = MagicMock()
        mock_res.modified_count = 0
        self.mock_db.TestingRun.update_many.return_value = mock_res
        count = self.akto.recover_stale_tasks(123, 3600)
        self.assertEqual(count, 0)

    def test_close(self):
        self.akto.close()
        self.mock_client.close.assert_called_once()


class TestWithRetry(unittest.TestCase):
    def test_success_first_try(self):
        calls = [0]
        def op():
            calls[0] += 1
            return "ok"
        result = _with_retry(op, "test")
        self.assertEqual(result, "ok")
        self.assertEqual(calls[0], 1)

    @patch("app.mongo_client.time.sleep")
    def test_retry_then_success(self, mock_sleep):
        calls = [0]
        def op():
            calls[0] += 1
            if calls[0] < 3:
                raise ConnectionFailure("fail")
            return "ok"
        result = _with_retry(op, "test")
        self.assertEqual(result, "ok")
        self.assertEqual(calls[0], 3)

    @patch("app.mongo_client.time.sleep")
    def test_retry_exhausted(self, mock_sleep):
        def op():
            raise ConnectionFailure("always fail")
        with self.assertRaises(ConnectionFailure):
            _with_retry(op, "test", max_retries=2)

    def test_non_retryable_error(self):
        """非瞬时错误不重试"""
        calls = [0]
        def op():
            calls[0] += 1
            raise OperationFailure("dup key")
        with self.assertRaises(OperationFailure):
            _with_retry(op, "test")
        self.assertEqual(calls[0], 1)


if __name__ == "__main__":
    unittest.main()
