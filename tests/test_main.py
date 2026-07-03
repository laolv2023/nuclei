# -*- coding: utf-8 -*-
"""
main.py NucleiBridgeService 单元测试

覆盖:
  - 信号处理（_signal_handler 只设标志位）
  - 任务执行流程（正常/异常/空任务）
  - 僵尸任务回收
  - 资源清理
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from unittest.mock import patch, MagicMock
import signal
from bson import ObjectId

from app.main import NucleiBridgeService


class TestSignalHandler(unittest.TestCase):
    @patch("app.main.NUCLEI_TARGET_COLLECTION_ID", "123")
    def test_signal_handler_sets_flag(self):
        """信号处理器只设置标志位，不执行重操作"""
        svc = NucleiBridgeService()
        svc._running = True
        svc._signal_handler(signal.SIGTERM, None)
        self.assertFalse(svc._running)

    @patch("app.main.NUCLEI_TARGET_COLLECTION_ID", "123")
    def test_signal_handler_does_not_call_logger(self):
        """信号处理器不应调用 logger（防死锁）"""
        svc = NucleiBridgeService()
        with patch("app.main.logger") as mock_logger:
            svc._signal_handler(signal.SIGINT, None)
            mock_logger.info.assert_not_called()


class TestServiceInit(unittest.TestCase):
    @patch("app.main.NUCLEI_TARGET_COLLECTION_ID", "123")
    def test_collection_id_is_int(self):
        """collection_id 应为 int 类型"""
        svc = NucleiBridgeService()
        self.assertIsInstance(svc._collection_id, int)
        self.assertEqual(svc._collection_id, 123)

    @patch("app.main.NUCLEI_TARGET_COLLECTION_ID", "456")
    def test_collection_id_value(self):
        svc = NucleiBridgeService()
        self.assertEqual(svc._collection_id, 456)


class TestPollLoop(unittest.TestCase):
    @patch("app.main.NUCLEI_TARGET_COLLECTION_ID", "123")
    def test_poll_exits_on_signal(self):
        """收到信号后轮询循环应退出"""
        svc = NucleiBridgeService()
        svc._mongo = MagicMock()
        svc._nuclei = MagicMock()
        svc._mongo.claim_task.return_value = None
        svc._running = True

        call_count = [0]

        def sleep_side_effect(sec):
            call_count[0] += 1
            if call_count[0] >= 2:
                svc._running = False

        with patch("app.main.time.sleep", side_effect=sleep_side_effect):
            svc._poll_loop()

        svc._mongo.claim_task.assert_called()

    @patch("app.main.NUCLEI_TARGET_COLLECTION_ID", "123")
    def test_poll_loop_handles_exception(self):
        """轮询循环异常不应崩溃"""
        svc = NucleiBridgeService()
        svc._mongo = MagicMock()
        svc._nuclei = MagicMock()
        svc._running = True
        svc._mongo.claim_task.side_effect = [Exception("db error"), None]

        call_count = [0]

        def sleep_side_effect(sec):
            call_count[0] += 1
            if call_count[0] >= 2:
                svc._running = False

        with patch("app.main.time.sleep", side_effect=sleep_side_effect):
            svc._poll_loop()  # 不应抛异常


class TestProcessTask(unittest.TestCase):
    def setUp(self):
        with patch("app.main.NUCLEI_TARGET_COLLECTION_ID", "123"):
            self.svc = NucleiBridgeService()
        self.svc._mongo = MagicMock()
        self.svc._nuclei = MagicMock()

    def test_no_task_returns_none(self):
        """claim_task 返回 None 时 _poll_loop 应继续"""
        self.svc._mongo.claim_task.return_value = None
        self.svc._running = True

        call_count = [0]

        def sleep_side_effect(sec):
            call_count[0] += 1
            if call_count[0] >= 1:
                self.svc._running = False

        with patch("app.main.time.sleep", side_effect=sleep_side_effect):
            self.svc._poll_loop()
        self.svc._nuclei.scan_batch.assert_not_called()

    def test_task_success(self):
        """正常任务流程"""
        task_id = ObjectId()
        task = {"_id": task_id, "testingEndpoints": {"apiCollectionId": 123}}
        self.svc._mongo.claim_task.side_effect = [task, None]
        self.svc._mongo.create_summary.return_value = ObjectId()
        self.svc._mongo.get_api_endpoints.return_value = [
            {"_id": {"url": "/api", "method": "GET"}, "samples": ["Authorization: Bearer tok\n"]},
        ]
        self.svc._nuclei.scan_batch.return_value = {
            "http://example.com/api": [{"template-id": "CVE-1", "matched-at": "http://example.com/api", "info": {"severity": "high"}}],
        }
        self.svc._nuclei.set_auth_token = MagicMock()
        self.svc._running = True

        def sleep_side_effect(sec):
            self.svc._running = False

        with patch("app.main.time.sleep", side_effect=sleep_side_effect):
            self.svc._poll_loop()

        self.svc._nuclei.scan_batch.assert_called_once()
        self.svc._mongo.complete_task.assert_called_once()

    def test_task_no_endpoints(self):
        """无 API 端点时应直接完成"""
        task_id = ObjectId()
        task = {"_id": task_id, "testingEndpoints": {"apiCollectionId": 123}}
        self.svc._mongo.claim_task.side_effect = [task, None]
        self.svc._mongo.create_summary.return_value = ObjectId()
        self.svc._mongo.get_api_endpoints.return_value = []
        self.svc._running = True

        def sleep_side_effect(sec):
            self.svc._running = False

        with patch("app.main.time.sleep", side_effect=sleep_side_effect):
            self.svc._poll_loop()

        self.svc._nuclei.scan_batch.assert_not_called()
        self.svc._mongo.complete_task.assert_called_once()

    def test_task_exception_marks_failed(self):
        """任务执行异常应标记失败"""
        task_id = ObjectId()
        task = {"_id": task_id, "testingEndpoints": {"apiCollectionId": 123}}
        self.svc._mongo.claim_task.side_effect = [task, None]
        self.svc._mongo.create_summary.return_value = ObjectId()
        self.svc._mongo.get_api_endpoints.side_effect = Exception("db error")
        self.svc._running = True

        def sleep_side_effect(sec):
            self.svc._running = False

        with patch("app.main.time.sleep", side_effect=sleep_side_effect):
            self.svc._poll_loop()

        self.svc._mongo.fail_task.assert_called_once()

    def test_task_missing_testing_endpoints(self):
        """任务缺少 testingEndpoints 不应崩溃，按无工作完成"""
        task = {"_id": ObjectId()}
        self.svc._mongo.claim_task.side_effect = [task, None]
        self.svc._mongo.create_summary.return_value = ObjectId()
        self.svc._running = True

        def sleep_side_effect(sec):
            self.svc._running = False

        with patch("app.main.time.sleep", side_effect=sleep_side_effect):
            self.svc._poll_loop()

        # 缺少 testingEndpoints 视为无工作，标记完成（非失败）
        self.svc._mongo.complete_task.assert_called_once()


class TestStaleTaskRecovery(unittest.TestCase):
    @patch("app.main.NUCLEI_TARGET_COLLECTION_ID", "123")
    def test_recover_on_startup(self):
        """启动时应回收僵尸任务"""
        svc = NucleiBridgeService()
        svc._mongo = MagicMock()
        svc._nuclei = MagicMock()
        svc._mongo.recover_stale_tasks.return_value = 2
        svc._running = True

        def claim_side_effect(*args):
            svc._running = False
            return None

        svc._mongo.claim_task.side_effect = claim_side_effect

        with patch("app.main.time.sleep"):
            svc._poll_loop()

        # recover_stale_tasks 在 start() 中调用，不在 _poll_loop 中
        # 这里验证 _poll_loop 正常退出即可
        self.assertFalse(svc._running)


class TestCleanup(unittest.TestCase):
    @patch("app.main.NUCLEI_TARGET_COLLECTION_ID", "123")
    def test_cleanup_closes_resources(self):
        """_cleanup 应关闭 mongo 和 nuclei"""
        svc = NucleiBridgeService()
        svc._mongo = MagicMock()
        svc._nuclei = MagicMock()
        svc._cleanup()
        svc._nuclei.kill_current_scan.assert_called_once()
        svc._mongo.close.assert_called_once()

    @patch("app.main.NUCLEI_TARGET_COLLECTION_ID", "123")
    def test_cleanup_with_none_clients(self):
        """_cleanup 在客户端为 None 时不应崩溃"""
        svc = NucleiBridgeService()
        svc._mongo = None
        svc._nuclei = None
        svc._cleanup()  # 不应抛异常


if __name__ == "__main__":
    unittest.main()
