# -*- coding: utf-8 -*-
"""
mongo_client 单元测试
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from unittest.mock import patch, MagicMock
from app.mongo_client import AktoMongoClient


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

    def test_create_summary(self):
        self.mock_db.TestingRunResultSummary.insert_one.return_value = MagicMock()
        summary_id = self.akto.create_summary("task1", 1700000000)
        self.assertIsNotNone(summary_id)
        self.mock_db.TestingRunResultSummary.insert_one.assert_called_once()

    def test_complete_summary(self):
        self.akto.complete_summary("summary1", 1700000100, {"HIGH": 2})
        self.mock_db.TestingRunResultSummary.update_one.assert_called_once()

    def test_complete_task(self):
        self.akto.complete_task("task1", 1700000100, 100)
        self.mock_db.TestingRun.update_one.assert_called_once()

    def test_get_api_endpoints(self):
        endpoints = [{"_id": {"apiCollectionId": 123, "url": "/api", "method": "GET"}}]
        cursor = MagicMock()
        cursor.__iter__ = MagicMock(return_value=iter(endpoints))
        self.mock_db.ApiInfo.find.return_value = cursor
        result = self.akto.get_api_endpoints(123)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["_id"]["apiCollectionId"], 123)

    def test_close(self):
        self.akto.close()
        self.mock_client.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
