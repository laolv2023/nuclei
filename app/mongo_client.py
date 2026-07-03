# -*- coding: utf-8 -*-
"""
MongoDB 操作层

复用 ZAP-Bridge V10.0 的 MongoDB 数据契约:
  - 集合名大驼峰 (TestingRun / TestingRunResult / TestingRunResultSummary / ApiInfo / SampleData)
  - _class 多态标识: com.akto.dto.testing.TestResult
  - apiInfoKey 外层必需字段
  - apiCollectionId int32 类型
  - testRunTime 耗时字段
"""
import time
import logging
from typing import List, Optional
from pymongo import MongoClient, ReturnDocument
from bson import ObjectId

logger = logging.getLogger("nuclei-bridge")


class AktoMongoClient:
    """Akto MongoDB 客户端"""

    def __init__(self, mongo_uri: str):
        self.client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
        self.db = self.client["akto"]

    def connect(self):
        """测试连接"""
        self.client.admin.command("ping")
        logger.info("MongoDB 连接成功 | db=akto")

    def claim_task(self, collection_id: int) -> Optional[dict]:
        """
        原子抢占任务。
        只抢占针对 NUCLEI_TARGET_COLLECTION_ID 的 SCHEDULED 任务，
        避免抢走 Akto 原生测试任务。
        """
        result = self.db.TestingRun.find_one_and_update(
            {
                "state": "SCHEDULED",
                "testingEndpoints.apiCollectionId": collection_id,
            },
            {"$set": {"state": "RUNNING"}},
            return_document=ReturnDocument.AFTER,
        )
        return result

    def create_summary(self, task_id, start_time: int) -> ObjectId:
        """初始化 TestingRunResultSummary"""
        summary_id = ObjectId()
        self.db.TestingRunResultSummary.insert_one({
            "_id": summary_id,
            "testRunId": task_id,
            "state": "RUNNING",
            "startTimestamp": start_time,
            "countIssues": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
        })
        return summary_id

    def complete_summary(self, summary_id, end_time: int, count_issues: dict):
        """更新 Summary 为 COMPLETED"""
        self.db.TestingRunResultSummary.update_one(
            {"_id": summary_id},
            {"$set": {
                "state": "COMPLETED",
                "endTimestamp": end_time,
                "countIssues": count_issues,
            }},
        )

    def complete_task(self, task_id, end_time: int, test_run_time: int):
        """更新 TestingRun 为 COMPLETED"""
        self.db.TestingRun.update_one(
            {"_id": task_id},
            {"$set": {
                "state": "COMPLETED",
                "endTimestamp": end_time,
                "testRunTime": test_run_time,
            }},
        )

    def get_api_endpoints(self, collection_id: int) -> List[dict]:
        """查询 ApiInfo 获取目标 API 列表"""
        cursor = self.db.ApiInfo.find({
            "_id.apiCollectionId": collection_id,
        })
        return list(cursor)

    def close(self):
        self.client.close()
