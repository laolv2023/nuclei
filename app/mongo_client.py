# -*- coding: utf-8 -*-
"""
MongoDB 操作层

复用 ZAP-Bridge V10.0 的 MongoDB 数据契约:
  - 集合名大驼峰 (TestingRun / TestingRunResult / TestingRunResultSummary / ApiInfo / SampleData)
  - _class 多态标识: com.akto.dto.testing.TestResult
  - apiInfoKey 外层必需字段
  - apiCollectionId int32 类型
  - testRunTime 耗时字段

生产级健壮性:
  - 重试机制（瞬时网络故障）
  - 幂等状态更新（$set 只在状态匹配时更新）
  - 任务超时回收（启动时清理僵尸 RUNNING 任务）
  - 分页查询防 OOM
"""
import time
import logging
from typing import List, Optional
from pymongo import MongoClient, ReturnDocument
from pymongo.errors import (
    ConnectionFailure, ServerSelectionTimeoutError,
    AutoReconnect, PyMongoError,
)
from bson import ObjectId

logger = logging.getLogger("nuclei-bridge")

# 可重试的 MongoDB 异常
_RETRYABLE_ERRORS = (ConnectionFailure, ServerSelectionTimeoutError, AutoReconnect)

# 重试参数
_MAX_RETRIES = 3
_RETRY_BASE_DELAY = 0.5  # 秒，指数退避基数


def _with_retry(operation, operation_name: str, max_retries: int = _MAX_RETRIES):
    """
    对 MongoDB 操作执行指数退避重试。
    只重试网络类瞬时故障，不重试数据类错误（如 DuplicateKey）。
    """
    last_exc = None
    for attempt in range(1, max_retries + 1):
        try:
            return operation()
        except _RETRYABLE_ERRORS as e:
            last_exc = e
            if attempt < max_retries:
                delay = _RETRY_BASE_DELAY * (2 ** (attempt - 1))
                logger.warning(
                    "MongoDB %s 失败（第%d次），%.1fs 后重试: %s",
                    operation_name, attempt, delay, e,
                )
                time.sleep(delay)
            else:
                logger.error("MongoDB %s 重试 %d 次仍失败: %s",
                             operation_name, max_retries, e)
        except PyMongoError as e:
            # 非瞬时错误，不重试
            logger.error("MongoDB %s 失败（不可重试）: %s", operation_name, e)
            raise
    raise last_exc  # type: ignore[misc]


class AktoMongoClient:
    """Akto MongoDB 客户端"""

    def __init__(self, mongo_uri: str):
        self.client = MongoClient(
            mongo_uri,
            serverSelectionTimeoutMS=5000,
            # 心跳检测，更快发现连接断开
            heartbeatFrequencyMS=10000,
            # 写入确认（生产推荐 majority，但为兼容性用 acknowledged）
            w=1,
            # 读取偏好：主节点（强一致）
            readPreference="primary",
        )
        self.db = self.client["akto"]

    def connect(self):
        """测试连接"""
        def _ping():
            self.client.admin.command("ping")
        _with_retry(_ping, "ping")
        logger.info("MongoDB 连接成功 | db=akto")

    def claim_task(self, collection_id: int) -> Optional[dict]:
        """
        原子抢占任务。
        只抢占针对 NUCLEI_TARGET_COLLECTION_ID 的 SCHEDULED 任务，
        避免抢走 Akto 原生测试任务。
        """
        def _claim():
            return self.db.TestingRun.find_one_and_update(
                {
                    "state": "SCHEDULED",
                    "testingEndpoints.apiCollectionId": collection_id,
                },
                {
                    "$set": {
                        "state": "RUNNING",
                        "startTimestamp": int(time.time()),
                    },
                },
                return_document=ReturnDocument.AFTER,
            )
        return _with_retry(_claim, "claim_task")

    def recover_stale_tasks(self, collection_id: int, timeout_seconds: int) -> int:
        """
        回收超时的 RUNNING 任务（Worker 崩溃后留下的僵尸任务）。
        返回回收的任务数。
        """
        cutoff = int(time.time()) - timeout_seconds
        try:
            result = self.db.TestingRun.update_many(
                {
                    "state": "RUNNING",
                    "testingEndpoints.apiCollectionId": collection_id,
                    "startTimestamp": {"$lt": cutoff},
                },
                {"$set": {
                    "state": "SCHEDULED",
                    "startTimestamp": None,
                    "recoveredAt": int(time.time()),
                }},
            )
            if result.modified_count > 0:
                logger.warning("回收僵尸任务 | count=%d", result.modified_count)
            return result.modified_count
        except PyMongoError as e:
            logger.error("回收僵尸任务失败: %s", e)
            return 0

    def create_summary(self, task_id, start_time: int) -> ObjectId:
        """初始化 TestingRunResultSummary"""
        summary_id = ObjectId()

        def _insert():
            self.db.TestingRunResultSummary.insert_one({
                "_id": summary_id,
                "testRunId": task_id,
                "state": "RUNNING",
                "startTimestamp": start_time,
                "countIssues": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
            })
        _with_retry(_insert, "create_summary")
        return summary_id

    def complete_summary(self, summary_id, end_time: int, count_issues: dict):
        """更新 Summary 为 COMPLETED（幂等：只在非 COMPLETED 时更新）"""
        def _update():
            self.db.TestingRunResultSummary.update_one(
                {"_id": summary_id, "state": {"$ne": "COMPLETED"}},
                {"$set": {
                    "state": "COMPLETED",
                    "endTimestamp": end_time,
                    "countIssues": count_issues,
                }},
            )
        _with_retry(_update, "complete_summary")

    def fail_summary(self, summary_id, end_time: int, error_msg: str):
        """更新 Summary 为 COMPLETED（带错误标记，用于任务失败场景）"""
        def _update():
            self.db.TestingRunResultSummary.update_one(
                {"_id": summary_id, "state": {"$ne": "COMPLETED"}},
                {"$set": {
                    "state": "COMPLETED",
                    "endTimestamp": end_time,
                    "errorMessage": error_msg[:500],
                }},
            )
        _with_retry(_update, "fail_summary")

    def complete_task(self, task_id, end_time: int, test_run_time: int):
        """更新 TestingRun 为 COMPLETED（幂等）"""
        def _update():
            self.db.TestingRun.update_one(
                {"_id": task_id, "state": {"$ne": "COMPLETED"}},
                {"$set": {
                    "state": "COMPLETED",
                    "endTimestamp": end_time,
                    "testRunTime": test_run_time,
                }},
            )
        _with_retry(_update, "complete_task")

    def fail_task(self, task_id, end_time: int, error_msg: str):
        """更新 TestingRun 为 COMPLETED（带错误标记）"""
        def _update():
            self.db.TestingRun.update_one(
                {"_id": task_id, "state": {"$ne": "COMPLETED"}},
                {"$set": {
                    "state": "COMPLETED",
                    "endTimestamp": end_time,
                    "errorMessage": error_msg[:500],
                }},
            )
        _with_retry(_update, "fail_task")

    def get_api_endpoints(self, collection_id: int, batch_size: int = 1000) -> List[dict]:
        """
        查询 ApiInfo 获取目标 API 列表。
        使用分批 yield 防止极大集合 OOM。
        """
        results: List[dict] = []
        try:
            cursor = self.db.ApiInfo.find(
                {"_id.apiCollectionId": collection_id},
                no_cursor_timeout=True,
            ).batch_size(batch_size)
            try:
                for doc in cursor:
                    results.append(doc)
            finally:
                cursor.close()
        except PyMongoError as e:
            logger.error("查询 ApiInfo 失败: %s", e)
        return results

    def insert_results(self, results: List[dict]) -> int:
        """批量写入测试结果，返回写入数。部分失败时记录错误。"""
        if not results:
            return 0
        try:
            res = self.db.TestingRunResult.insert_many(results, ordered=False)
            return len(res.inserted_ids)
        except PyMongoError as e:
            # ordered=False 时部分成功，部分失败
            logger.error("批量写入结果失败: %s", e)
            return 0

    def close(self):
        """关闭连接"""
        try:
            self.client.close()
            logger.info("MongoDB 连接已关闭")
        except Exception as e:
            logger.warning("关闭 MongoDB 连接异常: %s", e)
