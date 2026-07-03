# -*- coding: utf-8 -*-
"""
Nuclei-Bridge 主服务

轮询 Akto MongoDB，抢占 NUCLEI_TARGET_COLLECTION_ID 对应的 TestingRun 任务，
调用 Nuclei 执行批量扫描，结果写入 TestingRunResult。

生产级特性:
  - 信号安全关闭（handler 只设标志位）
  - 任务状态 try-finally 保证最终一致
  - 启动时回收僵尸 RUNNING 任务
  - MONGO_URI 脱敏日志
  - 版本号打印
"""
import signal
import sys
import time
import logging

from app.config import (
    MONGO_URI, NUCLEI_TARGET_COLLECTION_ID, TARGET_SCHEME, TARGET_HOST,
    TARGET_PORT, SCAN_TIMEOUT, REQUEST_TIMEOUT, MAX_CONCURRENCY,
    POLL_INTERVAL, NUCLEI_BIN, NUCLEI_TEMPLATES, NUCLEI_SEVERITY,
    LOG_LEVEL, LOG_JSON, build_target_url, validate_config, mask_mongo_uri,
    __version__,
)
from app.logger import setup_logging, get_logger
from app.mongo_client import AktoMongoClient
from app.nuclei_client import NucleiClient
from app.result_builder import build_result
from app.token_extractor import extract_token

logger = get_logger("nuclei-bridge")

# 僵尸任务超时回收阈值（秒）：超过此时间的 RUNNING 任务视为僵尸
_STALE_TASK_TIMEOUT = SCAN_TIMEOUT * 3 + 600


class NucleiBridgeService:
    """Nuclei-Bridge 主服务"""

    def __init__(self):
        self._running = True
        self._mongo: AktoMongoClient = None  # type: ignore[assignment]
        self._nuclei: NucleiClient = None  # type: ignore[assignment]
        self._collection_id = int(NUCLEI_TARGET_COLLECTION_ID)

    def start(self):
        """启动服务"""
        setup_logging(level=LOG_LEVEL, json_format=LOG_JSON)
        logger.info("=" * 60)
        logger.info("Nuclei-Bridge 启动 | version=%s", __version__)
        logger.info("=" * 60)
        logger.info("配置:")
        logger.info("  MongoDB:        %s", mask_mongo_uri(MONGO_URI))
        logger.info("  Collection ID:  %s", NUCLEI_TARGET_COLLECTION_ID)
        logger.info("  Target:         %s://%s:%d", TARGET_SCHEME, TARGET_HOST, TARGET_PORT)
        logger.info("  Scan Timeout:   %ds", SCAN_TIMEOUT)
        logger.info("  Concurrency:    %d", MAX_CONCURRENCY)
        logger.info("  Poll Interval:  %ds", POLL_INTERVAL)
        logger.info("  Templates:      %s", NUCLEI_TEMPLATES or "(default)")
        logger.info("  Severity:       %s", NUCLEI_SEVERITY)
        logger.info("=" * 60)

        # 启动前校验配置
        validate_config()

        # 初始化客户端
        self._mongo = AktoMongoClient(MONGO_URI)
        self._mongo.connect()

        self._nuclei = NucleiClient(
            nuclei_path=NUCLEI_BIN,
            request_timeout=REQUEST_TIMEOUT,
            scan_timeout=SCAN_TIMEOUT,
            max_concurrency=MAX_CONCURRENCY,
        )

        # 健康检查
        if not self._nuclei.health_check():
            logger.error("Nuclei 健康检查失败，退出")
            self._cleanup()
            sys.exit(1)

        # 启动时更新模板（非阻塞，失败不退出）
        self._nuclei.update_templates()

        # 回收僵尸任务
        self._mongo.recover_stale_tasks(self._collection_id, _STALE_TASK_TIMEOUT)

        # 注册信号（只设标志位，不调用非信号安全函数）
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        logger.info("Nuclei-Bridge 开始轮询任务")
        try:
            self._poll_loop()
        finally:
            self._cleanup()

    def _signal_handler(self, signum, frame):
        """信号处理器：只设置标志位（信号安全），由主循环检测并清理"""
        self._running = False
        # 注意：不在此调用 logger/kill_current_scan，避免死锁

    def _cleanup(self):
        """清理资源"""
        logger.info("正在清理资源...")
        if self._nuclei:
            self._nuclei.kill_current_scan()
        if self._mongo:
            self._mongo.close()
        logger.info("Nuclei-Bridge 已停止")

    def _poll_loop(self):
        """主轮询循环"""
        while self._running:
            try:
                task = self._mongo.claim_task(self._collection_id)
                if task:
                    logger.info("抢占任务 | task_id=%s", task.get("_id"))
                    self._process_task(task)
                else:
                    # 无任务时短暂 sleep
                    self._sleep(POLL_INTERVAL)
            except Exception as e:
                logger.error("轮询循环异常: %s", e, exc_info=True)
                self._sleep(POLL_INTERVAL)

    def _sleep(self, seconds: float):
        """可中断的 sleep（每秒检查 _running 标志）"""
        end = time.monotonic() + seconds
        while self._running and time.monotonic() < end:
            time.sleep(min(1.0, end - time.monotonic()))

    def _process_task(self, task: dict):
        """处理单个任务，try-finally 保证状态最终一致"""
        task_id = task.get("_id")
        start_time = int(time.time())
        summary_id = None

        try:
            # 创建 Summary
            summary_id = self._mongo.create_summary(task_id, start_time)

            # 获取 API 端点
            api_endpoints = self._mongo.get_api_endpoints(self._collection_id)
            logger.info("获取 API 端点 | count=%d", len(api_endpoints))

            if not api_endpoints:
                logger.warning("Collection %d 无 API 端点", self._collection_id)
                self._finalize_success(task_id, summary_id, start_time, [])
                return

            # 提取 Token
            token = self._extract_token_for_collection()
            if token:
                self._nuclei.set_auth_token(token)
                logger.info("已设置 Auth Token")
            else:
                self._nuclei.set_auth_token("")
                logger.info("未设置 Auth Token（匿名扫描）")

            # 构造 URL 列表 + url_to_api_key 映射
            urls, url_to_api_key = self._build_url_mapping(api_endpoints)
            if not urls:
                logger.warning("无有效 URL")
                self._finalize_success(task_id, summary_id, start_time, [])
                return

            # 执行批量扫描
            findings_by_url = self._nuclei.scan_batch(
                urls, templates=NUCLEI_TEMPLATES, severity=NUCLEI_SEVERITY
            )

            # 构造结果文档
            results = self._build_results(
                findings_by_url, task_id, summary_id, url_to_api_key
            )

            # 写入结果
            if results:
                inserted = self._mongo.insert_results(results)
                logger.info("写入测试结果 | inserted=%d", inserted)

            self._finalize_success(task_id, summary_id, start_time, results)

        except Exception as e:
            logger.error("任务处理失败 | task_id=%s error=%s", task_id, e, exc_info=True)
            self._finalize_failure(task_id, summary_id, start_time, str(e))

    def _extract_token_for_collection(self) -> str:
        """从 SampleData 提取 Token"""
        try:
            sample_doc = self._mongo.db.SampleData.find_one(
                {"apiCollectionId": self._collection_id}
            )
            if sample_doc:
                return extract_token(sample_doc) or ""
        except Exception as e:
            logger.warning("提取 Token 失败: %s", e)
        return ""

    def _build_url_mapping(self, api_endpoints: list):
        """构造 URL 列表和 url→api_key 映射"""
        urls = []
        url_to_api_key = {}
        for ep in api_endpoints:
            try:
                api_id = ep.get("_id", {})
                if not isinstance(api_id, dict):
                    continue
                url = api_id.get("url", "")
                method = api_id.get("method", "GET")
                if not url:
                    continue
                full_url = build_target_url(url)
                urls.append(full_url)
                url_to_api_key[full_url] = {"url": url, "method": method}
            except Exception as e:
                logger.debug("跳过异常端点: %s", e)
        return urls, url_to_api_key

    def _build_results(self, findings_by_url, task_id, summary_id, url_to_api_key):
        """构造结果文档列表"""
        results = []
        default_api_key = {"url": "", "method": "GET"}
        for matched_url, findings in findings_by_url.items():
            # 精确匹配 api_key
            api_key = url_to_api_key.get(matched_url, default_api_key)
            for finding in findings:
                try:
                    doc = build_result(
                        finding=finding,
                        task_id=task_id,
                        summary_id=summary_id,
                        api_collection_id=self._collection_id,
                        api_key=api_key,
                        url_to_api_key=url_to_api_key,
                    )
                    results.append(doc)
                except Exception as e:
                    logger.warning("构造结果文档失败: %s", e)
        return results

    def _finalize_success(self, task_id, summary_id, start_time, results):
        """任务成功收尾"""
        end_time = int(time.time())
        test_run_time = end_time - start_time
        try:
            # results 是 TestingRunResult 文档列表，从 severity 字段统计
            counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for r in (results if isinstance(results, list) else []):
                sev = r.get("severity", "LOW")
                counts[sev] = counts.get(sev, 0) + 1

            if summary_id:
                self._mongo.complete_summary(summary_id, end_time, counts)
            self._mongo.complete_task(task_id, end_time, test_run_time)
            logger.info("任务完成 | task_id=%s duration=%ds issues=%s",
                        task_id, test_run_time, counts)
        except Exception as e:
            logger.error("任务收尾失败 | task_id=%s error=%s", task_id, e)

    def _finalize_failure(self, task_id, summary_id, start_time, error_msg: str):
        """任务失败收尾"""
        end_time = int(time.time())
        test_run_time = end_time - start_time
        try:
            if summary_id:
                self._mongo.fail_summary(summary_id, end_time, error_msg)
            self._mongo.fail_task(task_id, end_time, error_msg)
            logger.error("任务失败 | task_id=%s duration=%ds error=%s",
                         task_id, test_run_time, error_msg[:200])
        except Exception as e:
            logger.error("任务失败收尾异常 | task_id=%s error=%s", task_id, e)


def main():
    service = NucleiBridgeService()
    service.start()


if __name__ == "__main__":
    main()
