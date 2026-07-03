# -*- coding: utf-8 -*-
"""
Nuclei-Bridge 主入口 — Shadow Worker 服务

核心流程:
  1. 连接 MongoDB 和 Nuclei
  2. 主循环: findOneAndUpdate 抢占任务 → 批量扫描 → 写回结果 → 更新状态
  3. 优雅关闭: SIGTERM/SIGINT → kill Nuclei 子进程 → 退出
"""
import signal
import sys
import time
import logging

from . import config
from .logger import setup_logging, get_logger
from .mongo_client import AktoMongoClient
from .nuclei_client import NucleiClient
from .result_builder import build_result_from_finding, count_by_severity, deduplicate_findings
from .token_extractor import fetch_latest_token_regex

logger = get_logger(__name__)


class NucleiBridgeService:
    """Nuclei-Bridge 影子 Worker 服务"""

    def __init__(self):
        self._mongo: AktoMongoClient | None = None
        self._nuclei: NucleiClient | None = None
        self._running = False

    def start(self):
        """启动服务"""
        setup_logging(config.LOG_LEVEL)

        logger.info("=" * 60)
        logger.info("Nuclei-Bridge 启动中...")
        logger.info("  MongoDB:  %s", config.MONGO_URI)
        logger.info("  Collection ID: %s", config.NUCLEI_TARGET_COLLECTION_ID)
        logger.info("  Target:   %s://%s:%s", config.TARGET_SCHEME, config.TARGET_HOST, config.TARGET_PORT)
        logger.info("  Templates: %s", config.DEFAULT_TEMPLATES)
        logger.info("  Scan timeout: %ds, Request timeout: %ds", config.SCAN_TIMEOUT, config.REQUEST_TIMEOUT)
        logger.info("=" * 60)

        # 1. 连接 MongoDB
        self._mongo = AktoMongoClient(config.MONGO_URI)
        try:
            self._mongo.connect()
        except Exception as e:
            logger.error("MongoDB 连接失败: %s", e)
            sys.exit(1)

        # 2. 初始化 Nuclei
        self._nuclei = NucleiClient(
            nuclei_path=config.NUCLEI_PATH,
            request_timeout=config.REQUEST_TIMEOUT,
            scan_timeout=config.SCAN_TIMEOUT,
            max_concurrency=config.MAX_CONCURRENCY,
        )
        if not self._nuclei.health_check():
            logger.error("Nuclei 健康检查失败，请确认 nuclei 已安装")
            sys.exit(1)

        # 3. 更新模板
        self._nuclei.update_templates()

        # 4. 注册信号处理器
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        # 5. 主循环
        self._running = True
        logger.info("Nuclei-Bridge 启动完成，进入主循环 (poll=%ds)", config.POLL_INTERVAL)

        while self._running:
            try:
                self._run_task_cycle()
            except Exception as e:
                logger.error("任务周期异常: %s", e, exc_info=True)
            time.sleep(config.POLL_INTERVAL)

        logger.info("Nuclei-Bridge 已停止")

    def _run_task_cycle(self):
        """单个任务周期"""
        collection_id = int(config.NUCLEI_TARGET_COLLECTION_ID)
        task = self._mongo.claim_task(collection_id)
        if not task:
            return

        task_id = task["_id"]
        start_time = int(time.time())
        logger.info("抢占任务 | task_id=%s collection_id=%s", task_id, collection_id)

        # 初始化 Summary
        summary_id = self._mongo.create_summary(task_id, start_time)

        # 查询 API 端点
        api_endpoints = self._mongo.get_api_endpoints(collection_id)
        if not api_endpoints:
            logger.warning("无 API 端点 | collection_id=%s", collection_id)
            self._mongo.complete_task(task_id, int(time.time()), 0)
            self._mongo.complete_summary(summary_id, int(time.time()), {"HIGH": 0, "MEDIUM": 0, "LOW": 0})
            return

        logger.info("API 端点数: %d", len(api_endpoints))

        # 构造目标 URL 列表
        urls = []
        url_to_api_key = {}
        for ep in api_endpoints:
            api_key = ep["_id"]
            path = api_key.get("url", "/")
            method = api_key.get("method", "GET")
            full_url = config.build_target_url(path)
            urls.append(full_url)
            url_to_api_key[full_url] = api_key

        # 提取 Auth Token（从第一个有 token 的端点获取）
        for ep in api_endpoints:
            api_key = ep["_id"]
            url = api_key.get("url", "/")
            method = api_key.get("method", "GET")
            token = fetch_latest_token_regex(self._mongo.db, collection_id, url, method)
            if token:
                self._nuclei.set_auth_token(token)
                logger.info("提取到 Auth Token | url=%s", url)
                break

        # 批量扫描
        scan_results = self._nuclei.scan_batch(
            urls, templates=config.DEFAULT_TEMPLATES
        )

        # 构造结果文档
        results_to_insert = []
        for matched_url, findings in scan_results.items():
            findings = deduplicate_findings(findings)
            # 找到对应的 api_info_key
            api_key = url_to_api_key.get(matched_url)
            if not api_key:
                # 尝试从 matched_url 中提取 path 来匹配
                for u, k in url_to_api_key.items():
                    if matched_url.endswith(k.get("url", "")):
                        api_key = k
                        break
            if not api_key:
                logger.debug("未找到匹配的 api_key | matched_url=%s", matched_url)
                api_key = {"apiCollectionId": collection_id, "url": matched_url, "method": "GET"}

            for finding in findings:
                result_doc = build_result_from_finding(
                    finding, api_key, task_id, summary_id, start_time
                )
                results_to_insert.append(result_doc)

        # 批量写入
        if results_to_insert:
            self._mongo.db.TestingRunResult.insert_many(results_to_insert)
            logger.info("写入结果 | count=%d", len(results_to_insert))

        # 更新 Summary 和 Task 状态
        end_time = int(time.time())
        count_issues = count_by_severity(results_to_insert)
        self._mongo.complete_summary(summary_id, end_time, count_issues)
        self._mongo.complete_task(task_id, end_time, end_time - start_time)
        logger.info(
            "任务完成 | task_id=%s findings=%d duration=%ds issues=%s",
            task_id, len(results_to_insert), end_time - start_time, count_issues,
        )

    def _signal_handler(self, signum, frame):
        """优雅关闭"""
        logger.info("收到信号 %s，准备优雅关闭...", signum)
        self._running = False
        if self._nuclei:
            self._nuclei.kill_current_scan()
