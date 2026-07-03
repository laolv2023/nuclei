# -*- coding: utf-8 -*-
"""
Nuclei CLI 封装

功能:
  - scan_url: 扫描单个 URL
  - scan_batch: 批量扫描 (-l list.txt)
  - update_templates: 更新 Nuclei 模板
  - health_check: 健康检查
  - kill_current_scan: 优雅关闭 (kill 子进程)
"""
import json
import os
import signal
import subprocess
import tempfile
import logging
from typing import Dict, List, Optional, Set

logger = logging.getLogger("nuclei-bridge")


class NucleiClient:
    """Nuclei CLI 封装（生产级）"""

    def __init__(
        self,
        nuclei_path: str = "nuclei",
        request_timeout: int = 10,
        scan_timeout: int = 600,
        max_concurrency: int = 25,
    ):
        self.nuclei_path = nuclei_path
        self.request_timeout = request_timeout
        self.scan_timeout = scan_timeout
        self.max_concurrency = max_concurrency
        self._auth_headers: List[str] = []
        self._current_process: Optional[subprocess.Popen] = None

    def set_auth_token(self, token: str, header_name: str = "Authorization"):
        """
        设置 Auth Token。
        token 是从 SampleData 正则提取的完整值，如 "Bearer xxx" 或 "xxx"。
        Nuclei -H 参数需要完整的 "Authorization: Bearer xxx" 格式。
        """
        if token:
            self._auth_headers = ["-H", f"{header_name}: {token}"]

    def scan_url(
        self,
        url: str,
        templates: List[str] = None,
        severity: str = "high,medium",
    ) -> List[Dict]:
        """扫描单个 URL"""
        cmd = [
            self.nuclei_path,
            "-u", url,
            "-json",
            "-severity", severity,
            "-nc",
            "-silent",
            "-timeout", str(self.request_timeout),
            "-c", str(self.max_concurrency),
            "-duc",
        ]
        if templates:
            for t in templates:
                cmd.extend(["-t", t])
        cmd.extend(self._auth_headers)

        stdout = self._run_with_timeout(cmd)
        if stdout is None:
            return []

        return self._parse_json_output(stdout)

    def scan_batch(
        self,
        urls: List[str],
        templates: List[str] = None,
        severity: str = "high,medium",
    ) -> Dict[str, List[Dict]]:
        """
        批量扫描多个 URL。
        使用 -l (list) 参数读取 URL 列表文件，比逐个串行快 10-50x。
        返回: {matched_url: [finding, ...], ...}
        """
        if not urls:
            return {}

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            for url in urls:
                f.write(f"{url}\n")
            url_list_path = f.name

        try:
            cmd = [
                self.nuclei_path,
                "-l", url_list_path,
                "-json",
                "-severity", severity,
                "-nc",
                "-silent",
                "-timeout", str(self.request_timeout),
                "-c", str(self.max_concurrency),
                "-duc",
            ]
            if templates:
                for t in templates:
                    cmd.extend(["-t", t])
            cmd.extend(self._auth_headers)

            logger.info(
                "Nuclei 批量扫描 | urls=%d templates=%s",
                len(urls), templates or "default",
            )

            stdout = self._run_with_timeout(cmd)
            if stdout is None:
                return {}

            seen: Set[str] = set()
            results: Dict[str, List[Dict]] = {}
            for finding in self._parse_json_output(stdout):
                matched_url = finding.get("matched-at", finding.get("matched_at", ""))
                template_id = finding.get("template-id", finding.get("templateID", ""))
                dedup_key = f"{matched_url}:{template_id}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                if matched_url not in results:
                    results[matched_url] = []
                results[matched_url].append(finding)

            return results

        finally:
            try:
                os.unlink(url_list_path)
            except OSError:
                pass

    def update_templates(self) -> bool:
        """更新 Nuclei 模板"""
        try:
            result = subprocess.run(
                [self.nuclei_path, "-update-templates"],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                logger.info("Nuclei 模板更新完成")
                return True
            logger.warning("Nuclei 模板更新失败 | rc=%d stderr=%s", result.returncode, result.stderr[:200])
            return False
        except Exception as e:
            logger.warning("Nuclei 模板更新异常: %s", e)
            return False

    def health_check(self) -> bool:
        """健康检查"""
        try:
            result = subprocess.run(
                [self.nuclei_path, "-version"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                version_line = result.stdout.strip().split("\n")[0] if result.stdout else "unknown"
                logger.info("Nuclei 健康检查通过 | %s", version_line)
                return True
            return False
        except Exception:
            return False

    def kill_current_scan(self):
        """优雅关闭：终止当前 Nuclei 子进程"""
        if self._current_process and self._current_process.poll() is None:
            logger.info("终止 Nuclei 子进程 (PID=%s)", self._current_process.pid)
            self._current_process.send_signal(signal.SIGTERM)
            try:
                self._current_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._current_process.kill()
                self._current_process.wait()
            finally:
                self._current_process = None

    def _run_with_timeout(self, cmd: List[str]) -> Optional[str]:
        """
        执行命令，支持总超时和优雅关闭。
        使用 Popen 替代 run，设置 _current_process 支持外部 kill。
        """
        try:
            self._current_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                stdout, _ = self._current_process.communicate(
                    timeout=self.scan_timeout
                )
                return stdout
            except subprocess.TimeoutExpired:
                self._current_process.kill()
                self._current_process.wait()
                logger.warning(
                    "Nuclei 扫描超时 | cmd=%s timeout=%ds",
                    cmd[0], self.scan_timeout,
                )
                return None
            finally:
                self._current_process = None
        except Exception as e:
            logger.error("Nuclei 扫描启动失败 | error=%s", e)
            return None

    @staticmethod
    def _parse_json_output(stdout: str) -> List[Dict]:
        """解析 Nuclei JSON 输出，跳过非 JSON 行"""
        findings = []
        for line in (stdout or "").strip().split("\n"):
            if not line or not line.startswith("{"):
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return findings
