# -*- coding: utf-8 -*-
"""
Nuclei CLI 封装

功能:
  - scan_url: 扫描单个 URL
  - scan_batch: 批量扫描 (-l list.txt)
  - update_templates: 更新 Nuclei 模板
  - health_check: 健康检查
  - kill_current_scan: 优雅关闭 (kill 子进程)

生产级健壮性:
  - 子进程异常路径强制 kill + wait，防僵尸
  - 临时文件 0600 权限 + 异常路径清理
  - 流式读取 stdout 防 OOM
  - Auth Token sanitize 防换行注入
  - returncode + stderr 记录，故障可观测
"""
import json
import os
import signal
import subprocess
import tempfile
import logging
from typing import Dict, List, Optional

logger = logging.getLogger("nuclei-bridge")

# 单次扫描 stdout 最大缓冲（字节），超过则截断并告警
_MAX_STDOUT_BYTES = 64 * 1024 * 1024  # 64MB


def _sanitize_header_value(value: str) -> str:
    """ sanitize header 值，拒绝换行/回车（防 HTTP 头注入）。"""
    if value is None:
        return ""
    # 移除所有 CR/LF 及控制字符
    cleaned = "".join(c for c in value if c >= " " and c not in ("\x7f",))
    if cleaned != value:
        logger.warning("Auth Token 含非法字符，已过滤")
    return cleaned


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
        会 sanitize 换行符防 HTTP 头注入。
        """
        if token:
            safe_token = _sanitize_header_value(token)
            safe_header = _sanitize_header_value(header_name)
            if safe_token and safe_header:
                self._auth_headers = ["-H", f"{safe_header}: {safe_token}"]
            else:
                logger.warning("Auth Token sanitize 后为空，忽略")
                self._auth_headers = []
        else:
            self._auth_headers = []

    def _build_base_cmd(self, severity: str = "high,medium") -> List[str]:
        """构造 Nuclei 公共参数（DRY：scan_url/scan_batch 共用）。"""
        cmd = [
            self.nuclei_path,
            "-json",
            "-severity", severity,
            "-nc",
            "-silent",
            "-timeout", str(self.request_timeout),
            "-c", str(self.max_concurrency),
            "-duc",
        ]
        cmd.extend(self._auth_headers)
        return cmd

    def scan_url(
        self,
        url: str,
        templates: Optional[List[str]] = None,
        severity: str = "high,medium",
    ) -> List[Dict]:
        """扫描单个 URL"""
        cmd = self._build_base_cmd(severity) + ["-u", url]
        if templates:
            for t in templates:
                cmd.extend(["-t", t])

        stdout = self._run_with_timeout(cmd)
        if stdout is None:
            return []

        return self._parse_json_output(stdout)

    def scan_batch(
        self,
        urls: List[str],
        templates: Optional[List[str]] = None,
        severity: str = "high,medium",
    ) -> Dict[str, List[Dict]]:
        """
        批量扫描 (-l list.txt)。
        返回 {matched_url: [findings]} 字典，已按 url+template-id 去重。
        """
        if not urls:
            return {}

        # 去重 + 限长，防超大列表
        unique_urls = list(dict.fromkeys(urls))  # 保序去重
        if len(unique_urls) > 10000:
            logger.warning("URL 列表过大 (%d)，截断为 10000", len(unique_urls))
            unique_urls = unique_urls[:10000]

        # 写入临时文件，权限 0600
        fd, url_list_path = tempfile.mkstemp(suffix=".txt", prefix="nuclei_urls_")
        try:
            os.chmod(url_list_path, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write("\n".join(unique_urls))

            cmd = self._build_base_cmd(severity) + ["-l", url_list_path]
            if templates:
                for t in templates:
                    cmd.extend(["-t", t])

            stdout = self._run_with_timeout(cmd)
            if stdout is None:
                return {}

            findings = self._parse_json_output(stdout)
            # 去重
            findings = deduplicate_findings_inline(findings)

            results: Dict[str, List[Dict]] = {}
            for finding in findings:
                matched_url = finding.get("matched-at", finding.get("matched_at", ""))
                if not matched_url:
                    continue
                results.setdefault(matched_url, []).append(finding)
            return results

        except Exception as e:
            logger.error("Nuclei 批量扫描异常: %s", e, exc_info=True)
            return {}
        finally:
            try:
                os.unlink(url_list_path)
            except OSError:
                pass

    def health_check(self) -> bool:
        """健康检查"""
        try:
            result = subprocess.run(
                [self.nuclei_path, "-version"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                logger.info("Nuclei 健康检查通过 | version=%s",
                            (result.stdout or "").strip().split("\n")[0])
                return True
            logger.warning("Nuclei 健康检查失败 | rc=%d stderr=%s",
                           result.returncode, (result.stderr or "")[:200])
            return False
        except FileNotFoundError:
            logger.error("Nuclei 可执行文件未找到: %s", self.nuclei_path)
            return False
        except subprocess.TimeoutExpired:
            logger.error("Nuclei 健康检查超时")
            return False
        except Exception as e:
            logger.error("Nuclei 健康检查异常: %s", e)
            return False

    def update_templates(self) -> bool:
        """
        更新 Nuclei 模板。启动时调用一次，后续不自动更新。
        """
        try:
            result = subprocess.run(
                [self.nuclei_path, "-update-templates"],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0:
                logger.info("Nuclei 模板更新完成")
                return True
            logger.warning("Nuclei 模板更新失败 | rc=%d stderr=%s",
                           result.returncode, (result.stderr or "")[:200])
            return False
        except Exception as e:
            logger.warning("Nuclei 模板更新异常: %s", e)
            return False

    def kill_current_scan(self):
        """
        优雅关闭 — kill 正在运行的 Nuclei 子进程。
        先 SIGTERM，超时再 SIGKILL。
        """
        proc = self._current_process
        if proc is None:
            return
        if proc.poll() is not None:
            self._current_process = None
            return

        logger.info("终止 Nuclei 子进程 (PID=%s)", proc.pid)
        try:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                logger.warning("SIGTERM 后 10s 未退出，发送 SIGKILL")
                proc.kill()
                proc.wait(timeout=5)
        except Exception as e:
            logger.error("终止子进程异常: %s", e)
            try:
                proc.kill()
            except Exception:
                pass
        finally:
            self._current_process = None

    def _run_with_timeout(self, cmd: List[str]) -> Optional[str]:
        """
        执行 Nuclei 命令，带总超时。
        流式读取 stdout 防止 OOM，超过 _MAX_STDOUT_BYTES 截断。
        异常路径强制 kill + wait 子进程。
        返回 stdout 字符串，失败返回 None。
        """
        logger.info("执行 Nuclei | cmd=%s", _mask_cmd_for_log(cmd))
        proc = None
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self._current_process = proc

            # 流式读取 stdout，限制大小
            chunks: List[str] = []
            total = 0
            truncated = False
            assert proc.stdout is not None
            for line in proc.stdout:
                total += len(line)
                if total > _MAX_STDOUT_BYTES:
                    truncated = True
                    logger.warning("Nuclei stdout 超过 %d 字节，截断",
                                   _MAX_STDOUT_BYTES)
                    break
                chunks.append(line)

            try:
                _, stderr = proc.communicate(timeout=max(1, self.scan_timeout))
            except subprocess.TimeoutExpired:
                logger.warning("Nuclei 扫描超时 | timeout=%ds", self.scan_timeout)
                proc.kill()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
                return None

            rc = proc.returncode
            if rc != 0:
                logger.error("Nuclei 退出码非0 | rc=%d stderr=%s",
                             rc, (stderr or "")[:500])
            if truncated:
                logger.warning("Nuclei 输出被截断，结果可能不完整")

            return "".join(chunks)

        except FileNotFoundError as e:
            logger.error("Nuclei 可执行文件未找到: %s", e)
            return None
        except Exception as e:
            logger.error("Nuclei 扫描启动失败 | error=%s", e, exc_info=True)
            return None
        finally:
            # 确保子进程被回收
            if proc is not None and proc.poll() is None:
                try:
                    proc.kill()
                    proc.wait(timeout=5)
                except Exception:
                    pass
            self._current_process = None

    @staticmethod
    def _parse_json_output(stdout: str) -> List[Dict]:
        """
        解析 Nuclei JSON 输出（每行一个 JSON 对象）。
        跳过非 JSON 行（如 Nuclei 的 banner/warning）。
        """
        findings: List[Dict] = []
        if not stdout:
            return findings
        for line in stdout.split("\n"):
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    findings.append(obj)
            except json.JSONDecodeError:
                continue
        return findings


def _mask_cmd_for_log(cmd: List[str]) -> str:
    """日志中脱敏 cmd（隐藏 -H 后的 token 值）。"""
    masked = []
    i = 0
    while i < len(cmd):
        if cmd[i] == "-H" and i + 1 < len(cmd):
            masked.append("-H")
            masked.append("***")
            i += 2
        else:
            masked.append(cmd[i])
            i += 1
    return " ".join(masked)


def deduplicate_findings_inline(findings: List[Dict]) -> List[Dict]:
    """
    扫描结果去重。同一 url + template-id 只保留一条。
    空 matched-at 时用 template-id + ip 补充 key 防误删。
    """
    seen = set()
    unique = []
    for f in findings:
        matched = f.get("matched-at", f.get("matched_at", ""))
        tpl = f.get("template-id", f.get("templateID", ""))
        host = f.get("host", f.get("ip", ""))
        if matched:
            key = f"{matched}:{tpl}"
        else:
            # 空 url 时用 host+template 防误去重
            key = f"__no_url__:{host}:{tpl}"
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
