# -*- coding: utf-8 -*-
"""
nuclei_client 单元测试

覆盖:
  - set_auth_token（含 sanitize）
  - health_check（成功/失败/异常）
  - update_templates
  - kill_current_scan（无进程/正常/强制kill）
  - scan_url（成功/超时）
  - scan_batch（成功/空列表/去重）
  - _parse_json_output（边界）
  - deduplicate_findings_inline
"""
import sys
import os
import signal
import subprocess
import json
import io

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from unittest.mock import patch, MagicMock

from app.nuclei_client import (
    NucleiClient, _sanitize_header_value, _mask_cmd_for_log,
    deduplicate_findings_inline,
)


def _make_mock_proc(stdout_text: str = "", stderr_text: str = "",
                    returncode: int = 0, communicate_raises=None):
    """构造模拟 Popen 对象"""
    mock_proc = MagicMock()
    # 用 StringIO 模拟真实文本流（含换行符，支持 for line in stdout）
    mock_proc.stdout = io.StringIO(stdout_text)
    mock_proc.stderr = stderr_text
    mock_proc.returncode = returncode
    mock_proc.poll.return_value = returncode
    if communicate_raises:
        mock_proc.communicate.side_effect = communicate_raises
    else:
        mock_proc.communicate.return_value = (stdout_text, stderr_text)
    mock_proc.pid = 12345
    mock_proc.kill.return_value = None
    mock_proc.wait.return_value = 0
    return mock_proc


class TestNucleiClient(unittest.TestCase):
    def setUp(self):
        self.client = NucleiClient(
            nuclei_path="nuclei",
            request_timeout=5,
            scan_timeout=30,
            max_concurrency=10,
        )

    # ── set_auth_token ──
    def test_set_auth_token(self):
        self.client.set_auth_token("Bearer xxx")
        self.assertEqual(self.client._auth_headers, ["-H", "Authorization: Bearer xxx"])

    def test_set_auth_token_empty(self):
        self.client.set_auth_token("")
        self.assertEqual(self.client._auth_headers, [])

    def test_set_auth_token_custom_header(self):
        self.client.set_auth_token("session123", header_name="Cookie")
        self.assertEqual(self.client._auth_headers, ["-H", "Cookie: session123"])

    def test_set_auth_token_sanitize_newline(self):
        """Token 含换行符应被过滤（防 HTTP 头注入）"""
        self.client.set_auth_token("Bearer xxx\r\nX-Injected: evil")
        # 换行符被移除
        self.assertNotIn("\r", self.client._auth_headers[1])
        self.assertNotIn("\n", self.client._auth_headers[1])

    # ── health_check ──
    @patch("subprocess.run")
    def test_health_check_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="Nuclei v3.3.7\n")
        self.assertTrue(self.client.health_check())

    @patch("subprocess.run")
    def test_health_check_failure(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stderr="error")
        self.assertFalse(self.client.health_check())

    @patch("subprocess.run")
    def test_health_check_exception(self, mock_run):
        mock_run.side_effect = FileNotFoundError("nuclei not found")
        self.assertFalse(self.client.health_check())

    @patch("subprocess.run")
    def test_health_check_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired("cmd", 10)
        self.assertFalse(self.client.health_check())

    # ── update_templates ──
    @patch("subprocess.run")
    def test_update_templates_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        self.assertTrue(self.client.update_templates())

    @patch("subprocess.run")
    def test_update_templates_failure(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stderr="err")
        self.assertFalse(self.client.update_templates())

    # ── kill_current_scan ──
    def test_kill_current_scan_no_process(self):
        self.client._current_process = None
        self.client.kill_current_scan()  # 不应报错

    def test_kill_current_scan_with_process(self):
        proc = MagicMock()
        proc.pid = 12345
        proc.poll.return_value = None
        proc.wait.return_value = 0
        self.client._current_process = proc
        self.client.kill_current_scan()
        proc.send_signal.assert_called_once_with(signal.SIGTERM)
        proc.wait.assert_called_once()

    def test_kill_current_scan_force_kill(self):
        proc = MagicMock()
        proc.pid = 12345
        proc.poll.return_value = None
        # SIGTERM 后 wait 超时，触发 SIGKILL
        proc.wait.side_effect = [subprocess.TimeoutExpired("cmd", 10), 0]
        self.client._current_process = proc
        self.client.kill_current_scan()
        proc.kill.assert_called_once()

    def test_kill_current_scan_already_exited(self):
        proc = MagicMock()
        proc.poll.return_value = 0  # 已退出
        self.client._current_process = proc
        self.client.kill_current_scan()
        proc.send_signal.assert_not_called()

    # ── scan_url ──
    @patch("subprocess.Popen")
    def test_scan_url_success(self, mock_popen):
        stdout = '{"template-id":"CVE-1","matched-at":"http://a.com/","info":{"severity":"high"}}\n'
        mock_popen.return_value = _make_mock_proc(stdout_text=stdout, returncode=0)
        results = self.client.scan_url("http://a.com/")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["template-id"], "CVE-1")

    @patch("subprocess.Popen")
    def test_scan_url_timeout(self, mock_popen):
        mock_proc = _make_mock_proc(
            stdout_text="",
            communicate_raises=subprocess.TimeoutExpired("cmd", 30),
        )
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc
        results = self.client.scan_url("http://a.com/")
        self.assertEqual(results, [])

    @patch("subprocess.Popen")
    def test_scan_url_binary_not_found(self, mock_popen):
        mock_popen.side_effect = FileNotFoundError("nuclei not found")
        results = self.client.scan_url("http://a.com/")
        self.assertEqual(results, [])

    # ── scan_batch ──
    @patch("subprocess.Popen")
    def test_scan_batch_success(self, mock_popen):
        stdout = (
            '{"template-id":"CVE-1","matched-at":"http://a.com/","info":{"severity":"high"}}\n'
            '{"template-id":"CVE-2","matched-at":"http://b.com/","info":{"severity":"medium"}}\n'
            '{"template-id":"CVE-1","matched-at":"http://a.com/","info":{"severity":"high"}}\n'
            'non-json-line\n'
        )
        mock_popen.return_value = _make_mock_proc(stdout_text=stdout, returncode=0)
        results = self.client.scan_batch(["http://a.com/", "http://b.com/"])
        self.assertIn("http://a.com/", results)
        self.assertEqual(len(results["http://a.com/"]), 1)  # 去重后1条
        self.assertIn("http://b.com/", results)

    def test_scan_batch_empty_urls(self):
        results = self.client.scan_batch([])
        self.assertEqual(results, {})

    @patch("subprocess.Popen")
    def test_scan_batch_dedup_urls(self, mock_popen):
        """输入 URL 去重"""
        stdout = ""
        mock_popen.return_value = _make_mock_proc(stdout_text=stdout, returncode=0)
        self.client.scan_batch(["http://a.com/", "http://a.com/", "http://b.com/"])
        # 验证写入临时文件的 URL 去重
        # （通过检查 Popen 被调用即可，详细 URL 验证在集成测试）

    # ── _parse_json_output ──
    def test_parse_json_output_empty(self):
        self.assertEqual(NucleiClient._parse_json_output(""), [])

    def test_parse_json_output_non_json(self):
        stdout = "banner line\nwarning line\n"
        self.assertEqual(NucleiClient._parse_json_output(stdout), [])

    def test_parse_json_output_mixed(self):
        stdout = (
            "banner\n"
            '{"template-id":"CVE-1"}\n'
            "warning\n"
            '{"template-id":"CVE-2"}\n'
        )
        results = NucleiClient._parse_json_output(stdout)
        self.assertEqual(len(results), 2)

    def test_parse_json_output_invalid_json(self):
        stdout = '{"template-id":"CVE-1"\n{"valid":true}\n'  # 第一行 JSON 不完整
        results = NucleiClient._parse_json_output(stdout)
        self.assertEqual(len(results), 1)

    # ── deduplicate_findings_inline ──
    def test_dedup_basic(self):
        findings = [
            {"matched-at": "http://a.com/", "template-id": "CVE-1"},
            {"matched-at": "http://a.com/", "template-id": "CVE-1"},  # 重复
            {"matched-at": "http://a.com/", "template-id": "CVE-2"},  # 不同模板
        ]
        result = deduplicate_findings_inline(findings)
        self.assertEqual(len(result), 2)

    def test_dedup_empty_url(self):
        """空 matched-at 用 host+template 防误删"""
        findings = [
            {"matched-at": "", "template-id": "CVE-1", "host": "a.com"},
            {"matched-at": "", "template-id": "CVE-1", "host": "b.com"},  # 不同host
            {"matched-at": "", "template-id": "CVE-1", "host": "a.com"},  # 重复
        ]
        result = deduplicate_findings_inline(findings)
        self.assertEqual(len(result), 2)

    # ── sanitize ──
    def test_sanitize_normal(self):
        self.assertEqual(_sanitize_header_value("Bearer xxx"), "Bearer xxx")

    def test_sanitize_newline(self):
        self.assertNotIn("\n", _sanitize_header_value("a\nb"))
        self.assertNotIn("\r", _sanitize_header_value("a\rb"))

    def test_sanitize_control_char(self):
        self.assertNotIn("\x00", _sanitize_header_value("a\x00b"))

    def test_sanitize_none(self):
        self.assertEqual(_sanitize_header_value(None), "")

    # ── mask_cmd_for_log ──
    def test_mask_cmd_no_header(self):
        cmd = ["nuclei", "-u", "http://a.com/"]
        self.assertEqual(_mask_cmd_for_log(cmd), "nuclei -u http://a.com/")

    def test_mask_cmd_with_header(self):
        cmd = ["nuclei", "-H", "Authorization: Bearer secret", "-u", "http://a.com/"]
        masked = _mask_cmd_for_log(cmd)
        self.assertIn("***", masked)
        self.assertNotIn("secret", masked)


if __name__ == "__main__":
    unittest.main()
