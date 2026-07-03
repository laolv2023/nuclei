# -*- coding: utf-8 -*-
"""
nuclei_client 单元测试
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from unittest.mock import patch, MagicMock
from app.nuclei_client import NucleiClient


class TestNucleiClient(unittest.TestCase):
    def setUp(self):
        self.client = NucleiClient(
            nuclei_path="nuclei",
            request_timeout=5,
            scan_timeout=30,
            max_concurrency=10,
        )

    def test_set_auth_token(self):
        self.client.set_auth_token("Bearer xxx")
        self.assertEqual(self.client._auth_headers, ["-H", "Authorization: Bearer xxx"])

    def test_set_auth_token_empty(self):
        self.client.set_auth_token("")
        self.assertEqual(self.client._auth_headers, [])

    def test_set_auth_token_custom_header(self):
        self.client.set_auth_token("session123", header_name="Cookie")
        self.assertEqual(self.client._auth_headers, ["-H", "Cookie: session123"])

    @patch("subprocess.run")
    def test_health_check_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        self.assertTrue(self.client.health_check())

    @patch("subprocess.run")
    def test_health_check_failure(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1)
        self.assertFalse(self.client.health_check())

    @patch("subprocess.run")
    def test_health_check_exception(self, mock_run):
        mock_run.side_effect = FileNotFoundError("nuclei not found")
        self.assertFalse(self.client.health_check())

    @patch("subprocess.run")
    def test_update_templates_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        self.assertTrue(self.client.update_templates())

    def test_kill_current_scan_no_process(self):
        # 没有正在运行的进程时应不报错
        self.client._current_process = None
        self.client.kill_current_scan()

    def test_kill_current_scan_with_process(self):
        proc = MagicMock()
        proc.pid = 12345
        proc.poll.return_value = None  # 进程仍在运行
        proc.wait.return_value = 0
        self.client._current_process = proc
        self.client.kill_current_scan()
        proc.send_signal.assert_called_once()
        proc.wait.assert_called_once()

    def test_kill_current_scan_force_kill(self):
        import signal as sig
        proc = MagicMock()
        proc.pid = 12345
        proc.poll.return_value = None  # 进程仍在运行
        proc.wait.side_effect = [subprocess.TimeoutExpired("cmd", 10), 0]
        self.client._current_process = proc
        self.client.kill_current_scan()
        proc.kill.assert_called_once()

    @patch("subprocess.Popen")
    def test_scan_url_success(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (
            '{"template-id":"CVE-1","matched-at":"http://a.com/","severity":"high"}\n', ""
        )
        mock_popen.return_value = mock_proc
        results = self.client.scan_url("http://a.com/")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["template-id"], "CVE-1")

    @patch("subprocess.Popen")
    def test_scan_url_timeout(self, mock_popen):
        import subprocess
        mock_proc = MagicMock()
        mock_proc.communicate.side_effect = subprocess.TimeoutExpired("cmd", 30)
        mock_proc.kill.return_value = None
        mock_proc.wait.return_value = 0
        mock_popen.return_value = mock_proc
        results = self.client.scan_url("http://a.com/")
        self.assertEqual(results, [])

    @patch("subprocess.Popen")
    def test_scan_batch_success(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (
            '{"template-id":"CVE-1","matched-at":"http://a.com/","severity":"high"}\n'
            '{"template-id":"CVE-2","matched-at":"http://b.com/","severity":"medium"}\n'
            '{"template-id":"CVE-1","matched-at":"http://a.com/","severity":"high"}\n'
            'non-json-line\n',
            ""
        )
        mock_popen.return_value = mock_proc
        results = self.client.scan_batch(["http://a.com/", "http://b.com/"])
        self.assertIn("http://a.com/", results)
        self.assertEqual(len(results["http://a.com/"]), 1)  # 去重后只剩1条
        self.assertIn("http://b.com/", results)

    def test_scan_batch_empty_urls(self):
        results = self.client.scan_batch([])
        self.assertEqual(results, {})


import subprocess  # for test_kill_current_scan_force_kill


if __name__ == "__main__":
    unittest.main()
