"""Testes para o módulo security_scanner."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from security_scanner import SecurityScanner


@pytest.fixture
def scanner():
    return SecurityScanner()


def _make_proc(pid, name, exe, cpu_percent):
    """Cria um mock de processo para psutil.process_iter."""
    proc = MagicMock()
    proc.info = {
        "pid": pid,
        "name": name,
        "exe": exe,
        "cpu_percent": cpu_percent,
    }
    return proc


class TestSecurityScanner:
    @patch("security_scanner.psutil.process_iter")
    def test_no_alerts_for_clean_system(self, mock_iter, scanner):
        """Sistema limpo não deve gerar alertas."""
        mock_iter.return_value = [
            _make_proc(1, "svchost.exe", "c:\\windows\\system32\\svchost.exe", 5.0),
            _make_proc(2, "chrome.exe", "c:\\program files\\google\\chrome.exe", 20.0),
        ]
        alerts = scanner.scan_running_processes()
        assert len(alerts) == 0

    @patch("security_scanner.psutil.process_iter")
    @patch("security_scanner.platform.system", return_value="Windows")
    def test_spoofing_detection(self, mock_platform, mock_iter, scanner):
        """Deve detectar processo crítico rodando fora do diretório oficial."""
        scanner._is_windows = True
        mock_iter.return_value = [
            _make_proc(99, "svchost.exe", "c:\\users\\hacker\\svchost.exe", 10.0),
        ]
        alerts = scanner.scan_running_processes()
        assert len(alerts) == 1
        assert alerts[0]["type"] == "SPOOFING"

    @patch("security_scanner.psutil.process_iter")
    def test_miner_detection(self, mock_iter, scanner):
        """Deve detectar processo suspeito em pasta temp com alto CPU."""
        import platform
        if platform.system() == "Windows":
            suspicious_exe = "c:\\users\\user\\appdata\\local\\temp\\miner.exe"
        else:
            suspicious_exe = "/tmp/miner.exe"
        mock_iter.return_value = [
            _make_proc(50, "miner.exe", suspicious_exe, 80.0),
        ]
        alerts = scanner.scan_running_processes()
        assert len(alerts) >= 1
        assert any(a["type"] == "MINER/RANSOMWARE SUSPECT" for a in alerts)

    @patch("security_scanner.psutil.process_iter")
    def test_low_cpu_in_temp_no_alert(self, mock_iter, scanner):
        """Processo em pasta temp mas com baixo CPU não deve gerar alerta."""
        mock_iter.return_value = [
            _make_proc(50, "updater.exe", "c:\\users\\user\\appdata\\local\\temp\\updater.exe", 2.0),
        ]
        alerts = scanner.scan_running_processes()
        miner_alerts = [a for a in alerts if a["type"] == "MINER/RANSOMWARE SUSPECT"]
        assert len(miner_alerts) == 0

    @patch("security_scanner.psutil.process_iter")
    def test_handles_none_exe(self, mock_iter, scanner):
        """Processo sem exe deve ser ignorado sem erro."""
        mock_iter.return_value = [
            _make_proc(1, "test", None, 10.0),
        ]
        alerts = scanner.scan_running_processes()
        assert len(alerts) == 0

    @patch("security_scanner.psutil.process_iter")
    def test_handles_none_name(self, mock_iter, scanner):
        """Processo sem nome deve ser ignorado sem erro."""
        mock_iter.return_value = [
            _make_proc(1, None, "/usr/bin/test", 10.0),
        ]
        alerts = scanner.scan_running_processes()
        assert len(alerts) == 0
