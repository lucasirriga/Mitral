"""Testes para o módulo action_manager."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from action_manager import ActionManager
from collector import SystemCollector


@pytest.fixture
def manager(tmp_path):
    """Cria ActionManager com collector de banco temporário."""
    db_path = str(tmp_path / "test.db")
    collector = SystemCollector(db_path=db_path)
    return ActionManager(collector)


class TestActionManager:
    def test_whitelist_blocks_mitigation(self, manager):
        """Processos na whitelist não devem ser mitigados."""
        culprit = {"name": "explorer.exe", "pid": 100, "cpu_percent": 90.0, "memory_percent": 50.0}
        result = manager.handle_anomaly(culprit)
        assert result is None

    def test_none_culprit(self, manager):
        """Culprit None não deve causar erro."""
        result = manager.handle_anomaly(None)
        assert result is None

    def test_pending_permission_for_new_process(self, manager):
        """Processo desconhecido deve entrar na fila de permissões."""
        culprit = {"name": "malware.exe", "pid": 999, "cpu_percent": 80.0, "memory_percent": 60.0}
        result = manager.handle_anomaly(culprit)
        assert result == "PENDING_PERMISSION"
        assert len(manager.pending_permissions) == 1
        assert manager.pending_permissions[0][0] == "malware.exe"

    def test_no_duplicate_pending(self, manager):
        """Mesmo processo não deve entrar duas vezes na fila."""
        culprit = {"name": "app.exe", "pid": 100, "cpu_percent": 50.0, "memory_percent": 30.0}
        manager.handle_anomaly(culprit)
        manager.handle_anomaly(culprit)
        assert len(manager.pending_permissions) == 1

    def test_auto_mitigate_requires_no_denials(self, manager):
        """Auto-mitigação requer allowed >= threshold E denied == 0."""
        # Registra 3 aprovações e 1 negação
        for _ in range(3):
            manager.collector.register_permission("app.exe", allowed=True)
        manager.collector.register_permission("app.exe", allowed=False)

        culprit = {"name": "app.exe", "pid": 100, "cpu_percent": 50.0, "memory_percent": 30.0}
        result = manager.handle_anomaly(culprit)
        # Não deve auto-mitigar porque tem denied_count > 0
        assert result == "PENDING_PERMISSION"

    @patch("action_manager.psutil.Process")
    def test_apply_mitigation_stale_pid(self, mock_process_cls, manager):
        """Mitigação deve falhar se o PID agora é de outro processo."""
        mock_proc = MagicMock()
        mock_proc.name.return_value = "other.exe"  # Nome diferente
        mock_process_cls.return_value = mock_proc

        result = manager.apply_mitigation("target.exe", 123)
        assert result is False

    @patch("action_manager.psutil.Process")
    def test_apply_mitigation_no_such_process(self, mock_process_cls, manager):
        """Mitigação deve retornar False se o processo não existe mais."""
        import psutil
        mock_process_cls.side_effect = psutil.NoSuchProcess(123)

        result = manager.apply_mitigation("app.exe", 123)
        assert result is False

    def test_resolve_permission_allowed(self, manager):
        """Resolve permissão com allow deve registrar no banco."""
        manager.resolve_permission("app.exe", 100, allowed=True)
        perms = manager.collector.get_permission("app.exe")
        assert perms["allowed_count"] == 1
        assert perms["denied_count"] == 0

    def test_resolve_permission_denied(self, manager):
        """Resolve permissão com deny deve registrar no banco."""
        manager.resolve_permission("app.exe", 100, allowed=False)
        perms = manager.collector.get_permission("app.exe")
        assert perms["allowed_count"] == 0
        assert perms["denied_count"] == 1
