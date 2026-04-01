"""Testes para o módulo collector."""

import datetime
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from collector import SystemCollector


@pytest.fixture
def collector(tmp_path):
    """Cria um collector com banco de dados temporário."""
    db_path = str(tmp_path / "test.db")
    return SystemCollector(db_path=db_path)


class TestSystemCollector:
    def test_init_creates_tables(self, collector):
        """Verifica se as tabelas são criadas na inicialização."""
        import sqlite3
        conn = sqlite3.connect(collector.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        conn.close()

        assert "system_metrics" in tables
        assert "process_metrics" in tables
        assert "user_permissions" in tables

    def test_save_and_read_metrics(self, collector):
        """Verifica ciclo de escrita e leitura de métricas."""
        sys_metrics = {
            "timestamp": datetime.datetime.now().isoformat(),
            "cpu_percent": 45.0,
            "memory_percent": 60.0,
            "disk_io_read": 1000,
            "disk_io_write": 2000,
        }
        proc_metrics = [
            {
                "timestamp": datetime.datetime.now().isoformat(),
                "pid": 1234,
                "name": "test.exe",
                "cpu_percent": 10.0,
                "memory_percent": 5.0,
            }
        ]

        collector.save_metrics(sys_metrics, proc_metrics)

        import sqlite3
        conn = sqlite3.connect(collector.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM system_metrics")
        assert cursor.fetchone()[0] == 1
        cursor.execute("SELECT COUNT(*) FROM process_metrics")
        assert cursor.fetchone()[0] == 1
        conn.close()

    def test_permission_default(self, collector):
        """Permissões para processo desconhecido devem ser zero."""
        perms = collector.get_permission("unknown.exe")
        assert perms == {"allowed_count": 0, "denied_count": 0}

    def test_register_and_get_permission(self, collector):
        """Verifica registro de permissões de allow e deny."""
        collector.register_permission("app.exe", allowed=True)
        collector.register_permission("app.exe", allowed=True)
        collector.register_permission("app.exe", allowed=False)

        perms = collector.get_permission("app.exe")
        assert perms["allowed_count"] == 2
        assert perms["denied_count"] == 1

    def test_cleanup_old_data(self, collector):
        """Verifica que dados antigos são removidos."""
        old_timestamp = (
            datetime.datetime.now() - datetime.timedelta(days=30)
        ).isoformat()
        recent_timestamp = datetime.datetime.now().isoformat()

        sys_old = {
            "timestamp": old_timestamp,
            "cpu_percent": 10.0, "memory_percent": 20.0,
            "disk_io_read": 100, "disk_io_write": 200,
        }
        sys_recent = {
            "timestamp": recent_timestamp,
            "cpu_percent": 50.0, "memory_percent": 60.0,
            "disk_io_read": 500, "disk_io_write": 600,
        }

        collector.save_metrics(sys_old, [])
        collector.save_metrics(sys_recent, [])
        collector.cleanup_old_data()

        import sqlite3
        conn = sqlite3.connect(collector.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM system_metrics")
        count = cursor.fetchone()[0]
        conn.close()

        assert count == 1  # Só o recente deve permanecer

    def test_save_empty_processes(self, collector):
        """Salvar sem processos não deve causar erro."""
        sys_metrics = {
            "timestamp": datetime.datetime.now().isoformat(),
            "cpu_percent": 10.0, "memory_percent": 20.0,
            "disk_io_read": 100, "disk_io_write": 200,
        }
        collector.save_metrics(sys_metrics, [])

    def test_wal_mode_enabled(self, collector):
        """WAL mode deve estar habilitado no banco."""
        import sqlite3
        conn = sqlite3.connect(collector.db_path)
        row = conn.execute("PRAGMA journal_mode").fetchone()
        conn.close()
        assert row[0] == "wal"

    def test_indices_created(self, collector):
        """Índices de timestamp devem existir."""
        import sqlite3
        conn = sqlite3.connect(collector.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
        indices = {row[0] for row in cursor.fetchall()}
        conn.close()
        assert "idx_sys_ts" in indices
        assert "idx_proc_ts" in indices

    def test_get_all_permissions_empty(self, collector):
        """Lista de permissões deve ser vazia inicialmente."""
        result = collector.get_all_permissions()
        assert result == []

    def test_get_all_permissions_returns_all(self, collector):
        """Deve retornar todas as permissões registradas."""
        collector.register_permission("a.exe", allowed=True)
        collector.register_permission("b.exe", allowed=False)
        result = collector.get_all_permissions()
        names = {p["name"] for p in result}
        assert names == {"a.exe", "b.exe"}

    def test_revoke_permission(self, collector):
        """Revogar deve remover o registro do banco."""
        collector.register_permission("app.exe", allowed=True)
        collector.revoke_permission("app.exe")
        perms = collector.get_permission("app.exe")
        assert perms == {"allowed_count": 0, "denied_count": 0}

    def test_collect_processes_filters_idle(self, collector):
        """Processos com CPU e RAM abaixo do threshold não devem ser retornados."""
        from unittest.mock import MagicMock, patch
        mock_proc = MagicMock()
        mock_proc.info = {
            "pid": 1, "name": "idle.exe",
            "cpu_percent": 0.0, "memory_percent": 0.1,
        }
        with patch("collector.psutil.process_iter", return_value=[mock_proc]):
            procs = collector.collect_processes()
        assert len(procs) == 0

    def test_collect_processes_includes_active(self, collector):
        """Processos com consumo relevante devem ser incluídos."""
        from unittest.mock import MagicMock, patch
        mock_proc = MagicMock()
        mock_proc.info = {
            "pid": 99, "name": "heavy.exe",
            "cpu_percent": 5.0, "memory_percent": 2.0,
        }
        with patch("collector.psutil.process_iter", return_value=[mock_proc]):
            procs = collector.collect_processes()
        assert len(procs) == 1
        assert procs[0]["name"] == "heavy.exe"
