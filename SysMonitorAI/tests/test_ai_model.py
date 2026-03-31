"""Testes para o módulo ai_model."""

import datetime
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ai_model import SysMonitorAI
from collector import SystemCollector


@pytest.fixture
def db_with_data(tmp_path):
    """Cria um banco com dados suficientes para treino."""
    db_path = str(tmp_path / "test.db")
    collector = SystemCollector(db_path=db_path)

    # Insere 100 amostras sintéticas para garantir treino
    import random
    random.seed(42)
    for i in range(100):
        ts = (datetime.datetime.now() - datetime.timedelta(seconds=100 - i)).isoformat()
        sys_metrics = {
            "timestamp": ts,
            "cpu_percent": random.uniform(10, 60),
            "memory_percent": random.uniform(30, 70),
            "disk_io_read": random.randint(1000, 50000),
            "disk_io_write": random.randint(1000, 50000),
        }
        collector.save_metrics(sys_metrics, [])

    return db_path


@pytest.fixture
def empty_db(tmp_path):
    """Cria um banco vazio."""
    db_path = str(tmp_path / "empty.db")
    SystemCollector(db_path=db_path)
    return db_path


class TestSysMonitorAI:
    def test_train_with_sufficient_data(self, db_with_data):
        """Modelo deve treinar com dados suficientes."""
        ai = SysMonitorAI(db_path=db_with_data)
        assert ai.train_model() is True
        assert ai.is_trained is True

    def test_train_without_data(self, empty_db):
        """Modelo não deve treinar sem dados."""
        ai = SysMonitorAI(db_path=empty_db)
        assert ai.train_model() is False
        assert ai.is_trained is False

    def test_predict_returns_bool(self, db_with_data):
        """Predição deve retornar booleano."""
        ai = SysMonitorAI(db_path=db_with_data)
        ai.train_model()
        result = ai.predict_anomaly(30.0, 50.0, 5000, 5000)
        assert isinstance(result, bool)

    def test_predict_untrained_returns_false(self, empty_db):
        """Sem treino, deve retornar False (assuma normalidade)."""
        ai = SysMonitorAI(db_path=empty_db)
        result = ai.predict_anomaly(99.0, 99.0, 999999, 999999)
        assert result is False

    def test_find_culprit_empty_list(self, empty_db):
        """Lista vazia deve retornar None."""
        ai = SysMonitorAI(db_path=empty_db)
        assert ai.find_culprit([]) is None

    def test_find_culprit_returns_highest_offender(self, empty_db):
        """Deve retornar o processo com maior consumo combinado."""
        ai = SysMonitorAI(db_path=empty_db)
        procs = [
            {"pid": 1, "name": "low.exe", "cpu_percent": 5.0, "memory_percent": 5.0},
            {"pid": 2, "name": "high.exe", "cpu_percent": 80.0, "memory_percent": 40.0},
            {"pid": 3, "name": "mid.exe", "cpu_percent": 30.0, "memory_percent": 20.0},
        ]
        culprit = ai.find_culprit(procs)
        assert culprit is not None
        assert culprit["name"] == "high.exe"

    def test_find_culprit_ignores_system_idle(self, empty_db):
        """Deve ignorar System Idle Process."""
        ai = SysMonitorAI(db_path=empty_db)
        procs = [
            {"pid": 0, "name": "System Idle Process", "cpu_percent": 99.0, "memory_percent": 0.0},
            {"pid": 2, "name": "app.exe", "cpu_percent": 10.0, "memory_percent": 5.0},
        ]
        culprit = ai.find_culprit(procs)
        assert culprit["name"] == "app.exe"

    def test_get_evolution_data(self, db_with_data):
        """Deve retornar DataFrame com coluna ai_score."""
        ai = SysMonitorAI(db_path=db_with_data)
        ai.train_model()
        df = ai.get_evolution_data()
        assert not df.empty
        assert "ai_score" in df.columns
