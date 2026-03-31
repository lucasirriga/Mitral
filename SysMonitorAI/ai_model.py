"""Módulo de detecção de anomalias com Isolation Forest."""

import logging
import os
import sqlite3
from contextlib import contextmanager
from typing import Any

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from config import (
    DB_PATH,
    MIN_TRAINING_SAMPLES,
    RETRAIN_INTERVAL,
    TRAINING_WINDOW,
    CHART_POINTS,
)

logger = logging.getLogger(__name__)

FEATURE_COLS = ['cpu_percent', 'memory_percent', 'disk_io_read', 'disk_io_write']


class SysMonitorAI:
    """Motor de IA para detecção de anomalias no sistema usando Isolation Forest."""

    def __init__(self, db_path: str = DB_PATH) -> None:
        self.db_path = db_path
        self.model = IsolationForest(contamination='auto', random_state=42)
        self.scaler = StandardScaler()
        self.is_trained: bool = False
        self.predict_count: int = 0
        self.my_pid: int = os.getpid()

    @contextmanager
    def _get_connection(self):
        """Context manager para conexões SQLite."""
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
        finally:
            conn.close()

    def get_training_data(self) -> pd.DataFrame:
        """Busca dados históricos para treino do modelo."""
        try:
            with self._get_connection() as conn:
                df = pd.read_sql_query(
                    f"SELECT {', '.join(FEATURE_COLS)} "
                    f"FROM system_metrics ORDER BY id DESC LIMIT {TRAINING_WINDOW}",
                    conn,
                )
            return df
        except Exception as e:
            logger.error("Erro ao ler banco: %s", e)
            return pd.DataFrame()

    def train_model(self) -> bool:
        """Treina o modelo de anomalias se houver dados suficientes."""
        df = self.get_training_data()
        if len(df) > MIN_TRAINING_SAMPLES:
            scaled = self.scaler.fit_transform(df)
            self.model.fit(scaled)
            self.is_trained = True
            return True
        return False

    def predict_anomaly(self, cpu: float, mem: float, disk_r: int, disk_w: int) -> bool:
        """Prediz se o estado atual do sistema é anômalo."""
        self.predict_count += 1
        if not self.is_trained or self.predict_count > RETRAIN_INTERVAL:
            self.train_model()
            self.predict_count = 0

        if not self.is_trained:
            return False

        data = pd.DataFrame([{
            "cpu_percent": cpu,
            "memory_percent": mem,
            "disk_io_read": disk_r,
            "disk_io_write": disk_w,
        }])

        scaled = self.scaler.transform(data)
        prediction = self.model.predict(scaled)
        return bool(prediction[0] == -1)

    def get_evolution_data(self) -> pd.DataFrame:
        """Busca dados históricos para renderização de gráficos."""
        try:
            with self._get_connection() as conn:
                df = pd.read_sql_query(
                    f"SELECT {', '.join(FEATURE_COLS)} "
                    f"FROM system_metrics ORDER BY id DESC LIMIT {CHART_POINTS}",
                    conn,
                )

            # Inverte para ordem cronológica (antigo -> novo)
            df = df.iloc[::-1].reset_index(drop=True)

            if self.is_trained and not df.empty:
                scaled = self.scaler.transform(df[FEATURE_COLS])
                df['ai_score'] = self.model.decision_function(scaled)
            else:
                df['ai_score'] = 0.0

            return df
        except Exception as e:
            logger.error("Erro ao buscar evolução: %s", e)
            return pd.DataFrame()

    def find_culprit(self, proc_metrics_list: list[dict[str, Any]]) -> dict[str, Any] | None:
        """Encontra o processo que provavelmente causou a anomalia (maior ofensor)."""
        if not proc_metrics_list:
            return None

        active_procs = [
            p for p in proc_metrics_list
            if p['name'] != 'System Idle Process' and p['pid'] != self.my_pid
        ]
        if not active_procs:
            return None

        culprit = max(active_procs, key=lambda p: p['cpu_percent'] + p['memory_percent'])
        return culprit
