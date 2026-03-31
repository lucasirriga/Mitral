"""Módulo de coleta de métricas do sistema e persistência em SQLite."""

import datetime
import logging
import sqlite3
from contextlib import contextmanager
from typing import Any

import pandas as pd
import psutil

from config import DB_PATH, DATA_RETENTION_DAYS

logger = logging.getLogger(__name__)


class SystemCollector:
    """Coleta métricas do sistema e dos processos, persistindo em SQLite."""

    def __init__(self, db_path: str = DB_PATH) -> None:
        self.db_path = db_path
        self._collection_count = 0
        self._init_db()

    @contextmanager
    def _get_connection(self):
        """Context manager para conexões SQLite com commit/rollback automático."""
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Cria as tabelas do banco caso não existam."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    cpu_percent REAL,
                    memory_percent REAL,
                    disk_io_read INTEGER,
                    disk_io_write INTEGER
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS process_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    pid INTEGER,
                    name TEXT,
                    cpu_percent REAL,
                    memory_percent REAL
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_permissions (
                    name TEXT PRIMARY KEY,
                    allowed_count INTEGER,
                    denied_count INTEGER
                )
            ''')

    def get_permission(self, process_name: str) -> dict[str, int]:
        """Retorna contadores de permissão para um processo."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT allowed_count, denied_count FROM user_permissions WHERE name=?",
                (process_name,),
            )
            row = cursor.fetchone()
        if row:
            return {"allowed_count": row[0], "denied_count": row[1]}
        return {"allowed_count": 0, "denied_count": 0}

    def register_permission(self, process_name: str, allowed: bool) -> None:
        """Registra uma decisão de permissão do usuário."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if allowed:
                cursor.execute('''
                    INSERT INTO user_permissions(name, allowed_count, denied_count)
                    VALUES(?, 1, 0)
                    ON CONFLICT(name) DO UPDATE SET allowed_count = allowed_count + 1
                ''', (process_name,))
            else:
                cursor.execute('''
                    INSERT INTO user_permissions(name, allowed_count, denied_count)
                    VALUES(?, 0, 1)
                    ON CONFLICT(name) DO UPDATE SET denied_count = denied_count + 1
                ''', (process_name,))

    def collect_system_metrics(self) -> dict[str, Any]:
        """Coleta métricas gerais do sistema (CPU, RAM, Disco)."""
        cpu = psutil.cpu_percent(interval=None)
        memory = psutil.virtual_memory().percent
        disk_io = psutil.disk_io_counters()

        return {
            "timestamp": datetime.datetime.now().isoformat(),
            "cpu_percent": cpu,
            "memory_percent": memory,
            "disk_io_read": disk_io.read_bytes if disk_io else 0,
            "disk_io_write": disk_io.write_bytes if disk_io else 0,
        }

    def collect_processes(self) -> list[dict[str, Any]]:
        """Coleta métricas de cada processo em execução."""
        processes = []
        now = datetime.datetime.now().isoformat()
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                pinfo = proc.info
                processes.append({
                    "timestamp": now,
                    "pid": pinfo['pid'],
                    "name": pinfo['name'],
                    "cpu_percent": pinfo['cpu_percent'] or 0.0,
                    "memory_percent": pinfo['memory_percent'] or 0.0,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        return processes

    def save_metrics(self, sys_metrics: dict[str, Any], proc_metrics: list[dict[str, Any]]) -> None:
        """Salva métricas do sistema e processos em uma única transação atômica."""
        with self._get_connection() as conn:
            system_df = pd.DataFrame([sys_metrics])
            system_df.to_sql('system_metrics', conn, if_exists='append', index=False)

            if proc_metrics:
                proc_df = pd.DataFrame(proc_metrics)
                proc_df.to_sql('process_metrics', conn, if_exists='append', index=False)

    def cleanup_old_data(self) -> None:
        """Remove dados mais antigos que DATA_RETENTION_DAYS."""
        cutoff = (
            datetime.datetime.now() - datetime.timedelta(days=DATA_RETENTION_DAYS)
        ).isoformat()
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM system_metrics WHERE timestamp < ?", (cutoff,))
                cursor.execute("DELETE FROM process_metrics WHERE timestamp < ?", (cutoff,))
                deleted = cursor.rowcount
                if deleted > 0:
                    logger.info("Limpeza: %d registros antigos removidos.", deleted)
        except Exception as e:
            logger.error("Erro na limpeza de dados antigos: %s", e)

    def step(self) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """Coleta e salva uma amostra no banco de dados."""
        sys_metrics = self.collect_system_metrics()
        proc_metrics = self.collect_processes()
        self.save_metrics(sys_metrics, proc_metrics)

        # Limpeza periódica (a cada 100 coletas)
        self._collection_count += 1
        if self._collection_count >= 100:
            self._collection_count = 0
            self.cleanup_old_data()

        return sys_metrics, proc_metrics


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    psutil.cpu_percent(interval=1)
    collector = SystemCollector()
    logger.info("Coletando métricas de teste...")
    sys_data, proc_data = collector.step()
    logger.info("Sistema: %s", sys_data)
    logger.info("Total de processos guardados: %d", len(proc_data))
