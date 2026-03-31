"""Módulo principal do SysMonitorAI — orquestra coleta, IA, segurança e GUI."""

import logging
import signal
import threading
import time
from typing import Any

import customtkinter as ctk
import pandas as pd

from action_manager import ActionManager
from ai_model import SysMonitorAI
from collector import SystemCollector
from config import BACKEND_INTERVAL, setup_logging
from gui import SysMonitorGUI
from notifier import Notifier
from security_scanner import SecurityScanner

logger = logging.getLogger(__name__)


class SysMonitorApp:
    """Aplicação principal que coordena todos os módulos do SysMonitorAI."""

    def __init__(self) -> None:
        self.collector = SystemCollector()
        self.ai = SysMonitorAI()
        self.action_manager = ActionManager(self.collector)
        self.scanner = SecurityScanner()
        self.notifier = Notifier()

        self._lock = threading.Lock()
        self._stop_event = threading.Event()

        self._latest_metrics: dict[str, Any] = {
            'cpu': 0, 'ram': 0, 'ai_trained': False, 'anomaly': False, 'culprit': '',
        }
        self._security_alerts: list[dict[str, Any]] = []
        self._cached_evolution: pd.DataFrame = pd.DataFrame()
        self._bg_thread: threading.Thread | None = None

    def run_backend(self) -> None:
        """Loop principal do backend: coleta, análise e mitigação."""
        logger.info("Iniciando backend (Coleta, IA, Escâner e Mitigação)...")
        consecutive_errors = 0

        while not self._stop_event.is_set():
            try:
                # 1. Escaneamento heurístico contra malware
                alerts = self.scanner.scan_running_processes()
                with self._lock:
                    self._security_alerts = alerts

                # 2. Coleta dados vitais do sistema
                sys_data, proc_data = self.collector.step()

                new_metrics: dict[str, Any] = {
                    'cpu': sys_data['cpu_percent'],
                    'ram': sys_data['memory_percent'],
                    'ai_trained': self.ai.is_trained,
                    'anomaly': False,
                    'culprit': '',
                    'mitigated': False,
                }

                # 3. Analisa anomalia
                if self.ai.is_trained or self.ai.train_model():
                    is_anomaly = self.ai.predict_anomaly(
                        sys_data['cpu_percent'],
                        sys_data['memory_percent'],
                        sys_data['disk_io_read'],
                        sys_data['disk_io_write'],
                    )

                    # 4. Age contra o gargalo
                    if is_anomaly:
                        culprit = self.ai.find_culprit(proc_data)
                        new_metrics['anomaly'] = True
                        if culprit:
                            new_metrics['culprit'] = culprit['name']
                            action_state = self.action_manager.handle_anomaly(culprit)
                            if action_state == "AUTO_MITIGATED":
                                new_metrics['mitigated'] = True

                            # Notificação desktop
                            self.notifier.send_anomaly_alert(
                                culprit['name'],
                                culprit['memory_percent'],
                                culprit['cpu_percent'],
                            )

                # Atualiza dados de evolução para cache (evita query na thread UI)
                evolution_df = self.ai.get_evolution_data()

                with self._lock:
                    self._latest_metrics = new_metrics
                    self._cached_evolution = evolution_df

                consecutive_errors = 0

            except Exception as e:
                consecutive_errors += 1
                logger.error("Erro no backend (tentativa %d): %s", consecutive_errors, e)
                if consecutive_errors >= 10:
                    logger.critical("Muitos erros consecutivos no backend. Parando.")
                    break

            self._stop_event.wait(timeout=BACKEND_INTERVAL)

    def get_latest_metrics(self) -> dict[str, Any]:
        """Retorna as métricas mais recentes (thread-safe)."""
        with self._lock:
            return self._latest_metrics.copy()

    def get_pending_permissions(self) -> list[tuple[str, int]]:
        """Retorna a fila de permissões pendentes."""
        with self._lock:
            return list(self.action_manager.pending_permissions)

    def resolve_permission(self, name: str, pid: int, allowed: bool) -> None:
        """Resolve uma permissão pendente do usuário."""
        with self._lock:
            self.action_manager.pending_permissions = [
                (n, p) for n, p in self.action_manager.pending_permissions if n != name
            ]
        self.action_manager.resolve_permission(name, pid, allowed)

    def get_security_alerts(self) -> list[dict[str, Any]]:
        """Retorna os alertas de segurança atuais (thread-safe)."""
        with self._lock:
            return list(self._security_alerts)

    def get_cached_evolution_data(self) -> pd.DataFrame:
        """Retorna os dados de evolução cacheados (thread-safe, sem query no banco)."""
        with self._lock:
            return self._cached_evolution.copy()

    def start(self) -> None:
        """Inicia a aplicação: backend em thread separada + GUI na thread principal."""
        setup_logging()

        self._bg_thread = threading.Thread(target=self.run_backend, daemon=True)
        self._bg_thread.start()

        # Handler para SIGINT (Ctrl+C)
        signal.signal(signal.SIGINT, lambda sig, frame: self._shutdown())

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        gui = SysMonitorGUI(self)
        try:
            gui.mainloop()
        finally:
            self._shutdown()

    def _shutdown(self) -> None:
        """Para o backend e limpa recursos de forma graciosa."""
        if self._stop_event.is_set():
            return
        logger.info("Encerrando SysMonitorAI...")
        self._stop_event.set()
        if self._bg_thread and self._bg_thread.is_alive():
            self._bg_thread.join(timeout=10)
        logger.info("Encerrado com sucesso.")


if __name__ == "__main__":
    app = SysMonitorApp()
    app.start()
