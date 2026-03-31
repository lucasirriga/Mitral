"""Módulo de notificações desktop para alertas de anomalia."""

import logging
import time

from plyer import notification

from config import NOTIFICATION_COOLDOWN

logger = logging.getLogger(__name__)


class Notifier:
    """Envia notificações desktop com cooldown para evitar spam."""

    def __init__(self, cooldown: int = NOTIFICATION_COOLDOWN) -> None:
        self.last_alert_time: float = 0
        self.cooldown = cooldown

    def send_anomaly_alert(self, proc_name: str, memory_percent: float, cpu_percent: float) -> None:
        """Envia um alerta desktop sobre um processo causador de anomalia."""
        current_time = time.time()
        if current_time - self.last_alert_time < self.cooldown:
            return

        title = "Gargalo Detectado pela IA!"
        message = (
            f"O processo '{proc_name}' pode estar causando lentidão.\n"
            f"CPU: {cpu_percent:.1f}% | RAM: {memory_percent:.1f}%"
        )

        try:
            notification.notify(
                title=title,
                message=message,
                app_name="SysMonitorAI",
                timeout=8,
            )
            self.last_alert_time = current_time
        except Exception as e:
            logger.error("Erro ao enviar notificação: %s", e)
