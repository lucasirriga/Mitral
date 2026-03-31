"""Configurações centralizadas do SysMonitorAI."""

import logging
import platform

# === Banco de Dados ===
DB_PATH: str = "sys_monitor.db"
DATA_RETENTION_DAYS: int = 7

# === Modelo de IA ===
MIN_TRAINING_SAMPLES: int = 50
RETRAIN_INTERVAL: int = 120  # Previsões entre re-treinos (~10 min)
TRAINING_WINDOW: int = 500   # Amostras para treino do baseline
CHART_POINTS: int = 60       # Pontos exibidos no gráfico de evolução

# === Mitigação ===
AUTO_APPROVE_THRESHOLD: int = 3  # Aprovações necessárias para auto-mitigar

# === Notificações ===
NOTIFICATION_COOLDOWN: int = 30  # Segundos entre alertas desktop

# === Intervalos ===
BACKEND_INTERVAL: int = 5       # Segundos entre coletas do backend
UI_REFRESH_INTERVAL: int = 2000  # Milissegundos entre atualizações da GUI

# === Scanner de Segurança ===
HIGH_CPU_THRESHOLD: float = 50.0  # % CPU para considerar suspeito

# Caminhos suspeitos por plataforma
if platform.system() == "Windows":
    SYSTEM_PATHS: list[str] = [
        "c:\\windows\\system32",
        "c:\\windows\\syswow64",
        "c:\\windows",
    ]
    SUSPICIOUS_PATHS: list[str] = ["\\appdata\\", "\\temp\\", "\\programdata\\"]
else:
    SYSTEM_PATHS: list[str] = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
    SUSPICIOUS_PATHS: list[str] = ["/tmp/", "/dev/shm/", "/var/tmp/"]

# === Logging ===
LOG_FORMAT: str = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_LEVEL: int = logging.INFO


def setup_logging() -> None:
    """Configura o sistema de logging da aplicação."""
    logging.basicConfig(format=LOG_FORMAT, level=LOG_LEVEL)
