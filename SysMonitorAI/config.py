"""Configurações centralizadas do SysMonitorAI."""

import logging
import platform
from logging.handlers import RotatingFileHandler

# === Banco de Dados ===
DB_PATH: str = "sys_monitor.db"
DATA_RETENTION_DAYS: int = 7

# === Modelo de IA ===
MIN_TRAINING_SAMPLES: int = 50
RETRAIN_INTERVAL: int = 120  # Previsões entre re-treinos (~10 min)
TRAINING_WINDOW: int = 500   # Amostras para treino do baseline
CHART_POINTS: int = 60       # Pontos exibidos no gráfico de evolução
MODEL_PATH: str = "model.pkl"  # Arquivo para persistência do modelo treinado

# === Coleta de Processos ===
PROCESS_CPU_THRESHOLD: float = 1.0    # % mínimo de CPU para salvar processo
PROCESS_MEM_THRESHOLD: float = 0.5   # % mínimo de RAM para salvar processo

# === Mitigação ===
AUTO_APPROVE_THRESHOLD: int = 3  # Aprovações necessárias para auto-mitigar

# === Notificações ===
NOTIFICATION_COOLDOWN: int = 30  # Segundos entre alertas desktop

# === Intervalos ===
BACKEND_INTERVAL: int = 5        # Segundos entre coletas do backend
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
LOG_FILE: str = "sysmonitor.log"
LOG_MAX_BYTES: int = 5 * 1024 * 1024  # 5 MB por arquivo
LOG_BACKUP_COUNT: int = 3             # Mantém até 3 arquivos de backup


def setup_logging() -> None:
    """Configura o sistema de logging com saída para console e arquivo rotativo."""
    root_logger = logging.getLogger()
    root_logger.setLevel(LOG_LEVEL)

    formatter = logging.Formatter(LOG_FORMAT)

    # Handler de console
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Handler de arquivo rotativo
    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)
