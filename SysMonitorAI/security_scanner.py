"""Módulo de escaneamento heurístico contra malwares."""

import logging
import platform
from typing import Any

import psutil

from config import HIGH_CPU_THRESHOLD, SYSTEM_PATHS, SUSPICIOUS_PATHS

logger = logging.getLogger(__name__)


class SecurityScanner:
    """Detecta processos suspeitos via heurísticas de segurança."""

    def __init__(self) -> None:
        self.critical_system_binaries: list[str] = [
            "svchost.exe", "explorer.exe", "winlogon.exe", "csrss.exe",
            "lsass.exe", "smss.exe", "services.exe", "spoolsv.exe",
        ]
        self._is_windows = platform.system() == "Windows"

    def scan_running_processes(self) -> list[dict[str, Any]]:
        """Escaneia processos em execução em busca de comportamento malicioso."""
        alerts: list[dict[str, Any]] = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent']):
            try:
                name = proc.info['name']
                exe = proc.info.get('exe')

                if not name or not exe:
                    continue

                name_lower = name.lower()
                exe_lower = exe.lower()

                # Heurística 1: Spoofing (processo crítico rodando fora do local oficial)
                if self._is_windows and name_lower in self.critical_system_binaries:
                    is_in_sys_path = any(exe_lower.startswith(sp) for sp in SYSTEM_PATHS)
                    if not is_in_sys_path:
                        alerts.append({
                            "type": "SPOOFING",
                            "name": name,
                            "pid": proc.info['pid'],
                            "path": exe,
                            "desc": "Processo crítico de sistema rodando de local inesperado!",
                        })

                # Heurística 2: Minerador/malware em pasta suspeita com alto consumo de CPU
                if any(sp in exe_lower for sp in SUSPICIOUS_PATHS):
                    cpu = proc.info['cpu_percent']
                    if cpu and cpu > HIGH_CPU_THRESHOLD:
                        alerts.append({
                            "type": "MINER/RANSOMWARE SUSPECT",
                            "name": name,
                            "pid": proc.info['pid'],
                            "path": exe,
                            "desc": "Software em pasta temporária com altíssimo consumo de CPU.",
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        return alerts
