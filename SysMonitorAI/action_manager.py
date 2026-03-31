"""Módulo de gerenciamento de ações de mitigação contra anomalias."""

import logging
import platform
from typing import Any

import psutil

from config import AUTO_APPROVE_THRESHOLD, SYSTEM_PATHS

logger = logging.getLogger(__name__)


class ActionManager:
    """Gerencia ações de mitigação com aprendizado de permissões do usuário."""

    def __init__(self, collector) -> None:
        self.collector = collector
        self.whitelist: list[str] = [
            'explorer.exe', 'csrss.exe', 'svchost.exe', 'System', 'Taskmgr.exe',
            'python.exe', 'cmd.exe', 'conhost.exe',
        ]
        self.pending_permissions: list[tuple[str, int]] = []

    def _is_whitelisted(self, name: str, pid: int) -> bool:
        """Verifica se o processo está na whitelist, validando também o caminho do executável."""
        if name not in self.whitelist:
            return False

        if platform.system() != "Windows":
            return True

        try:
            proc = psutil.Process(pid)
            exe_path = (proc.exe() or "").lower()
            return any(exe_path.startswith(sp) for sp in SYSTEM_PATHS)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return True  # Na dúvida, protege processos da whitelist

    def handle_anomaly(self, culprit: dict[str, Any] | None) -> str | None:
        """Decide a ação para um processo causador de anomalia."""
        if not culprit or self._is_whitelisted(culprit['name'], culprit['pid']):
            return None

        name = culprit['name']
        perms = self.collector.get_permission(name)

        # Auto-mitigar apenas se o usuário aprovou o suficiente E nunca negou
        if (perms['allowed_count'] >= AUTO_APPROVE_THRESHOLD
                and perms['denied_count'] == 0):
            self.apply_mitigation(name, culprit['pid'])
            return "AUTO_MITIGATED"
        else:
            if not any(n == name for n, p in self.pending_permissions):
                self.pending_permissions.append((name, culprit['pid']))
            return "PENDING_PERMISSION"

    def apply_mitigation(self, process_name: str, pid: int) -> bool:
        """Rebaixa a prioridade de um processo para aliviar o sistema."""
        try:
            proc = psutil.Process(pid)
            # Verifica se o PID ainda corresponde ao processo esperado
            if proc.name() != process_name:
                logger.warning(
                    "PID %d agora pertence a '%s', não a '%s'. Mitigação cancelada.",
                    pid, proc.name(), process_name,
                )
                return False

            if platform.system() == "Windows":
                proc.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
            else:
                # Em Linux/macOS, aumenta o nice value (menor prioridade)
                current = proc.nice()
                if current < 10:
                    proc.nice(10)
            logger.info("Mitigação aplicada: '%s' (PID %d).", process_name, pid)
            return True
        except psutil.NoSuchProcess:
            logger.warning("Processo '%s' (PID %d) não existe mais.", process_name, pid)
            return False
        except psutil.AccessDenied:
            logger.warning("Sem permissão para mitigar '%s' (PID %d).", process_name, pid)
            return False

    def resolve_permission(self, process_name: str, pid: int, allowed: bool) -> None:
        """Resolve uma permissão pendente do usuário."""
        self.collector.register_permission(process_name, allowed)
        if allowed:
            self.apply_mitigation(process_name, pid)
