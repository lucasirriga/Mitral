import psutil

class ActionManager:
    def __init__(self, collector):
        self.collector = collector
        self.whitelist = [
            'explorer.exe', 'csrss.exe', 'svchost.exe', 'System', 'Taskmgr.exe', 
            'python.exe', 'cmd.exe', 'conhost.exe'
        ]
        self.pending_permissions = [] # Fila aguardando permissão do usuario (na GUI)

    def handle_anomaly(self, culprit):
        if not culprit or culprit['name'] in self.whitelist:
            return None 
        
        name = culprit['name']
        perms = self.collector.get_permission(name)
        
        # Se o usuário permitiu essa ação no passado pelo menos 3 vezes seguidas, não pergunta mais
        if perms['allowed_count'] >= 3:
            self.apply_mitigation(name, culprit['pid'])
            return "AUTO_MITIGATED"
        else:
            # Precisa de permissão explícita
            # Verifica se já não está na fila
            if not any(n == name for n, p in self.pending_permissions):
                self.pending_permissions.append((name, culprit['pid']))
            return "PENDING_PERMISSION"

    def apply_mitigation(self, process_name, pid):
        try:
            proc = psutil.Process(pid)
            # Rebaixa a prioridade no Windows para poupar CPU para o resto do sistema
            proc.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
            return True
        except Exception:
            return False

    def resolve_permission(self, process_name, pid, allowed):
        self.collector.register_permission(process_name, allowed)
        if allowed:
            self.apply_mitigation(process_name, pid)
