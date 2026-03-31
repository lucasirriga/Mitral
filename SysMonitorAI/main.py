import threading
import time
from collector import SystemCollector
from ai_model import SysMonitorAI
from action_manager import ActionManager
from security_scanner import SecurityScanner
from gui import SysMonitorGUI
import customtkinter as ctk

class SysMonitorApp:
    def __init__(self):
        self.collector = SystemCollector()
        self.ai = SysMonitorAI()
        self.action_manager = ActionManager(self.collector)
        self.scanner = SecurityScanner()
        
        self.latest_metrics = {
            'cpu': 0, 'ram': 0, 'ai_trained': False, 'anomaly': False, 'culprit': ""
        }
        self.security_alerts = [] # Para a GUI exibir malwares detectados
        self.running = True

    def run_backend(self):
        print("Iniciando backend (Coleta, IA, Escâner e Mitigação)...")
        while self.running:
            # 1. Escaneamento heuristico contra malware
            self.security_alerts = self.scanner.scan_running_processes()

            # 2. Coleta dados vitais do Sistema
            sys_data, proc_data = self.collector.step()
            
            new_metrics = {
                'cpu': sys_data['cpu_percent'],
                'ram': sys_data['memory_percent'],
                'ai_trained': self.ai.is_trained,
                'anomaly': False,
                'culprit': "",
                'mitigated': False
            }
            
            # 3. Analisa Anomalia
            if self.ai.is_trained or self.ai.train_model():
                is_anomaly = self.ai.predict_anomaly(
                    sys_data['cpu_percent'],
                    sys_data['memory_percent'],
                    sys_data['disk_io_read'],
                    sys_data['disk_io_write']
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
                        
            self.latest_metrics = new_metrics
            time.sleep(5) 

    def get_latest_metrics(self):
        return self.latest_metrics
        
    def get_pending_permissions(self):
        return self.action_manager.pending_permissions

    def resolve_permission(self, name, pid, allowed):
        # Tira da fila e envia pro manager resolver (salvar a decisão e possivelmente aplicar)
        self.action_manager.pending_permissions = [(n, p) for n, p in self.action_manager.pending_permissions if n != name]
        self.action_manager.resolve_permission(name, pid, allowed)

    def get_security_alerts(self):
        return self.security_alerts

    def start(self):
        bg_thread = threading.Thread(target=self.run_backend, daemon=True)
        bg_thread.start()
        
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        gui = SysMonitorGUI(self)
        try:
            gui.mainloop()
        finally:
            self.running = False 

if __name__ == "__main__":
    app = SysMonitorApp()
    app.start()
