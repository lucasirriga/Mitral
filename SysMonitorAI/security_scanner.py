import psutil
import os

class SecurityScanner:
    def __init__(self):
        # Lista the processos falsificados comumente por malwares
        self.critical_system_binaries = ["svchost.exe", "explorer.exe", "winlogon.exe", "csrss.exe", "lsass.exe", "smss.exe", "services.exe", "spoolsv.exe"]
        
        # Onde eles devem rodar
        self.system_paths = ["c:\\windows\\system32", "c:\\windows\\syswow64", "c:\\windows"]

    def scan_running_processes(self):
        alerts = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent']):
            try:
                name = proc.info['name']
                exe = proc.info.get('exe')
                
                if not name or not exe:
                    continue
                    
                name_lower = name.lower()
                exe_lower = exe.lower()
                
                # Heurística 1: Spoofing (Processo Core do Windows rodando fora do local oficial)
                if name_lower in self.critical_system_binaries:
                    is_in_sys_path = any(exe_lower.startswith(sp) for sp in self.system_paths)
                    if not is_in_sys_path:
                        alerts.append({
                            "type": "SPOOFING",
                            "name": name,
                            "pid": proc.info['pid'],
                            "path": exe,
                            "desc": f"Processo crítico de sistema rodando de local inesperado!"
                        })
                
                # Heurística 2: Minerador escondido ou Malware rodando da pasta Temp/AppData chupando muita CPU
                suspicious_paths = ["\\appdata\\", "\\temp\\", "\\programdata\\"]
                if any(sp in exe_lower for sp in suspicious_paths):
                    # Se usa mais de 50% de CPU instantâneo fora das pastas comuns
                    if proc.info['cpu_percent'] and proc.info['cpu_percent'] > 50.0:
                        alerts.append({
                            "type": "MINER/RANSOMWARE SUSPECT",
                            "name": name,
                            "pid": proc.info['pid'],
                            "path": exe,
                            "desc": f"Software rodando em pasta temporária (usada por malwares) com ALTÍSSIMO consumo de CPU."
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
        return alerts
