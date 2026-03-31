import psutil
import time
import pandas as pd
import sqlite3
import datetime

class SystemCollector:
    def __init__(self, db_path="sys_monitor.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        # Tabela para métricas gerais do sistema
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
        # Tabela para métricas detalhadas dos processos
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
        # Tabela para controle de permissões de usuário (Auto-Fix)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_permissions (
                name TEXT PRIMARY KEY,
                allowed_count INTEGER,
                denied_count INTEGER
            )
        ''')
        conn.commit()
        conn.close()

    def get_permission(self, process_name):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT allowed_count, denied_count FROM user_permissions WHERE name=?", (process_name,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return {"allowed_count": row[0], "denied_count": row[1]}
        return {"allowed_count": 0, "denied_count": 0}

    def register_permission(self, process_name, allowed):
        conn = sqlite3.connect(self.db_path)
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
        conn.commit()
        conn.close()


    def collect_system_metrics(self):
        cpu = psutil.cpu_percent(interval=None)
        memory = psutil.virtual_memory().percent
        disk_io = psutil.disk_io_counters()

        return {
            "timestamp": datetime.datetime.now().isoformat(),
            "cpu_percent": cpu,
            "memory_percent": memory,
            "disk_io_read": disk_io.read_bytes if disk_io else 0,
            "disk_io_write": disk_io.write_bytes if disk_io else 0
        }

    def collect_processes(self):
        processes = []
        now = datetime.datetime.now().isoformat()
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                # psutil cpu_percent for process is non-blocking but might need time to be accurate.
                # Since we don't want to block, we capture the instantaneous value.
                pinfo = proc.info
                processes.append({
                    "timestamp": now,
                    "pid": pinfo['pid'],
                    "name": pinfo['name'],
                    "cpu_percent": pinfo['cpu_percent'] or 0.0,
                    "memory_percent": pinfo['memory_percent'] or 0.0
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        return processes

    def save_metrics(self, sys_metrics, proc_metrics):
        conn = sqlite3.connect(self.db_path)
        
        # Inserir métricas do sistema
        system_df = pd.DataFrame([sys_metrics])
        system_df.to_sql('system_metrics', conn, if_exists='append', index=False)
        
        # Inserir métricas de processos
        if proc_metrics:
            proc_df = pd.DataFrame(proc_metrics)
            proc_df.to_sql('process_metrics', conn, if_exists='append', index=False)
            
        conn.close()

    def step(self):
        """Coleta e salva uma amostra no banco de dados."""
        sys_metrics = self.collect_system_metrics()
        proc_metrics = self.collect_processes()
        self.save_metrics(sys_metrics, proc_metrics)
        return sys_metrics, proc_metrics

if __name__ == "__main__":
    # Teste rápido
    psutil.cpu_percent(interval=1) # Inicializa os contadores
    collector = SystemCollector()
    print("Coletando métricas de teste...")
    sys_data, proc_data = collector.step()
    print(f"Sistema: {sys_data}")
    print(f"Total de processos guardados: {len(proc_data)}")
