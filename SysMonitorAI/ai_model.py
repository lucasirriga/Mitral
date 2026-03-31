import os
import pandas as pd
import sqlite3
from sklearn.ensemble import IsolationForest

class SysMonitorAI:
    def __init__(self, db_path="sys_monitor.db"):
        self.db_path = db_path
        # contamination = auto ajusta o limite dinamicamente e é mais estável
        self.model = IsolationForest(contamination='auto', random_state=42)
        self.is_trained = False
        self.predict_count = 0
        self.my_pid = os.getpid()

    def get_training_data(self):
        try:
            conn = sqlite3.connect(self.db_path)
            # Busca os últimos 500 registros para aprendizado do baseline
            df = pd.read_sql_query("SELECT cpu_percent, memory_percent, disk_io_read, disk_io_write FROM system_metrics ORDER BY id DESC LIMIT 500", conn)
            conn.close()
            return df
        except Exception as e:
            print(f"Erro ao ler banco: {e}")
            return pd.DataFrame()

    def train_model(self):
        df = self.get_training_data()
        if len(df) > 50: # É preciso um mínimo de histórico para funcionar
            self.model.fit(df)
            self.is_trained = True
            return True
        return False

    def predict_anomaly(self, cpu, mem, disk_r, disk_w):
        self.predict_count += 1
        # Re-treina a cada 120 coletas (aprox 10 min) para atualizar o que é normal na máquina
        if not self.is_trained or self.predict_count > 120:
            self.train_model()
            self.predict_count = 0

        if not self.is_trained:
            return False # Sem dados suficientes, assuma normalidade

        data = pd.DataFrame([{
            "cpu_percent": cpu,
            "memory_percent": mem,
            "disk_io_read": disk_r,
            "disk_io_write": disk_w
        }])
        
        # IsolationForest retorna -1 para anomalia e 1 para inlier
        prediction = self.model.predict(data)
        return prediction[0] == -1

    def get_evolution_data(self):
        try:
            conn = sqlite3.connect(self.db_path)
            # Busca histórico para renderizar gráfico (últimos 60 pontos)
            df = pd.read_sql_query(
                "SELECT cpu_percent, memory_percent, disk_io_read, disk_io_write FROM system_metrics ORDER BY id DESC LIMIT 60", 
                conn
            )
            conn.close()
            
            # Inverte para ordem cronológica (antigo -> novo)
            df = df.iloc[::-1].reset_index(drop=True)
            
            # Se a IA já treinou, podemos simular a "pontuação de normalidade"
            if self.is_trained and not df.empty:
                df['ai_score'] = self.model.decision_function(
                    df[['cpu_percent', 'memory_percent', 'disk_io_read', 'disk_io_write']]
                )
            else:
                df['ai_score'] = 0.0
                
            return df
        except Exception as e:
            print(f"Erro ao buscar evolução: {e}")
            return pd.DataFrame()

    def find_culprit(self, proc_metrics_list):
        """Encontra o processo que provavelmente causou a anomalia (o maior ofensor)."""
        if not proc_metrics_list:
            return None
        
        # Ignora processo System Idle e o próprio processo do monitor
        active_procs = [p for p in proc_metrics_list if p['name'] != 'System Idle Process' and p['pid'] != self.my_pid]
        if not active_procs:
            return None
            
        # Pondera o maior ladrão de recursos como o possível causador
        culprit = max(active_procs, key=lambda p: p['cpu_percent'] + p['memory_percent'])
        return culprit
