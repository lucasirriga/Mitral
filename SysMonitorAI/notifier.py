from plyer import notification
import time

class Notifier:
    def __init__(self):
        self.last_alert_time = 0
        self.cooldown = 30 # Segundos de espera entre alertas para evitar spam

    def send_anomaly_alert(self, proc_name, memory_percent, cpu_percent):
        current_time = time.time()
        if current_time - self.last_alert_time < self.cooldown:
            return # Evita poluir a tela do usuário

        title = "Gargalo Detectado pela IA!"
        message = f"O processo '{proc_name}' pode estar causando lentidão na máquina.\nConsumo:\nCPU: {cpu_percent:.1f}%\nRAM: {memory_percent:.1f}%"
        
        try:
            notification.notify(
                title=title,
                message=message,
                app_name="SysMonitorAI",
                timeout=8  # Dura 8 segundos na tela
            )
            self.last_alert_time = current_time
        except Exception as e:
            print(f"Erro ao enviar notificação: {e}")
