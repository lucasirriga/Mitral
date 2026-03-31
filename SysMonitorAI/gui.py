import customtkinter as ctk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd

class SysMonitorGUI(ctk.CTk):
    def __init__(self, main_app):
        super().__init__()
        self.main_app = main_app
        self.title("SysMonitorAI Segurança Proativa - Mitral")
        self.geometry("750x600")
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.active_popup = False # Evita múltiplas janelas ao mesmo tempo
        
        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=0, column=0, padx=15, pady=15, sticky="nsew")
        self.tabview.add("Dashboard Seguro")
        self.tabview.add("Evolução (Gráficos)")
        
        self.setup_dashboard_tab()
        self.setup_evolution_tab()
        self.update_ui()

    def setup_dashboard_tab(self):
        tab = self.tabview.tab("Dashboard Seguro")
        tab.grid_columnconfigure((0, 1), weight=1)
        
        self.title_label = ctk.CTkLabel(tab, text="Status em Tempo Real", font=("Roboto", 22, "bold"))
        self.title_label.grid(row=0, column=0, columnspan=2, pady=10)
        
        self.cpu_label = ctk.CTkLabel(tab, text="CPU: 0%", font=("Roboto", 20))
        self.cpu_label.grid(row=1, column=0, pady=5)
        
        self.ram_label = ctk.CTkLabel(tab, text="RAM: 0%", font=("Roboto", 20))
        self.ram_label.grid(row=1, column=1, pady=5)

        self.ai_status_label = ctk.CTkLabel(tab, text="Modelo IA: Coletando baseline histórico...", text_color="orange")
        self.ai_status_label.grid(row=2, column=0, columnspan=2, pady=5)
        
        # Painel de Segurança e Malwares (Vermelho e Perigoso)
        self.security_frame = ctk.CTkFrame(tab, fg_color="#330000", border_color="red", border_width=2)
        self.security_frame.grid(row=3, column=0, columnspan=2, pady=10, padx=10, sticky="nsew")
        self.security_label = ctk.CTkLabel(self.security_frame, text="✅ Scanner de Malware Ativo: Sem Ameaças", text_color="green", font=("Roboto", 14, "bold"))
        self.security_label.pack(pady=10)

        # Logs de Lentidão
        self.log_textbox = ctk.CTkTextbox(tab, width=650, height=150)
        self.log_textbox.grid(row=4, column=0, columnspan=2, pady=(10, 10))
        self.log_textbox.insert("0.0", "Nenhum gargalo de performance.\n")

    def setup_evolution_tab(self):
        tab = self.tabview.tab("Evolução (Gráficos)")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)
        
        self.plot_title = ctk.CTkLabel(tab, text="Histórico Recente e Avaliação da IA", font=("Roboto", 18, "bold"))
        self.plot_title.grid(row=0, column=0, pady=5)

        self.fig, (self.ax1, self.ax2) = plt.subplots(2, 1, figsize=(6, 4))
        self.fig.patch.set_facecolor('#2b2b2b')
        
        for ax in [self.ax1, self.ax2]:
            ax.set_facecolor('#333333')
            ax.tick_params(colors='white')
            for spine in ax.spines.values():
                spine.set_color('white')
                
        self.canvas = FigureCanvasTkAgg(self.fig, master=tab)
        self.canvas.get_tk_widget().grid(row=1, column=0, sticky="nsew", padx=10, pady=5)

    def draw_chart(self, df):
        if df.empty: return
        self.ax1.clear()
        self.ax2.clear()

        x = range(len(df))
        self.ax1.plot(x, df['cpu_percent'], label='CPU %', color='#00ff00')
        self.ax1.plot(x, df['memory_percent'], label='RAM %', color='#00aaff')
        self.ax1.set_ylim(-5, 105)
        self.ax1.legend(loc='upper right', facecolor='#2b2b2b', labelcolor='white')
        
        self.ax2.plot(x, df['ai_score'], label='Score da IA (Abaixo de Zero = Anomalia)', color='#ffaa00')
        self.ax2.axhline(0, color='red', linestyle='--', linewidth=1)
        self.ax2.legend(loc='lower left', facecolor='#2b2b2b', labelcolor='white')
        
        for ax in [self.ax1, self.ax2]:
            ax.set_facecolor('#333333')
            ax.tick_params(colors='white')
            for spine in ax.spines.values():
                spine.set_color('white')
                
        self.fig.tight_layout()
        self.canvas.draw()

    def show_permission_popup(self, proc_name, pid):
        self.active_popup = True
        popup = ctk.CTkToplevel(self)
        popup.title("IA Pede Permissão")
        popup.geometry("400x200")
        popup.attributes("-topmost", True)
        
        msg = f"A IA detectou '{proc_name}' como gargalo.\nVocê permite abaixar a prioridade dele para melhorar o PC?\n(Eu aprenderei sua preferência com o tempo)"
        label = ctk.CTkLabel(popup, text=msg, wraplength=350, font=("Roboto", 14))
        label.pack(pady=20)
        
        def on_allow():
            self.main_app.resolve_permission(proc_name, pid, True)
            self.active_popup = False
            popup.destroy()
            
        def on_deny():
            self.main_app.resolve_permission(proc_name, pid, False)
            self.active_popup = False
            popup.destroy()

        btn_frame = ctk.CTkFrame(popup, fg_color="transparent")
        btn_frame.pack(pady=10)
        ctk.CTkButton(btn_frame, text="✅ Sim, Permitir", fg_color="green", hover_color="darkgreen", command=on_allow).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="❌ Não, Manter", fg_color="red", hover_color="darkred", command=on_deny).pack(side="right", padx=10)
        
        # Se usuário fechar pelo X, conta como no
        popup.protocol("WM_DELETE_WINDOW", on_deny)

    def update_ui(self):
        metrics = self.main_app.get_latest_metrics()
        if metrics:
            self.cpu_label.configure(text=f"CPU: {metrics['cpu']:.1f}%")
            self.ram_label.configure(text=f"RAM: {metrics['ram']:.1f}%")
            
            if metrics['ai_trained']:
                self.ai_status_label.configure(text="Modelo IA: Operacional (Verificando estado)", text_color="green")
            
            if metrics.get('anomaly'):
                if metrics.get('mitigated'):
                    msg = f"✅ [Auto-Fix] Resolvi a lentidão de '{metrics['culprit']}' porque aprendi com você!\n"
                else:
                    msg = f"⚠️ [Gargalo] Lentidão por culpado provável: '{metrics['culprit']}'\n"
                self.log_textbox.insert("end", msg)
                self.log_textbox.see("end")

        # Atualiza o quadro de Malwares
        alerts = self.main_app.get_security_alerts()
        if alerts:
            self.security_label.configure(
                text=f"❌ PERIGO: {len(alerts)} atividade(s) maliciosa(s) detectada(s)!\nVerifique o Painel.", 
                text_color="white"
            )
            # Loga os perigos apenas se não já logou antes
            for alert in alerts:
                msg = f"[!!!] {alert['type']}: Processo '{alert['name']}' em '{alert['path']}'.\nMotivo: {alert['desc']}\n"
                # Um jeito rudimentar de nao inundar a textbox infinitamente
                if msg not in self.log_textbox.get("0.0", "end"):
                    self.log_textbox.insert("end", msg)
                    self.log_textbox.see("end")
        else:
            self.security_label.configure(text="✅ Scanner de Malware Ativo: Sem Ameaças", text_color="green")

        # Exibe popup se tiver na fila e nao houver outro ativo
        if not self.active_popup:
            pending = self.main_app.get_pending_permissions()
            if pending:
                name, pid = pending[0]
                self.show_permission_popup(name, pid)
                
        if self.tabview.get() == "Evolução (Gráficos)":
            df = self.main_app.ai.get_evolution_data()
            self.draw_chart(df)
                
        self.after(2000, self.update_ui)
