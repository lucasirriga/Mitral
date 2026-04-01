"""Módulo da interface gráfica do SysMonitorAI."""

import collections
import datetime
from typing import Any

import customtkinter as ctk
import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from config import UI_REFRESH_INTERVAL


class SysMonitorGUI(ctk.CTk):
    """Interface gráfica principal com dashboard, gráficos, alertas e permissões."""

    MAX_LOG_LINES: int = 200

    def __init__(self, main_app) -> None:
        super().__init__()
        self.main_app = main_app
        self.title("SysMonitorAI Segurança Proativa - Mitral")
        self.geometry("900x660")

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.active_popup: bool = False

        # Controle de log com tamanho limitado
        self._log_messages: collections.deque[str] = collections.deque(maxlen=self.MAX_LOG_LINES)
        self._log_hashes: set[int] = set()

        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=0, column=0, padx=15, pady=15, sticky="nsew")
        self.tabview.add("Dashboard Seguro")
        self.tabview.add("Evolução (Gráficos)")
        self.tabview.add("Alertas de Segurança")
        self.tabview.add("Permissões Aprendidas")

        self._setup_dashboard_tab()
        self._setup_evolution_tab()
        self._setup_security_tab()
        self._setup_permissions_tab()
        self.update_ui()

    # ── Dashboard ──────────────────────────────────────────────────────────────

    def _setup_dashboard_tab(self) -> None:
        """Configura a aba de dashboard em tempo real."""
        tab = self.tabview.tab("Dashboard Seguro")
        tab.grid_columnconfigure((0, 1), weight=1)

        self.title_label = ctk.CTkLabel(tab, text="Status em Tempo Real", font=("Roboto", 22, "bold"))
        self.title_label.grid(row=0, column=0, columnspan=2, pady=10)

        self.cpu_label = ctk.CTkLabel(tab, text="CPU: 0%", font=("Roboto", 20))
        self.cpu_label.grid(row=1, column=0, pady=5)

        self.ram_label = ctk.CTkLabel(tab, text="RAM: 0%", font=("Roboto", 20))
        self.ram_label.grid(row=1, column=1, pady=5)

        self.ai_status_label = ctk.CTkLabel(
            tab, text="Modelo IA: Coletando baseline histórico...", text_color="orange"
        )
        self.ai_status_label.grid(row=2, column=0, columnspan=2, pady=5)

        # Indicador compacto de segurança (detalhes na aba dedicada)
        self.security_frame = ctk.CTkFrame(tab, fg_color="#330000", border_color="red", border_width=2)
        self.security_frame.grid(row=3, column=0, columnspan=2, pady=8, padx=10, sticky="nsew")
        self.security_label = ctk.CTkLabel(
            self.security_frame,
            text="✅ Scanner de Malware Ativo: Sem Ameaças",
            text_color="green",
            font=("Roboto", 13, "bold"),
        )
        self.security_label.pack(pady=8)

        # Log de performance
        log_frame = ctk.CTkFrame(tab, fg_color="transparent")
        log_frame.grid(row=4, column=0, columnspan=2, pady=(5, 10), padx=10, sticky="nsew")
        log_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(log_frame, text="Log de Performance", font=("Roboto", 13, "bold")).grid(
            row=0, column=0, sticky="w", pady=(0, 4)
        )
        self.log_textbox = ctk.CTkTextbox(log_frame, width=800, height=200)
        self.log_textbox.grid(row=1, column=0, sticky="nsew")
        self.log_textbox.insert("0.0", "Nenhum gargalo de performance.\n")

    # ── Evolução ───────────────────────────────────────────────────────────────

    def _setup_evolution_tab(self) -> None:
        """Configura a aba de gráficos de evolução."""
        tab = self.tabview.tab("Evolução (Gráficos)")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        self.plot_title = ctk.CTkLabel(
            tab, text="Histórico Recente e Avaliação da IA", font=("Roboto", 18, "bold")
        )
        self.plot_title.grid(row=0, column=0, pady=5)

        self.fig, (self.ax1, self.ax2) = plt.subplots(2, 1, figsize=(7, 4))
        self.fig.patch.set_facecolor('#2b2b2b')

        for ax in [self.ax1, self.ax2]:
            ax.set_facecolor('#333333')
            ax.tick_params(colors='white')
            for spine in ax.spines.values():
                spine.set_color('white')

        self.canvas = FigureCanvasTkAgg(self.fig, master=tab)
        self.canvas.get_tk_widget().grid(row=1, column=0, sticky="nsew", padx=10, pady=5)

    # ── Alertas de Segurança ───────────────────────────────────────────────────

    def _setup_security_tab(self) -> None:
        """Configura a aba de alertas de segurança detalhados."""
        tab = self.tabview.tab("Alertas de Segurança")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(tab, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header, text="Processos Suspeitos Detectados", font=("Roboto", 18, "bold")
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            header,
            text="Atualizado automaticamente a cada ciclo de escaneamento.",
            text_color="gray",
            font=("Roboto", 11),
        ).grid(row=1, column=0, sticky="w")

        # Frame scrollável para a lista de alertas
        self._security_scroll = ctk.CTkScrollableFrame(tab, fg_color="#1a1a1a")
        self._security_scroll.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        self._security_scroll.grid_columnconfigure(0, weight=1)

        self._security_empty_label = ctk.CTkLabel(
            self._security_scroll,
            text="✅ Nenhum processo suspeito detectado.",
            text_color="green",
            font=("Roboto", 14),
        )
        self._security_empty_label.grid(row=0, column=0, pady=30)

        # Registro de alertas com timestamp para histórico
        self._alert_history: list[dict[str, Any]] = []
        self._alert_history_hashes: set[int] = set()

    def _refresh_security_tab(self, alerts: list[dict[str, Any]]) -> None:
        """Atualiza a lista de alertas na aba de segurança."""
        # Adiciona novos alertas ao histórico
        for alert in alerts:
            key = hash((alert['type'], alert['name'], alert['path']))
            if key not in self._alert_history_hashes:
                self._alert_history_hashes.add(key)
                self._alert_history.append({
                    **alert,
                    "first_seen": datetime.datetime.now().strftime("%H:%M:%S"),
                })

        # Limita histórico a 50 entradas
        if len(self._alert_history) > 50:
            self._alert_history = self._alert_history[-50:]

        # Limpa o frame
        for widget in self._security_scroll.winfo_children():
            widget.destroy()

        if not self._alert_history:
            ctk.CTkLabel(
                self._security_scroll,
                text="✅ Nenhum processo suspeito detectado.",
                text_color="green",
                font=("Roboto", 14),
            ).grid(row=0, column=0, pady=30)
            return

        for i, alert in enumerate(reversed(self._alert_history)):
            is_active = any(
                a['type'] == alert['type'] and a['name'] == alert['name']
                for a in alerts
            )
            self._create_alert_card(self._security_scroll, alert, i, is_active)

    def _create_alert_card(
        self, parent, alert: dict[str, Any], row: int, is_active: bool
    ) -> None:
        """Cria um card visual para um alerta de segurança."""
        border_color = "red" if is_active else "#555555"
        bg_color = "#2a0000" if is_active else "#222222"

        card = ctk.CTkFrame(parent, fg_color=bg_color, border_color=border_color, border_width=1)
        card.grid(row=row, column=0, sticky="ew", padx=5, pady=4)
        card.grid_columnconfigure(1, weight=1)

        # Ícone de tipo
        icon = "🔴" if is_active else "🟡"
        ctk.CTkLabel(card, text=icon, font=("Roboto", 18)).grid(
            row=0, column=0, rowspan=2, padx=(10, 6), pady=8
        )

        # Tipo e nome
        status_text = "ATIVO" if is_active else "Histórico"
        ctk.CTkLabel(
            card,
            text=f"[{alert['type']}]  {alert['name']}  —  PID {alert['pid']}",
            font=("Roboto", 13, "bold"),
            text_color="red" if is_active else "#aaaaaa",
            anchor="w",
        ).grid(row=0, column=1, sticky="w", padx=5, pady=(8, 2))

        ctk.CTkLabel(
            card,
            text=f"📁 {alert['path']}",
            font=("Roboto", 11),
            text_color="#cccccc",
            anchor="w",
            wraplength=700,
        ).grid(row=1, column=1, sticky="w", padx=5, pady=(0, 2))

        ctk.CTkLabel(
            card,
            text=f"⚠  {alert['desc']}",
            font=("Roboto", 11),
            text_color="#ffaa44",
            anchor="w",
            wraplength=700,
        ).grid(row=2, column=1, sticky="w", padx=5, pady=(0, 6))

        ctk.CTkLabel(
            card,
            text=f"{status_text} · Visto às {alert['first_seen']}",
            font=("Roboto", 10),
            text_color="#888888",
            anchor="e",
        ).grid(row=0, column=2, padx=10, pady=8)

    # ── Permissões Aprendidas ──────────────────────────────────────────────────

    def _setup_permissions_tab(self) -> None:
        """Configura a aba de permissões aprendidas."""
        tab = self.tabview.tab("Permissões Aprendidas")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(tab, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header, text="Preferências Aprendidas da IA", font=("Roboto", 18, "bold")
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            header,
            text='Revogar apaga o histórico e a IA voltará a perguntar sobre o processo.',
            text_color="gray",
            font=("Roboto", 11),
        ).grid(row=1, column=0, sticky="w")

        ctk.CTkButton(
            header,
            text="↻  Atualizar",
            width=110,
            command=self._refresh_permissions_tab,
        ).grid(row=0, column=1, rowspan=2, padx=(10, 0))

        # Frame scrollável para a lista de permissões
        self._perms_scroll = ctk.CTkScrollableFrame(tab, fg_color="#1a1a1a")
        self._perms_scroll.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        self._perms_scroll.grid_columnconfigure(0, weight=1)

        self._perms_empty_label = ctk.CTkLabel(
            self._perms_scroll,
            text="Nenhuma preferência registrada ainda.",
            text_color="gray",
            font=("Roboto", 13),
        )
        self._perms_empty_label.grid(row=0, column=0, pady=30)

    def _refresh_permissions_tab(self) -> None:
        """Busca e exibe as permissões atuais no banco."""
        permissions = self.main_app.get_all_permissions()

        for widget in self._perms_scroll.winfo_children():
            widget.destroy()

        if not permissions:
            ctk.CTkLabel(
                self._perms_scroll,
                text="Nenhuma preferência registrada ainda.",
                text_color="gray",
                font=("Roboto", 13),
            ).grid(row=0, column=0, pady=30)
            return

        # Cabeçalho da tabela
        header_frame = ctk.CTkFrame(self._perms_scroll, fg_color="#2b2b2b")
        header_frame.grid(row=0, column=0, sticky="ew", padx=2, pady=(0, 4))
        header_frame.grid_columnconfigure(0, weight=1)

        for col, (text, w) in enumerate([
            ("Processo", 0), ("✅ Aprovações", 100), ("❌ Negações", 100), ("Ação", 100)
        ]):
            ctk.CTkLabel(
                header_frame, text=text, font=("Roboto", 12, "bold"),
                width=w if w else 0,
            ).grid(row=0, column=col, padx=12, pady=6, sticky="w" if col == 0 else "")

        # Linhas de permissão
        for i, perm in enumerate(permissions):
            self._create_permission_row(self._perms_scroll, perm, i + 1)

    def _create_permission_row(
        self, parent, perm: dict[str, Any], row: int
    ) -> None:
        """Cria uma linha na tabela de permissões."""
        bg = "#222222" if row % 2 == 0 else "#1e1e1e"
        frame = ctk.CTkFrame(parent, fg_color=bg, corner_radius=4)
        frame.grid(row=row, column=0, sticky="ew", padx=2, pady=1)
        frame.grid_columnconfigure(0, weight=1)

        allowed = perm["allowed_count"]
        denied = perm["denied_count"]
        total = allowed + denied
        rate = f"{allowed / total * 100:.0f}% aprovação" if total > 0 else "-"

        # Nome do processo
        ctk.CTkLabel(
            frame, text=perm["name"], font=("Roboto", 13), anchor="w"
        ).grid(row=0, column=0, sticky="w", padx=12, pady=8)

        # Aprovações
        ctk.CTkLabel(
            frame,
            text=f"{allowed}x  ({rate})",
            font=("Roboto", 12),
            text_color="#44dd88",
            width=160,
        ).grid(row=0, column=1, padx=8)

        # Negações
        ctk.CTkLabel(
            frame,
            text=f"{denied}x",
            font=("Roboto", 12),
            text_color="#ff6655" if denied > 0 else "#666666",
            width=100,
        ).grid(row=0, column=2, padx=8)

        # Botão Revogar
        ctk.CTkButton(
            frame,
            text="Revogar",
            width=90,
            height=28,
            fg_color="#993300",
            hover_color="#cc4400",
            font=("Roboto", 12),
            command=lambda name=perm["name"]: self._revoke_permission(name),
        ).grid(row=0, column=3, padx=(8, 12), pady=6)

    def _revoke_permission(self, process_name: str) -> None:
        """Revoga uma permissão e atualiza a listagem."""
        self.main_app.revoke_permission(process_name)
        self._refresh_permissions_tab()

    # ── Gráficos ───────────────────────────────────────────────────────────────

    def draw_chart(self, df: pd.DataFrame) -> None:
        """Renderiza os gráficos de evolução de CPU/RAM e score da IA."""
        if df.empty:
            return
        self.ax1.clear()
        self.ax2.clear()

        x = range(len(df))
        self.ax1.plot(x, df['cpu_percent'], label='CPU %', color='#00ff00')
        self.ax1.plot(x, df['memory_percent'], label='RAM %', color='#00aaff')
        self.ax1.set_ylim(-5, 105)
        self.ax1.legend(loc='upper right', facecolor='#2b2b2b', labelcolor='white')

        self.ax2.plot(x, df['ai_score'], label='Score IA (< 0 = Anomalia)', color='#ffaa00')
        self.ax2.axhline(0, color='red', linestyle='--', linewidth=1)
        self.ax2.legend(loc='lower left', facecolor='#2b2b2b', labelcolor='white')

        for ax in [self.ax1, self.ax2]:
            ax.set_facecolor('#333333')
            ax.tick_params(colors='white')
            for spine in ax.spines.values():
                spine.set_color('white')

        self.fig.tight_layout()
        self.canvas.draw()

    # ── Popup de permissão ─────────────────────────────────────────────────────

    def show_permission_popup(self, proc_name: str, pid: int) -> None:
        """Exibe popup pedindo permissão ao usuário para mitigar um processo."""
        self.active_popup = True
        popup = ctk.CTkToplevel(self)
        popup.title("IA Pede Permissão")
        popup.geometry("420x210")
        popup.attributes("-topmost", True)

        msg = (
            f"A IA detectou '{proc_name}' como gargalo.\n"
            f"Você permite abaixar a prioridade dele para melhorar o PC?\n"
            f"(Eu aprenderei sua preferência com o tempo)"
        )
        label = ctk.CTkLabel(popup, text=msg, wraplength=370, font=("Roboto", 14))
        label.pack(pady=22)

        def on_allow():
            self.main_app.resolve_permission(proc_name, pid, True)
            self.active_popup = False
            popup.destroy()

        def on_deny():
            self.main_app.resolve_permission(proc_name, pid, False)
            self.active_popup = False
            popup.destroy()

        btn_frame = ctk.CTkFrame(popup, fg_color="transparent")
        btn_frame.pack(pady=8)
        ctk.CTkButton(
            btn_frame, text="✅ Sim, Permitir",
            fg_color="green", hover_color="darkgreen", command=on_allow,
        ).pack(side="left", padx=10)
        ctk.CTkButton(
            btn_frame, text="❌ Não, Manter",
            fg_color="red", hover_color="darkred", command=on_deny,
        ).pack(side="right", padx=10)

        popup.protocol("WM_DELETE_WINDOW", on_deny)

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _append_log(self, msg: str, deduplicate: bool = False) -> None:
        """Adiciona uma mensagem ao log com controle de tamanho."""
        if deduplicate:
            msg_hash = hash(msg)
            if msg_hash in self._log_hashes:
                return
            self._log_hashes.add(msg_hash)

        if len(self._log_messages) >= self.MAX_LOG_LINES:
            self.log_textbox.delete("1.0", "2.0")

        self._log_messages.append(msg)
        self.log_textbox.insert("end", msg)
        self.log_textbox.see("end")

    # ── Loop de atualização ────────────────────────────────────────────────────

    def update_ui(self) -> None:
        """Atualiza a interface periodicamente com dados do backend."""
        metrics = self.main_app.get_latest_metrics()
        if metrics:
            self.cpu_label.configure(text=f"CPU: {metrics['cpu']:.1f}%")
            self.ram_label.configure(text=f"RAM: {metrics['ram']:.1f}%")

            if metrics['ai_trained']:
                self.ai_status_label.configure(
                    text="Modelo IA: Operacional ✔", text_color="green"
                )

            if metrics.get('anomaly'):
                if metrics.get('mitigated'):
                    msg = f"✅ [Auto-Fix] Resolvi a lentidão de '{metrics['culprit']}' porque aprendi com você!\n"
                else:
                    msg = f"⚠️ [Gargalo] Culpado provável: '{metrics['culprit']}'\n"
                self._append_log(msg)

        # Indicador de segurança no dashboard + atualiza aba dedicada
        alerts = self.main_app.get_security_alerts()
        if alerts:
            self.security_label.configure(
                text=f"❌ PERIGO: {len(alerts)} ameaça(s) ativa(s) — veja aba 'Alertas de Segurança'",
                text_color="red",
            )
        else:
            self.security_label.configure(
                text="✅ Scanner de Malware Ativo: Sem Ameaças", text_color="green"
            )

        current_tab = self.tabview.get()

        if current_tab == "Alertas de Segurança":
            self._refresh_security_tab(alerts)
        elif current_tab == "Evolução (Gráficos)":
            df = self.main_app.get_cached_evolution_data()
            self.draw_chart(df)
        elif current_tab == "Permissões Aprendidas":
            self._refresh_permissions_tab()

        # Exibe popup se houver permissão pendente
        if not self.active_popup:
            pending = self.main_app.get_pending_permissions()
            if pending:
                name, pid = pending[0]
                self.show_permission_popup(name, pid)

        self.after(UI_REFRESH_INTERVAL, self.update_ui)
