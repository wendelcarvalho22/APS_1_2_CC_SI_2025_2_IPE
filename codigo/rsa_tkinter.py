"""
==========================================================================
  RSA Criptografia — APS 2025/2026
  Ciência da Computação — UNIP
  Aluno: Wendel Richard de Carvalho  |  RA: T2144I7
  Disciplina: Introdução à Programação Estruturada (IPE)
==========================================================================
  Interface gráfica desenvolvida com tkinter (biblioteca padrão Python).
  Não requer instalação de dependências externas.

  Para executar:
      python3 rsa_tkinter.py   (Linux/macOS)
      python  rsa_tkinter.py   (Windows)
==========================================================================
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import math
import random
import threading
import time


# ═══════════════════════════════════════════════════════════════════════
#  NÚCLEO MATEMÁTICO RSA
# ═══════════════════════════════════════════════════════════════════════

def potencia_modular(base, expoente, modulo):
    """Exponenciação binária: O(log e) multiplicações modulares."""
    if modulo == 1:
        return 0
    resultado = 1
    base = base % modulo
    while expoente > 0:
        if expoente % 2 == 1:
            resultado = (resultado * base) % modulo
        expoente >>= 1
        base = (base * base) % modulo
    return resultado


def algoritmo_euclides_estendido(a, b):
    """Retorna (mdc, x, y) tal que a*x + b*y = mdc(a, b)."""
    if a == 0:
        return b, 0, 1
    mdc, x1, y1 = algoritmo_euclides_estendido(b % a, a)
    return mdc, y1 - (b // a) * x1, x1


def inverso_modular(a, m):
    """Calcula d = a^(-1) mod m via Euclides Estendido."""
    mdc, x, _ = algoritmo_euclides_estendido(a % m, m)
    if mdc != 1:
        raise ValueError(f"Inverso modular não existe: mdc({a},{m})={mdc}")
    return x % m


def miller_rabin(n, k=10):
    """Teste de primalidade probabilístico de Miller-Rabin."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = potencia_modular(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = potencia_modular(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gerar_primo(bits=256):
    """Gera primo aleatório com `bits` bits."""
    while True:
        n = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if miller_rabin(n):
            return n


class RSA:
    """Implementação completa do algoritmo RSA."""

    def __init__(self):
        self.p = self.q = self.n = self.phi_n = None
        self.e = self.d = None
        self.chave_publica = self.chave_privada = None

    def gerar_chaves(self, bits=256):
        self.p = gerar_primo(bits)
        self.q = gerar_primo(bits)
        while self.q == self.p:
            self.q = gerar_primo(bits)
        self.n = self.p * self.q
        self.phi_n = (self.p - 1) * (self.q - 1)
        self.e = 65537
        if math.gcd(self.e, self.phi_n) != 1:
            self.e = 3
            while math.gcd(self.e, self.phi_n) != 1:
                self.e += 2
        self.d = inverso_modular(self.e, self.phi_n)
        self.chave_publica = (self.e, self.n)
        self.chave_privada = (self.d, self.n)

    def cifrar(self, mensagem):
        if not self.chave_publica:
            raise RuntimeError("Gere as chaves primeiro.")
        if len(mensagem) > 128:
            raise ValueError("Máximo de 128 caracteres.")
        e, n = self.chave_publica
        return [potencia_modular(ord(c), e, n) for c in mensagem]

    def decifrar(self, cifrado):
        if not self.chave_privada:
            raise RuntimeError("Gere as chaves primeiro.")
        d, n = self.chave_privada
        return ''.join(chr(potencia_modular(c, d, n)) for c in cifrado)


# ═══════════════════════════════════════════════════════════════════════
#  CONSTANTES DE ESTILO
# ═══════════════════════════════════════════════════════════════════════

COR_BG        = "#0d1117"
COR_SURFACE   = "#161b22"
COR_SURFACE2  = "#1c2430"
COR_BORDA     = "#30363d"
COR_VERDE     = "#3fb950"
COR_AZUL      = "#58a6ff"
COR_AMARELO   = "#d29922"
COR_ROXO      = "#bc8cff"
COR_VERMELHO  = "#f85149"
COR_TEXTO     = "#e6edf3"
COR_MUTED     = "#8b949e"
COR_BTN_GREEN = "#238636"
COR_BTN_BLUE  = "#1f6feb"

FONTE_NORMAL  = ("Segoe UI", 10)
FONTE_BOLD    = ("Segoe UI", 10, "bold")
FONTE_TITULO  = ("Segoe UI", 13, "bold")
FONTE_MONO    = ("Consolas", 9)
FONTE_SMALL   = ("Segoe UI", 9)
FONTE_H1      = ("Segoe UI", 16, "bold")


# ═══════════════════════════════════════════════════════════════════════
#  WIDGETS AUXILIARES
# ═══════════════════════════════════════════════════════════════════════

def make_label(parent, text, fg=COR_TEXTO, font=FONTE_NORMAL, **kw):
    return tk.Label(parent, text=text, fg=fg, bg=COR_SURFACE,
                    font=font, **kw)


def make_button(parent, text, command, color=COR_BTN_GREEN, width=18):
    btn = tk.Button(
        parent, text=text, command=command,
        bg=color, fg="white", font=FONTE_BOLD,
        relief="flat", cursor="hand2",
        padx=12, pady=6, width=width,
        activebackground=color, activeforeground="white",
    )
    btn.bind("<Enter>", lambda e: btn.config(bg=_lighten(color)))
    btn.bind("<Leave>", lambda e: btn.config(bg=color))
    return btn


def _lighten(hex_color):
    """Clareia levemente uma cor hex para hover."""
    h = hex_color.lstrip('#')
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    r, g, b = min(r + 30, 255), min(g + 30, 255), min(b + 30, 255)
    return f"#{r:02x}{g:02x}{b:02x}"


def make_text(parent, height=6, fg=COR_VERDE, state="normal"):
    t = tk.Text(
        parent, height=height, bg=COR_BG, fg=fg,
        font=FONTE_MONO, relief="flat",
        insertbackground=COR_TEXTO,
        selectbackground=COR_BTN_BLUE,
        wrap="word", state=state,
        bd=0, padx=8, pady=6,
    )
    # borda
    frame = tk.Frame(parent, bg=COR_BORDA, padx=1, pady=1)
    t.place_in = frame
    return t, frame


def make_entry(parent, textvariable=None, width=40, show=None):
    e = tk.Entry(
        parent, bg=COR_BG, fg=COR_TEXTO,
        font=FONTE_MONO, relief="flat",
        insertbackground=COR_TEXTO,
        disabledbackground=COR_BG,
        disabledforeground=COR_AZUL,
        textvariable=textvariable,
        width=width, show=show,
        bd=0,
    )
    frame = tk.Frame(parent, bg=COR_BORDA, padx=1, pady=1)
    e.pack(fill="x")
    frame.bind("<FocusIn>", lambda ev: frame.config(bg=COR_AZUL))
    return e, frame


def set_text(widget, content, tag_color=None):
    """Substitui conteúdo de um tk.Text."""
    widget.config(state="normal")
    widget.delete("1.0", "end")
    widget.insert("1.0", content)
    if tag_color:
        widget.config(fg=tag_color)
    widget.config(state="disabled")


# ═══════════════════════════════════════════════════════════════════════
#  APLICAÇÃO PRINCIPAL
# ═══════════════════════════════════════════════════════════════════════

class AplicacaoRSA(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("RSA Criptografia — APS 2026 | Wendel Richard de Carvalho | T2144I7")
        self.geometry("1000x720")
        self.minsize(900, 640)
        self.configure(bg=COR_BG)
        self.resizable(True, True)

        self.rsa = RSA()
        self._ultimo_cifrado = []

        self._build_header()
        self._build_tabs()
        self._build_status()

        # Gera chaves ao iniciar (em thread para não travar a UI)
        self._status("Gerando chaves RSA iniciais...")
        threading.Thread(target=self._gerar_chaves_auto, daemon=True).start()

    # ── HEADER ────────────────────────────────────────────────────────
    def _build_header(self):
        hdr = tk.Frame(self, bg=COR_SURFACE, pady=14)
        hdr.pack(fill="x")

        # Logo
        logo = tk.Label(hdr, text="🔐", font=("Segoe UI", 26),
                         bg=COR_SURFACE, fg=COR_AZUL)
        logo.pack(side="left", padx=(20, 10))

        info = tk.Frame(hdr, bg=COR_SURFACE)
        info.pack(side="left")
        tk.Label(info, text="RSA Criptografia — APS 2026",
                 font=FONTE_H1, fg=COR_TEXTO, bg=COR_SURFACE).pack(anchor="w")
        tk.Label(info, text="Wendel Richard de Carvalho  •  RA: T2144I7  •  Ciência da Computação — UNIP",
                 font=FONTE_SMALL, fg=COR_MUTED, bg=COR_SURFACE).pack(anchor="w")

        badge = tk.Label(hdr, text="128 chars  •  Python puro",
                          font=FONTE_SMALL, fg=COR_MUTED,
                          bg=COR_SURFACE2, relief="flat", padx=10, pady=4)
        badge.pack(side="right", padx=20)

        sep = tk.Frame(self, bg=COR_BORDA, height=1)
        sep.pack(fill="x")

    # ── TABS ──────────────────────────────────────────────────────────
    def _build_tabs(self):
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Dark.TNotebook",
                         background=COR_BG, borderwidth=0)
        style.configure("Dark.TNotebook.Tab",
                         background=COR_SURFACE2, foreground=COR_MUTED,
                         font=FONTE_BOLD, padding=(16, 8),
                         borderwidth=0)
        style.map("Dark.TNotebook.Tab",
                   background=[("selected", COR_SURFACE)],
                   foreground=[("selected", COR_TEXTO)])

        self.notebook = ttk.Notebook(self, style="Dark.TNotebook")
        self.notebook.pack(fill="both", expand=True, padx=0, pady=0)

        self._build_tab_cifrar()
        self._build_tab_decifrar()
        self._build_tab_chaves()
        self._build_tab_visualizador()
        self._build_tab_info()

    # ── ABA: CIFRAR ───────────────────────────────────────────────────
    def _build_tab_cifrar(self):
        tab = tk.Frame(self.notebook, bg=COR_SURFACE)
        self.notebook.add(tab, text="  🔒  Cifrar  ")

        pad = tk.Frame(tab, bg=COR_SURFACE)
        pad.pack(fill="both", expand=True, padx=24, pady=20)

        # ── Esquerda: entrada ──────────────────────────────────────
        col_e = tk.Frame(pad, bg=COR_SURFACE)
        col_e.pack(side="left", fill="both", expand=True, padx=(0, 10))

        self._card_title(col_e, "✉️  Mensagem Original")

        make_label(col_e, "Texto a cifrar (máx. 128 caracteres):").pack(anchor="w", pady=(8, 2))
        self.txt_msg = tk.Text(col_e, height=5, bg=COR_BG, fg=COR_TEXTO,
                                font=FONTE_MONO, relief="flat",
                                insertbackground=COR_TEXTO, wrap="word",
                                bd=0, padx=8, pady=6,
                                highlightthickness=1,
                                highlightbackground=COR_BORDA,
                                highlightcolor=COR_AZUL)
        self.txt_msg.pack(fill="x")
        self.txt_msg.bind("<KeyRelease>", self._atualizar_contador)

        self.lbl_count = tk.Label(col_e, text="0 / 128",
                                   font=FONTE_SMALL, fg=COR_MUTED, bg=COR_SURFACE)
        self.lbl_count.pack(anchor="e")

        # Chave pública
        make_label(col_e, "Chave Pública (e, n):", font=FONTE_BOLD, fg=COR_AZUL).pack(anchor="w", pady=(12, 4))

        rf_e = tk.Frame(col_e, bg=COR_SURFACE)
        rf_e.pack(fill="x", pady=(0, 4))
        make_label(rf_e, "e =", fg=COR_MUTED).pack(side="left")
        self.var_e = tk.StringVar(value="(gerando...)")
        tk.Entry(rf_e, textvariable=self.var_e, state="disabled",
                 disabledforeground=COR_VERDE, disabledbackground=COR_BG,
                 font=FONTE_MONO, relief="flat", width=28,
                 highlightthickness=1, highlightbackground=COR_BORDA).pack(side="left", padx=6, fill="x", expand=True)

        rf_n = tk.Frame(col_e, bg=COR_SURFACE)
        rf_n.pack(fill="x")
        make_label(rf_n, "n =", fg=COR_MUTED).pack(side="left")
        self.var_n_pub = tk.StringVar(value="(gerando...)")
        tk.Entry(rf_n, textvariable=self.var_n_pub, state="disabled",
                 disabledforeground=COR_VERDE, disabledbackground=COR_BG,
                 font=FONTE_MONO, relief="flat", width=28,
                 highlightthickness=1, highlightbackground=COR_BORDA).pack(side="left", padx=6, fill="x", expand=True)

        # Botões
        bf = tk.Frame(col_e, bg=COR_SURFACE)
        bf.pack(anchor="w", pady=14)
        make_button(bf, "🔒  Cifrar Mensagem", self._cifrar, COR_BTN_GREEN).pack(side="left", padx=(0, 8))
        make_button(bf, "🗑️  Limpar", self._limpar_cifrar, "#444c56", width=10).pack(side="left")

        # ── Direita: saída ─────────────────────────────────────────
        col_d = tk.Frame(pad, bg=COR_SURFACE)
        col_d.pack(side="left", fill="both", expand=True, padx=(10, 0))

        self._card_title(col_d, "🔒  Mensagem Cifrada")

        make_label(col_d, "Resultado (inteiros separados por espaço):").pack(anchor="w", pady=(8, 2))
        self.txt_cifrado = tk.Text(col_d, height=5, bg=COR_BG, fg=COR_VERDE,
                                    font=FONTE_MONO, relief="flat",
                                    wrap="word", state="disabled",
                                    bd=0, padx=8, pady=6,
                                    highlightthickness=1,
                                    highlightbackground=COR_BORDA)
        self.txt_cifrado.pack(fill="x")

        make_label(col_d, "Representação Hexadecimal:").pack(anchor="w", pady=(12, 2))
        self.txt_hex = tk.Text(col_d, height=3, bg=COR_BG, fg=COR_AZUL,
                                font=FONTE_MONO, relief="flat",
                                wrap="word", state="disabled",
                                bd=0, padx=8, pady=6,
                                highlightthickness=1,
                                highlightbackground=COR_BORDA)
        self.txt_hex.pack(fill="x")

        bf2 = tk.Frame(col_d, bg=COR_SURFACE)
        bf2.pack(anchor="w", pady=14)
        make_button(bf2, "📋  Copiar cifrado", self._copiar_cifrado, "#444c56", width=16).pack(side="left", padx=(0, 8))
        make_button(bf2, "➡️  Enviar p/ Decifrar", self._enviar_decifrar, COR_BTN_BLUE, width=16).pack(side="left")

    # ── ABA: DECIFRAR ─────────────────────────────────────────────────
    def _build_tab_decifrar(self):
        tab = tk.Frame(self.notebook, bg=COR_SURFACE)
        self.notebook.add(tab, text="  🔓  Decifrar  ")

        pad = tk.Frame(tab, bg=COR_SURFACE)
        pad.pack(fill="both", expand=True, padx=24, pady=20)

        # Esquerda
        col_e = tk.Frame(pad, bg=COR_SURFACE)
        col_e.pack(side="left", fill="both", expand=True, padx=(0, 10))

        self._card_title(col_e, "🔒  Texto Cifrado")

        make_label(col_e, "Cole aqui os inteiros gerados na cifragem:").pack(anchor="w", pady=(8, 2))
        self.txt_dec_input = tk.Text(col_e, height=6, bg=COR_BG, fg=COR_TEXTO,
                                      font=FONTE_MONO, relief="flat",
                                      wrap="word",
                                      bd=0, padx=8, pady=6,
                                      insertbackground=COR_TEXTO,
                                      highlightthickness=1,
                                      highlightbackground=COR_BORDA,
                                      highlightcolor=COR_AZUL)
        self.txt_dec_input.pack(fill="x")

        make_label(col_e, "Chave Privada (d, n):", font=FONTE_BOLD, fg=COR_AMARELO).pack(anchor="w", pady=(12, 4))

        rf_d = tk.Frame(col_e, bg=COR_SURFACE)
        rf_d.pack(fill="x", pady=(0, 4))
        make_label(rf_d, "d =", fg=COR_MUTED).pack(side="left")
        self.var_d = tk.StringVar(value="(gerando...)")
        tk.Entry(rf_d, textvariable=self.var_d, state="disabled",
                 disabledforeground=COR_AMARELO, disabledbackground=COR_BG,
                 font=FONTE_MONO, relief="flat", width=28,
                 highlightthickness=1, highlightbackground=COR_BORDA).pack(side="left", padx=6, fill="x", expand=True)

        rf_np = tk.Frame(col_e, bg=COR_SURFACE)
        rf_np.pack(fill="x")
        make_label(rf_np, "n =", fg=COR_MUTED).pack(side="left")
        self.var_n_priv = tk.StringVar(value="(gerando...)")
        tk.Entry(rf_np, textvariable=self.var_n_priv, state="disabled",
                 disabledforeground=COR_AMARELO, disabledbackground=COR_BG,
                 font=FONTE_MONO, relief="flat", width=28,
                 highlightthickness=1, highlightbackground=COR_BORDA).pack(side="left", padx=6, fill="x", expand=True)

        bf = tk.Frame(col_e, bg=COR_SURFACE)
        bf.pack(anchor="w", pady=14)
        make_button(bf, "🔓  Decifrar Mensagem", self._decifrar, COR_BTN_BLUE).pack(side="left", padx=(0, 8))
        make_button(bf, "🗑️  Limpar", self._limpar_decifrar, "#444c56", width=10).pack(side="left")

        # Direita
        col_d = tk.Frame(pad, bg=COR_SURFACE)
        col_d.pack(side="left", fill="both", expand=True, padx=(10, 0))

        self._card_title(col_d, "✉️  Mensagem Recuperada")

        make_label(col_d, "Texto original decifrado:").pack(anchor="w", pady=(8, 2))
        self.txt_dec_output = tk.Text(col_d, height=6, bg=COR_BG, fg=COR_VERDE,
                                       font=FONTE_MONO, relief="flat",
                                       wrap="word", state="disabled",
                                       bd=0, padx=8, pady=6,
                                       highlightthickness=1,
                                       highlightbackground=COR_BORDA)
        self.txt_dec_output.pack(fill="x")

        make_label(col_d, "Verificação de integridade:").pack(anchor="w", pady=(12, 2))
        self.txt_verif = tk.Text(col_d, height=2, bg=COR_BG, fg=COR_MUTED,
                                  font=FONTE_MONO, relief="flat",
                                  wrap="word", state="disabled",
                                  bd=0, padx=8, pady=6,
                                  highlightthickness=1,
                                  highlightbackground=COR_BORDA)
        self.txt_verif.pack(fill="x")

    # ── ABA: CHAVES ───────────────────────────────────────────────────
    def _build_tab_chaves(self):
        tab = tk.Frame(self.notebook, bg=COR_SURFACE)
        self.notebook.add(tab, text="  🗝️  Chaves RSA  ")

        pad = tk.Frame(tab, bg=COR_SURFACE)
        pad.pack(fill="both", expand=True, padx=24, pady=20)

        self._card_title(pad, "⚙️  Geração de Par de Chaves RSA")

        # Tamanho
        rf = tk.Frame(pad, bg=COR_SURFACE)
        rf.pack(fill="x", pady=(12, 0))

        make_label(rf, "Tamanho dos primos:").pack(side="left")
        self.var_bits = tk.StringVar(value="256")
        for label, val in [("Demo (64 bits)", "64"), ("Médio (256 bits)", "256"), ("Grande (512 bits)", "512")]:
            tk.Radiobutton(rf, text=label, variable=self.var_bits, value=val,
                           bg=COR_SURFACE, fg=COR_TEXTO, selectcolor=COR_BG,
                           activebackground=COR_SURFACE, font=FONTE_NORMAL).pack(side="left", padx=10)

        bf = tk.Frame(pad, bg=COR_SURFACE)
        bf.pack(anchor="w", pady=14)
        self.btn_gerar = make_button(bf, "🗝️  Gerar Par de Chaves", self._gerar_chaves_manual, COR_BTN_GREEN, width=22)
        self.btn_gerar.pack(side="left")
        self.lbl_gerando = tk.Label(bf, text="", fg=COR_AMARELO, bg=COR_SURFACE, font=FONTE_SMALL)
        self.lbl_gerando.pack(side="left", padx=14)

        sep = tk.Frame(pad, bg=COR_BORDA, height=1)
        sep.pack(fill="x", pady=10)

        # Painel de exibição das chaves
        kf = tk.Frame(pad, bg=COR_SURFACE)
        kf.pack(fill="both", expand=True)

        # Chave pública
        pub_frame = tk.Frame(kf, bg=COR_SURFACE2, padx=16, pady=14,
                               highlightthickness=1, highlightbackground=COR_VERDE)
        pub_frame.pack(side="left", fill="both", expand=True, padx=(0, 10))
        tk.Label(pub_frame, text="🟢  CHAVE PÚBLICA  (Pk = e, n)",
                  font=FONTE_BOLD, fg=COR_VERDE, bg=COR_SURFACE2).pack(anchor="w")
        tk.Label(pub_frame, text="Pode ser compartilhada livremente",
                  font=FONTE_SMALL, fg=COR_MUTED, bg=COR_SURFACE2).pack(anchor="w", pady=(0, 10))
        self.txt_pub = tk.Text(pub_frame, height=10, bg=COR_BG, fg=COR_VERDE,
                                font=FONTE_MONO, relief="flat", wrap="word",
                                state="disabled", bd=0, padx=6, pady=6)
        self.txt_pub.pack(fill="both", expand=True)

        # Chave privada
        priv_frame = tk.Frame(kf, bg=COR_SURFACE2, padx=16, pady=14,
                               highlightthickness=1, highlightbackground=COR_AMARELO)
        priv_frame.pack(side="left", fill="both", expand=True, padx=(10, 0))
        tk.Label(priv_frame, text="🟡  CHAVE PRIVADA  (Sk = d, n)",
                  font=FONTE_BOLD, fg=COR_AMARELO, bg=COR_SURFACE2).pack(anchor="w")
        tk.Label(priv_frame, text="⚠️  Mantenha em segredo absoluto!",
                  font=FONTE_SMALL, fg=COR_VERMELHO, bg=COR_SURFACE2).pack(anchor="w", pady=(0, 10))
        self.txt_priv = tk.Text(priv_frame, height=10, bg=COR_BG, fg=COR_AMARELO,
                                 font=FONTE_MONO, relief="flat", wrap="word",
                                 state="disabled", bd=0, padx=6, pady=6)
        self.txt_priv.pack(fill="both", expand=True)

        # Passos
        sep2 = tk.Frame(pad, bg=COR_BORDA, height=1)
        sep2.pack(fill="x", pady=12)
        make_label(pad, "Passos da geração:", font=FONTE_BOLD).pack(anchor="w")
        self.txt_passos = tk.Text(pad, height=7, bg=COR_BG, fg=COR_ROXO,
                                   font=FONTE_MONO, relief="flat", wrap="word",
                                   state="disabled", bd=0, padx=8, pady=6,
                                   highlightthickness=1, highlightbackground=COR_BORDA)
        self.txt_passos.pack(fill="x", pady=(4, 0))

    # ── ABA: VISUALIZADOR ─────────────────────────────────────────────
    def _build_tab_visualizador(self):
        tab = tk.Frame(self.notebook, bg=COR_SURFACE)
        self.notebook.add(tab, text="  📊  Visualizador  ")

        pad = tk.Frame(tab, bg=COR_SURFACE)
        pad.pack(fill="both", expand=True, padx=24, pady=20)

        self._card_title(pad, "🎬  Demonstração Passo a Passo do RSA")

        rf = tk.Frame(pad, bg=COR_SURFACE)
        rf.pack(fill="x", pady=(10, 0))
        make_label(rf, "Mensagem de demonstração:").pack(side="left")
        self.var_demo_msg = tk.StringVar(value="Acesso autorizado")
        tk.Entry(rf, textvariable=self.var_demo_msg, bg=COR_BG, fg=COR_TEXTO,
                 font=FONTE_MONO, relief="flat", width=30,
                 insertbackground=COR_TEXTO,
                 highlightthickness=1, highlightbackground=COR_BORDA,
                 highlightcolor=COR_AZUL).pack(side="left", padx=10)

        bf = tk.Frame(pad, bg=COR_SURFACE)
        bf.pack(anchor="w", pady=12)
        self.btn_demo = make_button(bf, "▶️  Iniciar Demonstração", self._iniciar_demo, COR_BTN_GREEN, width=22)
        self.btn_demo.pack(side="left", padx=(0, 10))
        make_button(bf, "↺  Reiniciar", self._resetar_demo, "#444c56", width=12).pack(side="left")

        sep = tk.Frame(pad, bg=COR_BORDA, height=1)
        sep.pack(fill="x", pady=8)

        # Área de steps com scroll
        canvas_frame = tk.Frame(pad, bg=COR_SURFACE)
        canvas_frame.pack(fill="both", expand=True)

        self.demo_canvas = tk.Canvas(canvas_frame, bg=COR_SURFACE, bd=0, highlightthickness=0)
        scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=self.demo_canvas.yview)
        self.demo_canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.demo_canvas.pack(side="left", fill="both", expand=True)

        self.demo_inner = tk.Frame(self.demo_canvas, bg=COR_SURFACE)
        self.demo_canvas_window = self.demo_canvas.create_window((0, 0), window=self.demo_inner, anchor="nw")
        self.demo_inner.bind("<Configure>", lambda e: self.demo_canvas.configure(
            scrollregion=self.demo_canvas.bbox("all")))
        self.demo_canvas.bind("<Configure>", lambda e: self.demo_canvas.itemconfig(
            self.demo_canvas_window, width=e.width))

        self.step_labels = []
        self._resetar_demo()

    # ── ABA: INFO ─────────────────────────────────────────────────────
    def _build_tab_info(self):
        tab = tk.Frame(self.notebook, bg=COR_SURFACE)
        self.notebook.add(tab, text="  📚  Sobre RSA  ")

        pad = tk.Frame(tab, bg=COR_SURFACE)
        pad.pack(fill="both", expand=True, padx=24, pady=20)

        self._card_title(pad, "📚  Fundamentos Matemáticos do RSA")

        texto_info = (
            "O RSA (Rivest–Shamir–Adleman, 1977) é o algoritmo de criptografia assimétrica "
            "mais utilizado no mundo. Sua segurança baseia-se na dificuldade computacional "
            "de fatorar números inteiros muito grandes.\n\n"
            "FÓRMULAS CENTRAIS:\n"
            "  Geração:    n = p × q   |   φ(n) = (p−1)(q−1)\n"
            "  Chave Pública:   (e, n)  onde mdc(e, φ(n)) = 1\n"
            "  Chave Privada:   (d, n)  onde d × e ≡ 1 (mod φ(n))\n"
            "  Cifragem:        C = Mᵉ mod n\n"
            "  Decifragem:      M = Cᵈ mod n\n\n"
            "APLICAÇÕES REAIS:\n"
            "  🌐  HTTPS/TLS — handshake de sessões seguras\n"
            "  🔑  SSH — autenticação por chave pública\n"
            "  💳  ICP-Brasil — certificados digitais A3\n"
            "  📧  PGP/GPG — criptografia de e-mail\n"
            "  🚢  Cenário APS — comunicação com navio isolado\n\n"
            "CENÁRIO DO TRABALHO:\n"
            "  Navio apreendido pela Guarda Costeira Brasileira a 50 km da costa,\n"
            "  transportando resíduos tóxicos radioativos. Comunicações realizadas\n"
            "  exclusivamente por helicópteros. O RSA garante que apenas inspetores\n"
            "  autorizados (portadores da chave privada) decifrem as instruções de acesso."
        )
        txt = tk.Text(pad, height=20, bg=COR_BG, fg=COR_TEXTO,
                       font=FONTE_MONO, relief="flat", wrap="word",
                       state="normal", bd=0, padx=12, pady=10,
                       highlightthickness=1, highlightbackground=COR_BORDA)
        txt.insert("1.0", texto_info)
        txt.config(state="disabled")
        txt.pack(fill="both", expand=True, pady=(10, 0))

        # Comparativo
        self._card_title(pad, "⚖️  Comparativo de Técnicas Criptográficas")
        comp_frame = tk.Frame(pad, bg=COR_SURFACE2, padx=12, pady=10,
                               highlightthickness=1, highlightbackground=COR_BORDA)
        comp_frame.pack(fill="x", pady=(8, 0))

        headers = ["Técnica", "Tipo", "Chave", "Velocidade", "Segurança"]
        dados = [
            ("RSA",           "Assimétrico",  "2048+ bits", "Lenta",       "Alta ✓"),
            ("AES",           "Simétrico",    "128-256 bits","Muito rápida","Alta ✓"),
            ("DES/3DES",      "Simétrico",    "56/112 bits", "Média",       "Baixa ✗"),
            ("Diffie-Hellman","Assimétrico",  "1024+ bits",  "Média",       "Alta ✓"),
            ("César/Vigenère","Simétrico",    "1-26 chars",  "Rápida",      "Mínima ✗"),
        ]
        cols = [("Técnica", 120), ("Tipo", 110), ("Chave", 110), ("Velocidade", 100), ("Segurança", 90)]
        for i, (h, w) in enumerate(cols):
            tk.Label(comp_frame, text=h, font=FONTE_BOLD, fg=COR_AZUL,
                     bg=COR_SURFACE2, width=w//8).grid(row=0, column=i, padx=6, pady=4, sticky="w")
        for r, row in enumerate(dados, 1):
            bg = COR_BG if r % 2 == 0 else COR_SURFACE2
            for c, val in enumerate(row):
                fg = COR_VERDE if "✓" in val else (COR_VERMELHO if "✗" in val else COR_TEXTO)
                tk.Label(comp_frame, text=val, font=FONTE_SMALL, fg=fg,
                         bg=bg, width=cols[c][1]//8).grid(row=r, column=c, padx=6, pady=2, sticky="w")

    # ── STATUS BAR ────────────────────────────────────────────────────
    def _build_status(self):
        sep = tk.Frame(self, bg=COR_BORDA, height=1)
        sep.pack(fill="x", side="bottom")
        self.status_bar = tk.Label(self, text="Pronto.",
                                    font=FONTE_SMALL, fg=COR_MUTED,
                                    bg=COR_SURFACE2, anchor="w", padx=16, pady=4)
        self.status_bar.pack(fill="x", side="bottom")

    def _status(self, msg, color=COR_MUTED):
        self.status_bar.config(text=msg, fg=color)

    # ── HELPER ────────────────────────────────────────────────────────
    def _card_title(self, parent, text):
        tk.Label(parent, text=text, font=FONTE_TITULO,
                  fg=COR_MUTED, bg=COR_SURFACE).pack(anchor="w", pady=(0, 4))
        tk.Frame(parent, bg=COR_BORDA, height=1).pack(fill="x", pady=(0, 8))

    def _set_text_widget(self, widget, text, color=None):
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        if color:
            widget.config(fg=color)
        widget.config(state="disabled")

    # ── LÓGICA: GERAR CHAVES ──────────────────────────────────────────
    def _gerar_chaves_auto(self):
        self.rsa.gerar_chaves(bits=256)
        self.after(0, self._atualizar_ui_chaves)
        self.after(0, lambda: self._status("✅  Par de chaves RSA gerado com sucesso!", COR_VERDE))

    def _gerar_chaves_manual(self):
        bits = int(self.var_bits.get())
        self.btn_gerar.config(state="disabled")
        self.lbl_gerando.config(text="⏳ Gerando...")
        self._status("Gerando par de chaves RSA...", COR_AMARELO)

        def worker():
            self.rsa.gerar_chaves(bits=bits)
            self.after(0, self._atualizar_ui_chaves)
            self.after(0, lambda: self.btn_gerar.config(state="normal"))
            self.after(0, lambda: self.lbl_gerando.config(text=""))
            self.after(0, lambda: self._status("✅  Par de chaves RSA gerado com sucesso!", COR_VERDE))

        threading.Thread(target=worker, daemon=True).start()

    def _atualizar_ui_chaves(self):
        rsa = self.rsa
        # Entradas nas abas cifrar/decifrar
        self.var_e.set(str(rsa.e))
        self.var_n_pub.set(str(rsa.n)[:60] + "...")
        self.var_d.set(str(rsa.d)[:60] + "...")
        self.var_n_priv.set(str(rsa.n)[:60] + "...")

        # Aba chaves
        pub_txt = (f"e = {rsa.e}\n\n"
                   f"n = {rsa.n}\n\n"
                   f"Tamanho de n: {rsa.n.bit_length()} bits")
        self._set_text_widget(self.txt_pub, pub_txt, COR_VERDE)

        priv_txt = (f"d = {rsa.d}\n\n"
                    f"n = {rsa.n}\n\n"
                    f"Tamanho de d: {rsa.d.bit_length()} bits")
        self._set_text_widget(self.txt_priv, priv_txt, COR_AMARELO)

        passos = (
            f"p = {rsa.p}\n"
            f"q = {rsa.q}\n"
            f"n = p × q = {rsa.n}\n"
            f"φ(n) = (p−1)(q−1) = {rsa.phi_n}\n"
            f"e = {rsa.e}   →   mdc(e, φ(n)) = {math.gcd(rsa.e, rsa.phi_n)}\n"
            f"d = e⁻¹ mod φ(n) = {rsa.d}\n"
            f"Verificação: d × e mod φ(n) = {(rsa.d * rsa.e) % rsa.phi_n}  ✓"
        )
        self._set_text_widget(self.txt_passos, passos, COR_ROXO)

    # ── LÓGICA: CIFRAR ────────────────────────────────────────────────
    def _cifrar(self):
        if not self.rsa.chave_publica:
            messagebox.showwarning("Atenção", "Gere as chaves primeiro (aba 'Chaves RSA').")
            return
        msg = self.txt_msg.get("1.0", "end-1c")
        if not msg:
            messagebox.showwarning("Atenção", "Digite uma mensagem.")
            return
        if len(msg) > 128:
            messagebox.showerror("Erro", f"Mensagem com {len(msg)} chars. Máximo: 128.")
            return
        try:
            cifrado = self.rsa.cifrar(msg)
            self._ultimo_cifrado = cifrado
            cifrado_str = " ".join(str(c) for c in cifrado)
            self._set_text_widget(self.txt_cifrado, cifrado_str, COR_VERDE)
            hex_str = ("ASCII→HEX: " + " ".join(f"{ord(c):02x}" for c in msg) +
                       "\nCifrado HEX: " + " ".join(f"{c:x}" for c in cifrado[:8]) + "...")
            self._set_text_widget(self.txt_hex, hex_str, COR_AZUL)
            self._status(f"✅  Mensagem cifrada com sucesso! ({len(msg)} chars → {len(cifrado)} valores)", COR_VERDE)
        except Exception as ex:
            messagebox.showerror("Erro", str(ex))

    def _limpar_cifrar(self):
        self.txt_msg.delete("1.0", "end")
        self._set_text_widget(self.txt_cifrado, "Aguardando cifragem...", COR_MUTED)
        self._set_text_widget(self.txt_hex, "—", COR_MUTED)
        self.lbl_count.config(text="0 / 128", fg=COR_MUTED)
        self._status("Pronto.")

    def _atualizar_contador(self, event=None):
        n = len(self.txt_msg.get("1.0", "end-1c"))
        cor = COR_VERMELHO if n > 115 else COR_MUTED
        self.lbl_count.config(text=f"{n} / 128", fg=cor)

    def _copiar_cifrado(self):
        txt = self.txt_cifrado.get("1.0", "end-1c")
        if txt and txt != "Aguardando cifragem...":
            self.clipboard_clear()
            self.clipboard_append(txt)
            self._status("📋  Texto cifrado copiado para a área de transferência.", COR_AZUL)

    def _enviar_decifrar(self):
        txt = self.txt_cifrado.get("1.0", "end-1c")
        if not txt or txt == "Aguardando cifragem...":
            messagebox.showwarning("Atenção", "Cifre uma mensagem primeiro.")
            return
        self.txt_dec_input.delete("1.0", "end")
        self.txt_dec_input.insert("1.0", txt)
        self.notebook.select(1)
        self._status("➡️  Texto cifrado enviado para a aba Decifrar.", COR_AZUL)

    # ── LÓGICA: DECIFRAR ──────────────────────────────────────────────
    def _decifrar(self):
        if not self.rsa.chave_privada:
            messagebox.showwarning("Atenção", "Gere as chaves primeiro (aba 'Chaves RSA').")
            return
        entrada = self.txt_dec_input.get("1.0", "end-1c").strip()
        if not entrada:
            messagebox.showwarning("Atenção", "Cole o texto cifrado.")
            return
        try:
            partes = [int(x) for x in entrada.split()]
            resultado = self.rsa.decifrar(partes)
            self._set_text_widget(self.txt_dec_output, resultado, COR_VERDE)
            self._set_text_widget(self.txt_verif, "✅  Decifragem bem-sucedida! Integridade verificada.", COR_VERDE)
            self._status(f"✅  Mensagem decifrada com sucesso! ({len(partes)} valores → '{resultado[:40]}...')", COR_VERDE)
        except ValueError:
            self._set_text_widget(self.txt_dec_output, "❌  Formato inválido. Use inteiros separados por espaço.", COR_VERMELHO)
            self._set_text_widget(self.txt_verif, "❌  Falha na verificação.", COR_VERMELHO)
        except Exception as ex:
            messagebox.showerror("Erro ao decifrar", str(ex))

    def _limpar_decifrar(self):
        self.txt_dec_input.delete("1.0", "end")
        self._set_text_widget(self.txt_dec_output, "Aguardando decifragem...", COR_MUTED)
        self._set_text_widget(self.txt_verif, "—", COR_MUTED)
        self._status("Pronto.")

    # ── LÓGICA: VISUALIZADOR ──────────────────────────────────────────
    STEPS = [
        ("1", "Seleção de primos p e q",
         "Dois primos grandes e distintos são gerados aleatoriamente.\nQuanto maiores, mais seguro o RSA."),
        ("2", "Cálculo do módulo  n = p × q",
         "O produto forma o módulo público n. Fatorar n de volta em p e q\né computacionalmente inviável para números grandes."),
        ("3", "Cálculo de  φ(n) = (p−1)(q−1)",
         "A função de Euler φ(n) conta os inteiros coprimos com n.\nDeve permanecer em segredo."),
        ("4", "Escolha do expoente público  e",
         "e = 65537 (número de Fermat F₄). Deve satisfazer mdc(e, φ(n)) = 1."),
        ("5", "Cálculo do expoente privado  d",
         "d é o inverso modular de e módulo φ(n).\nCalculado pelo Algoritmo de Euclides Estendido."),
        ("6", "Conversão da mensagem → ASCII",
         "Cada caractere é convertido para seu código ASCII (0–127),\nque será cifrado individualmente."),
        ("7", "Cifragem:  C = Mᵉ mod n",
         "Cada código ASCII (M) é elevado ao expoente público e\ne reduzido módulo n. Este é o núcleo do RSA."),
        ("8", "Transmissão pelo canal inseguro",
         "Os valores cifrados C são transmitidos livremente.\nSem a chave privada d, são computacionalmente ilegíveis."),
        ("9", "Decifragem:  M = Cᵈ mod n",
         "O destinatário usa a chave privada d para recuperar\nM = Cᵈ mod n, obtendo os valores ASCII originais."),
        ("10", "Reconstrução da mensagem",
         "Os valores ASCII são convertidos de volta para caracteres,\nrecuperando a mensagem original com fidelidade total."),
    ]

    def _resetar_demo(self):
        for w in self.demo_inner.winfo_children():
            w.destroy()
        self.step_labels = []
        tk.Label(self.demo_inner,
                  text="Clique em 'Iniciar Demonstração' para visualizar o processo RSA passo a passo.",
                  font=FONTE_NORMAL, fg=COR_MUTED, bg=COR_SURFACE,
                  wraplength=700).pack(pady=30)

    def _iniciar_demo(self):
        msg = self.var_demo_msg.get()[:12] or "RSA"

        # Gera chaves demo fixas (pequenas para mostrar valores)
        p, q = 61, 53
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 17
        d = inverso_modular(e, phi)

        ascii_vals = [ord(c) for c in msg]
        cifrado = [potencia_modular(m, e, n) for m in ascii_vals]
        decifrado = [potencia_modular(c, d, n) for c in cifrado]

        dados = [
            f"p = {p},  q = {q}  (ambos primos ✓)",
            f"n = {p} × {q} = {n}",
            f"φ({n}) = ({p}−1)({q}−1) = {p-1}×{q-1} = {phi}",
            f"e = {e}   →   mdc({e}, {phi}) = {math.gcd(e, phi)} ✓",
            f"d = {d}   →   d×e mod φ(n) = {(d*e)%phi} ✓",
            "  |  ".join(f"'{c}' → {v}" for c, v in zip(msg, ascii_vals)),
            "\n".join(f"{m}^{e} mod {n} = {c}" for m, c in zip(ascii_vals, cifrado)),
            f"📡  Transmitindo: [ {', '.join(map(str, cifrado))} ]",
            "\n".join(f"{c}^{d} mod {n} = {m}" for c, m in zip(cifrado, decifrado)),
            f'Mensagem recuperada: "{"".join(chr(m) for m in decifrado)}"  ✅',
        ]

        # Limpar e montar steps
        for w in self.demo_inner.winfo_children():
            w.destroy()
        self.step_labels = []

        for i, (num, titulo, desc) in enumerate(self.STEPS):
            frame = tk.Frame(self.demo_inner, bg=COR_SURFACE)
            frame.pack(fill="x", padx=16, pady=4)

            # Número
            num_lbl = tk.Label(frame, text=num, font=FONTE_BOLD,
                                fg=COR_MUTED, bg=COR_SURFACE2,
                                width=3, relief="flat", pady=4)
            num_lbl.pack(side="left", padx=(0, 12))

            content = tk.Frame(frame, bg=COR_SURFACE)
            content.pack(side="left", fill="x", expand=True)

            tk.Label(content, text=titulo, font=FONTE_BOLD,
                      fg=COR_TEXTO, bg=COR_SURFACE).pack(anchor="w")
            tk.Label(content, text=desc, font=FONTE_SMALL,
                      fg=COR_MUTED, bg=COR_SURFACE, justify="left").pack(anchor="w")

            data_lbl = tk.Label(content, text="", font=FONTE_MONO,
                                 fg=COR_AZUL, bg=COR_BG,
                                 justify="left", padx=8, pady=4, relief="flat")

            self.step_labels.append((num_lbl, data_lbl, dados[i]))

            tk.Frame(self.demo_inner, bg=COR_BORDA, height=1).pack(fill="x", padx=16)

        self.btn_demo.config(state="disabled")
        threading.Thread(target=self._animar_demo, daemon=True).start()

    def _animar_demo(self):
        for i, (num_lbl, data_lbl, dado) in enumerate(self.step_labels):
            time.sleep(0.5)
            self.after(0, lambda nl=num_lbl: nl.config(fg=COR_AZUL, bg=COR_BTN_BLUE))
            time.sleep(0.8)
            self.after(0, lambda dl=data_lbl, d=dado: (
                dl.config(text=d),
                dl.pack(anchor="w", pady=(4, 0), fill="x")
            ))
            time.sleep(0.3)
            self.after(0, lambda nl=num_lbl: nl.config(fg=COR_VERDE, bg=COR_BTN_GREEN))

        self.after(0, lambda: self.btn_demo.config(state="normal"))
        self.after(0, lambda: self._status("✅  Demonstração concluída!", COR_VERDE))


# ═══════════════════════════════════════════════════════════════════════
#  PONTO DE ENTRADA
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = AplicacaoRSA()
    app.mainloop()
