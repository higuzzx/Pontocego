"""Ponto Cego: descubra vulnerabilidades em seus ativos.

Sistema de gestão de vulnerabilidades de ativos de TI.
Interface em Streamlit integrada ao PostgreSQL.
Para rodar (a partir da pasta do projeto):  streamlit run app/app.py
"""
import base64
import time
from datetime import date, datetime
from functools import lru_cache
from html import escape
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

import auth
import db
from db import ErroBanco

ASSETS = Path(__file__).parent / "assets"

st.set_page_config(page_title="Ponto Cego · Gestão de Vulnerabilidades",
                   page_icon=str(ASSETS / "icone_ponto_cego.png"),
                   layout="wide", initial_sidebar_state="expanded")

# ---------------------------------------------------------------------
# Identidade visual: Ponto Cego
#   Vermelho Alerta #E50914 · Cinza Escuro #1A1A1A · Cinza #6B7280 · Cinza Claro #E5E7EB
#   Orbitron (títulos e números) · Inter (textos) · JetBrains Mono (rótulos HUD e SQL)
# ---------------------------------------------------------------------
VERMELHO = "#E50914"
SEVERIDADES = ["Crítica", "Alta", "Média", "Baixa"]
COR_SEV = {"Crítica": "#E50914", "Alta": "#F97316", "Média": "#FBBF24", "Baixa": "#22C55E"}
COR_STATUS = {"Aberta": "#F97316", "Em correção": "#60A5FA", "Corrigida": "#22C55E", "Risco aceito": "#9CA3AF"}
COR_PRAZO = {"Vencida": "#E50914", "Vence em até 7 dias": "#FBBF24", "No prazo": "#22C55E"}
COR_OPERACAO = {"INSERT": "#22C55E", "UPDATE": "#60A5FA", "DELETE": "#E50914"}
COR_SITUACAO = {"Ativo": "#22C55E", "Inativo": "#9CA3AF"}
TIPOS = ["Servidor", "Estação", "Switch", "Roteador", "Firewall", "Impressora", "Access Point"]
FERRAMENTAS = ["OpenVAS", "Nessus Essentials", "Nmap", "Nmap (scripts NSE vulners)", "Qualys", "Outra"]

# Fundo HUD: mira (+) a cada 96px sobre uma grade quase invisível
_MIRA = ("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='96' height='96'%3E"
         "%3Cpath d='M48 42v12M42 48h12' stroke='%23E50914' stroke-opacity='.16' stroke-width='1'/%3E%3C/svg%3E")

CSS = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&family=Orbitron:wght@500;600;700;800&display=swap');

:root {
  --bg: #0A0A0C; --panel: #111114; --panel-2: #17171B; --border: #26262C; --border-2: #33333A;
  --text: #E5E7EB; --muted: #9CA3AF; --faint: #6B7280; --accent: #E50914; --accent-2: #FF2A36;
  --accent-dim: rgba(229,9,20,.14); --red: #E50914; --orange: #F97316; --yellow: #FBBF24; --green: #22C55E;
  --hud-c: rgba(229,9,20,.55);
  /* cantoneiras HUD nos quatro cantos dos painéis */
  --hud:
    linear-gradient(var(--hud-c), var(--hud-c)) left top / 14px 1px no-repeat,
    linear-gradient(var(--hud-c), var(--hud-c)) left top / 1px 14px no-repeat,
    linear-gradient(var(--hud-c), var(--hud-c)) right top / 14px 1px no-repeat,
    linear-gradient(var(--hud-c), var(--hud-c)) right top / 1px 14px no-repeat,
    linear-gradient(var(--hud-c), var(--hud-c)) left bottom / 14px 1px no-repeat,
    linear-gradient(var(--hud-c), var(--hud-c)) left bottom / 1px 14px no-repeat,
    linear-gradient(var(--hud-c), var(--hud-c)) right bottom / 14px 1px no-repeat,
    linear-gradient(var(--hud-c), var(--hud-c)) right bottom / 1px 14px no-repeat;
  --panel-bg: linear-gradient(180deg, rgba(23,23,27,.92) 0%, rgba(14,14,17,.92) 100%);
}
html, body, .stApp, .stMarkdown, .stText, input, textarea, button, select, label, p {
  font-family: 'Inter', system-ui, -apple-system, 'Segoe UI', sans-serif; }
span[data-testid="stIconMaterial"], .msi { font-family: 'Material Symbols Rounded' !important; }
.msi { font-weight: normal; font-style: normal; line-height: 1; letter-spacing: normal; text-transform: none;
  display: inline-block; white-space: nowrap; direction: ltr; -webkit-font-smoothing: antialiased;
  font-feature-settings: 'liga'; font-variation-settings: 'FILL' 0, 'wght' 400; }
code, pre, .stCode * { font-family: 'JetBrains Mono', ui-monospace, Consolas, monospace !important; }
::selection { background: rgba(229,9,20,.35); color: #fff; }

/* Estrutura e fundo HUD */
.stApp {
  background:
    radial-gradient(1100px 560px at 88% -8%, rgba(229,9,20,.13), transparent 62%),
    radial-gradient(800px 480px at -8% 108%, rgba(229,9,20,.07), transparent 60%),
    url("__MIRA__") 0 0 / 96px 96px,
    linear-gradient(rgba(255,255,255,.014) 1px, transparent 1px) 0 0 / 96px 96px,
    linear-gradient(90deg, rgba(255,255,255,.014) 1px, transparent 1px) 0 0 / 96px 96px,
    var(--bg);
  background-attachment: fixed; }
header[data-testid="stHeader"] { background: transparent; height: 0; }
[data-testid="stToolbar"], [data-testid="stDecoration"], footer { display: none !important; }
.block-container { padding: 2.2rem 2.6rem 3rem; max-width: 1440px; }

/* Barra lateral */
section[data-testid="stSidebar"] {
  background: linear-gradient(180deg, #0D0D10 0%, #08080A 100%);
  border-right: 1px solid rgba(229,9,20,.18);
  box-shadow: 1px 0 0 rgba(0,0,0,.6), 12px 0 40px -20px rgba(229,9,20,.25); }
section[data-testid="stSidebar"] .block-container, section[data-testid="stSidebar"] > div { padding-top: .4rem; }
.brand { padding: 6px 2px 4px; }
.brand img { width: 100%; max-width: 230px; display: block; filter: drop-shadow(0 0 18px rgba(229,9,20,.18)); }
.brand-tag { display: flex; align-items: center; gap: 8px; margin: 10px 2px 22px; font-size: 12px;
  color: var(--muted); line-height: 1.35; }
.brand-tag::before { content: ""; width: 2px; align-self: stretch; background: var(--accent); border-radius: 2px; }
.nav-label { font-family: 'JetBrains Mono', monospace; font-size: 10.5px; font-weight: 500; letter-spacing: .14em;
  text-transform: uppercase; color: var(--faint); padding: 0 6px 10px; display: flex; align-items: center; gap: 8px; }
.nav-label::after { content: ""; flex: 1; height: 1px; background: linear-gradient(90deg, var(--border-2), transparent); }
section[data-testid="stSidebar"] .stElementContainer:has(div[role="radiogroup"]),
section[data-testid="stSidebar"] div[data-testid="stRadio"],
section[data-testid="stSidebar"] div[data-testid="stRadio"] > div { width: 100% !important; }
section[data-testid="stSidebar"] div[role="radiogroup"] { gap: 3px !important; width: 100%; }
section[data-testid="stSidebar"] div[role="radiogroup"] > div { width: 100%; }
section[data-testid="stSidebar"] div[role="radiogroup"] label {
  width: 100%; margin: 0 !important; padding: 9px 12px; border-radius: 8px; cursor: pointer; min-height: 0;
  border: 1px solid transparent; transition: background .15s ease, border-color .15s ease, box-shadow .15s ease; }
/* esconde a bolinha do radio (cobre versões antigas e novas do Streamlit) */
section[data-testid="stSidebar"] label[data-testid="stRadioOption"] > div > div:first-child,
section[data-testid="stSidebar"] label[data-baseweb="radio"] > div:first-child { display: none; }
section[data-testid="stSidebar"] div[role="radiogroup"] label p {
  font-size: 14px; font-weight: 500; color: var(--muted); }
section[data-testid="stSidebar"] div[role="radiogroup"] label p span[role="img"] {
  font-size: 19px !important; margin-right: 4px; color: var(--faint); vertical-align: -4px !important; }
section[data-testid="stSidebar"] div[role="radiogroup"] label:hover { background: rgba(255,255,255,.035);
  border-color: rgba(255,255,255,.04); }
section[data-testid="stSidebar"] div[role="radiogroup"] label:hover p span[role="img"] { color: var(--accent-2); }
section[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked) {
  background: linear-gradient(90deg, #E50914 0%, #B5060F 100%); border-color: rgba(255,80,90,.35);
  box-shadow: 0 8px 24px -8px rgba(229,9,20,.6), inset 0 1px 0 rgba(255,255,255,.12); }
section[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked) p { color: #fff; font-weight: 600; }
section[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked) p span[role="img"] { color: #fff; }
.side-user { display: flex; align-items: center; gap: 10px; margin: 26px 2px 10px; }
.avatar { width: 36px; height: 36px; border-radius: 50%; display: grid; place-items: center; flex: none;
  font-family: 'Orbitron', sans-serif; font-size: 12.5px; font-weight: 700; color: #fff;
  background: linear-gradient(135deg, #E50914, #7A050B); box-shadow: 0 0 0 2px rgba(229,9,20,.25); }
.side-user-nome { font-size: 13.5px; font-weight: 600; color: var(--text); line-height: 1.2; }
.side-user-perfil { font-size: 11.5px; color: var(--muted); margin-top: 2px; }
.side-foot { margin-top: 16px; padding: 14px; border: 1px solid var(--border); border-radius: 10px;
  background: var(--hud), var(--panel-bg); --hud-c: rgba(229,9,20,.4); }
.conn { display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--text); font-weight: 500; }
.dot { width: 8px; height: 8px; border-radius: 50%; background: var(--green); box-shadow: 0 0 0 3px rgba(34,197,94,.18);
  animation: pulso-verde 2.4s ease-in-out infinite; }
@keyframes pulso-verde { 50% { box-shadow: 0 0 0 5px rgba(34,197,94,.06); } }
.side-meta { font-size: 12px; color: var(--muted); margin-top: 6px; line-height: 1.5; }
.side-meta code { font-size: 11px; background: transparent; color: var(--muted); padding: 0; }
.side-sys { font-family: 'JetBrains Mono', monospace; font-size: 10px; letter-spacing: .1em; color: #4B4B55;
  margin-top: 14px; text-transform: uppercase; }
.side-sys b { color: rgba(229,9,20,.7); font-weight: 500; }

/* Cabeçalho de página */
.pg-head { position: relative; margin-bottom: 24px; padding-bottom: 16px; }
.pg-head::after { content: ""; position: absolute; left: 0; right: 0; bottom: 0; height: 1px;
  background: linear-gradient(90deg, var(--accent) 0, rgba(229,9,20,.35) 80px, var(--border) 81px, transparent 100%); }
.pg-eyebrow { font-family: 'JetBrains Mono', monospace; font-size: 11.5px; font-weight: 500; letter-spacing: .14em;
  text-transform: uppercase; color: var(--accent-2); }
.pg-eyebrow span { color: var(--faint); margin: 0 8px; }
.pg-title { font-family: 'Orbitron', 'Inter', sans-serif; font-size: 28px; font-weight: 700; color: #F3F4F6;
  letter-spacing: .02em; margin: 8px 0 6px; line-height: 1.15; }
.pg-sub { font-size: 15px; color: var(--muted); margin: 0; }

/* Indicadores */
.kpi-grid { display: grid; grid-template-columns: repeat(var(--cols, 6), minmax(0, 1fr)); gap: 14px; margin: 4px 0 22px; }
.kpi { position: relative; background: var(--hud), var(--panel-bg); border: 1px solid var(--border); border-radius: 10px;
  padding: 16px 18px 16px; overflow: hidden; --hud-c: color-mix(in srgb, var(--tone, #E50914) 60%, transparent);
  transition: border-color .2s ease, transform .2s ease; }
.kpi:hover { border-color: color-mix(in srgb, var(--tone, #E50914) 45%, var(--border)); transform: translateY(-1px); }
.kpi::after { content: ""; position: absolute; left: 0; right: 0; bottom: 0; height: 2px;
  background: linear-gradient(90deg, var(--tone, var(--faint)), transparent 85%); opacity: .85; }
.kpi::before { content: ""; position: absolute; right: -40px; top: -40px; width: 120px; height: 120px; border-radius: 50%;
  background: radial-gradient(circle, color-mix(in srgb, var(--tone, #E50914) 18%, transparent), transparent 70%); }
.kpi-ic { font-size: 24px; color: var(--tone, var(--muted)); margin-bottom: 10px;
  filter: drop-shadow(0 0 8px color-mix(in srgb, var(--tone, #E50914) 45%, transparent)); }
.kpi-label { font-size: 12.5px; color: var(--muted); font-weight: 500; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.kpi-value { font-family: 'Orbitron', 'Inter', sans-serif; font-size: 27px; font-weight: 700; color: #F9FAFB;
  letter-spacing: .01em; margin: 2px 0 2px; line-height: 1.15; }
.kpi-value small { font-family: 'Inter', sans-serif; font-size: 13px; font-weight: 500; color: var(--muted); margin-left: 4px; letter-spacing: 0; }
.kpi-foot { font-size: 12px; color: var(--faint); margin-top: 6px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

/* Títulos de seção */
.sec { margin: 2px 0 12px; }
.sec-title { font-size: 15px; font-weight: 600; color: var(--text); display: flex; align-items: center; gap: 10px; }
.sec-title::before { content: ""; width: 7px; height: 7px; transform: rotate(45deg); border: 1.5px solid var(--accent);
  box-shadow: 0 0 8px rgba(229,9,20,.6); flex: none; }
.sec-desc { font-size: 13px; color: var(--muted); margin-top: 3px; padding-left: 17px; }

/* Painéis com borda (painel()) */
[class*="st-key-painel_"], div[data-testid="stVerticalBlockBorderWrapper"] {
  background: var(--hud), var(--panel-bg); border-color: var(--border) !important; border-radius: 10px; }

/* Alerta de vulnerabilidade crítica */
.alerta { position: relative; display: flex; align-items: center; gap: 18px; padding: 16px 20px; margin: 0 0 22px;
  border: 1px solid rgba(229,9,20,.45); border-radius: 10px; overflow: hidden;
  background: linear-gradient(90deg, rgba(229,9,20,.16) 0%, rgba(229,9,20,.04) 45%, rgba(17,17,20,.9) 100%);
  box-shadow: 0 0 0 1px rgba(229,9,20,.08), 0 14px 40px -18px rgba(229,9,20,.55); }
.alerta::before { content: ""; position: absolute; inset: 0 auto 0 0; width: 3px; background: var(--accent);
  box-shadow: 0 0 14px var(--accent); }
.alerta-ic { width: 46px; height: 46px; flex: none; display: grid; place-items: center; border-radius: 10px;
  background: rgba(229,9,20,.14); border: 1px solid rgba(229,9,20,.45); color: var(--accent-2);
  animation: pulso 1.8s ease-in-out infinite; }
.alerta-ic .msi { font-size: 26px; font-variation-settings: 'FILL' 1, 'wght' 500; }
@keyframes pulso { 0%,100% { box-shadow: 0 0 0 0 rgba(229,9,20,.45); } 50% { box-shadow: 0 0 0 8px rgba(229,9,20,0); } }
.alerta-tag { font-family: 'JetBrains Mono', monospace; font-size: 10.5px; letter-spacing: .14em; text-transform: uppercase;
  color: var(--accent-2); }
.alerta-tit { font-size: 15.5px; font-weight: 700; color: #fff; margin: 2px 0 3px; }
.alerta-txt { font-size: 13.5px; color: #C9CDD4; }
.alerta-txt b { color: #fff; font-weight: 600; }
.alerta-txt code { background: rgba(255,255,255,.06); color: #fff; padding: 1px 6px; border-radius: 4px; font-size: 12.5px; }
.alerta-side { margin-left: auto; text-align: right; flex: none; }
.alerta-num { font-family: 'Orbitron', sans-serif; font-size: 24px; font-weight: 700; color: var(--accent-2); line-height: 1; }
.alerta-num-l { font-size: 11.5px; color: var(--muted); margin-top: 4px; }

/* Legenda do medidor de risco */
.leg { display: flex; flex-direction: column; gap: 12px; padding: 18px 6px 0 0; }
.leg-row { display: flex; align-items: center; gap: 10px; font-size: 13.5px; color: #D1D5DB; }
.leg-row i { width: 9px; height: 9px; border-radius: 50%; flex: none; box-shadow: 0 0 8px currentColor; }
.leg-row span { margin-left: auto; font-family: 'Orbitron', sans-serif; font-weight: 600; font-size: 13.5px; color: #F3F4F6; }
.leg-bar { height: 3px; border-radius: 3px; background: rgba(255,255,255,.05); margin: -6px 0 2px 19px; overflow: hidden; }
.leg-bar div { height: 100%; border-radius: 3px; }

/* Selos */
.badge { display: inline-flex; align-items: center; gap: 6px; padding: 3px 10px; border-radius: 999px;
  font-size: 12px; font-weight: 600; border: 1px solid; white-space: nowrap; }
.badge::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: currentColor; box-shadow: 0 0 6px currentColor; }

/* Ficha de detalhe */
.ficha { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 18px; background: var(--hud), var(--panel-bg);
  border: 1px solid var(--border); border-radius: 10px; padding: 18px 20px; margin: 6px 0 14px; }
.ficha .k { font-family: 'JetBrains Mono', monospace; font-size: 10.5px; letter-spacing: .1em; text-transform: uppercase;
  color: var(--faint); margin-bottom: 7px; }
.ficha .v { font-size: 15px; color: var(--text); font-weight: 600; }
.ficha .v.mono { font-family: 'Orbitron', sans-serif; font-weight: 600; font-size: 16px; }
.ficha-desc { grid-column: 1 / -1; border-top: 1px solid var(--border); padding-top: 14px; font-size: 13.5px; color: var(--muted); }
.ficha-desc b { color: var(--accent-2); font-weight: 600; font-family: 'JetBrains Mono', monospace; }

/* Abas */
.stTabs [data-baseweb="tab-list"] { gap: 6px; border-bottom: 1px solid var(--border); }
.stTabs [data-baseweb="tab"] { padding: 10px 4px; margin-right: 16px; font-weight: 500; }
.stTabs [data-baseweb="tab"] p { font-size: 14px; color: var(--muted); }
.stTabs [data-baseweb="tab"][aria-selected="true"] p { color: #fff; font-weight: 600; }
.stTabs [data-baseweb="tab"]:hover p { color: var(--text); }
.stTabs [data-baseweb="tab-highlight"] { background: var(--accent); height: 2px; box-shadow: 0 0 10px var(--accent); }
.stTabs [data-baseweb="tab-border"] { display: none; }

/* Botões e formulários */
.stButton button, .stFormSubmitButton button { border-radius: 8px; font-weight: 600; padding: .5rem 1rem;
  transition: box-shadow .2s ease, transform .1s ease, background .2s ease; }
button[kind="primary"], button[kind="primaryFormSubmit"], button[data-testid="stBaseButton-primary"],
button[data-testid="stBaseButton-primaryFormSubmit"] {
  background: linear-gradient(180deg, #F0141F 0%, #C70711 100%) !important; border: 1px solid rgba(255,90,100,.35) !important;
  color: #fff !important; box-shadow: 0 6px 18px -6px rgba(229,9,20,.65), inset 0 1px 0 rgba(255,255,255,.15); }
button[kind="primary"]:hover, button[kind="primaryFormSubmit"]:hover, button[data-testid="stBaseButton-primary"]:hover,
button[data-testid="stBaseButton-primaryFormSubmit"]:hover {
  box-shadow: 0 8px 26px -6px rgba(229,9,20,.85), inset 0 1px 0 rgba(255,255,255,.2); }
button[kind="primary"]:disabled, button[data-testid="stBaseButton-primary"]:disabled { opacity: .45; box-shadow: none; }
button[kind="secondary"]:hover, button[data-testid="stBaseButton-secondary"]:hover { border-color: var(--accent) !important;
  color: #fff !important; }
div[data-testid="stForm"] { background: var(--hud), var(--panel-bg); border: 1px solid var(--border); border-radius: 10px; padding: 22px; }
div[data-testid="stExpander"] details { border-color: var(--border); border-radius: 8px; background: rgba(10,10,12,.6); }
div[data-testid="stExpander"] summary p { font-family: 'JetBrains Mono', monospace; font-size: 12px; letter-spacing: .04em; color: var(--muted); }
div[data-testid="stExpander"] summary:hover p, div[data-testid="stExpander"] summary:hover span { color: var(--accent-2); }
div[data-testid="stAlert"] { border-radius: 10px; }
[data-testid="stDataFrame"] { border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
.caption-count { font-family: 'JetBrains Mono', monospace; font-size: 11.5px; letter-spacing: .08em; text-transform: uppercase;
  color: var(--faint); margin: 4px 0 8px; }
.caption-count b { color: var(--accent-2); font-weight: 600; }
""".replace("__MIRA__", _MIRA)

st.markdown(f"<style>{CSS}</style>", unsafe_allow_html=True)


@lru_cache(maxsize=None)
def imagem_b64(nome):
    return base64.b64encode((ASSETS / nome).read_bytes()).decode()

# ---------------------------------------------------------------------
# Componentes visuais
# ---------------------------------------------------------------------
def html(conteudo):
    st.markdown(conteudo, unsafe_allow_html=True)


def icone(nome):
    """Ícone do Material Symbols (mesma família usada pelo Streamlit)."""
    return f"<span class='msi'>{escape(nome)}</span>"


def cabecalho(secao, titulo, sub):
    html(f"<div class='pg-head'><div class='pg-eyebrow'>Ponto Cego<span>·</span>{escape(secao)}</div>"
         f"<div class='pg-title'>{escape(titulo)}</div><p class='pg-sub'>{escape(sub)}</p></div>")


def secao(titulo, desc=None):
    html(f"<div class='sec'><div class='sec-title'>{escape(titulo)}</div>"
         + (f"<div class='sec-desc'>{escape(desc)}</div>" if desc else "") + "</div>")


_paineis = iter(range(10_000))


def painel():
    """Container com borda no estilo HUD (cantoneiras vermelhas)."""
    return st.container(border=True, key=f"painel_{next(_paineis)}")


def kpis(itens):
    """itens: lista de (ícone, rótulo, valor, rodapé, cor)."""
    cards = "".join(
        f"<div class='kpi' style='--tone:{cor}'><div class='kpi-ic'>{icone(ic)}</div>"
        f"<div class='kpi-value'>{v}</div><div class='kpi-label'>{escape(r)}</div>"
        f"<div class='kpi-foot'>{escape(rod)}</div></div>"
        for ic, r, v, rod, cor in itens)
    html(f"<div class='kpi-grid' style='--cols:{len(itens)}'>{cards}</div>")


def badge(texto, cor):
    return (f"<span class='badge' style='color:{cor};border-color:{cor}40;background:{cor}14'>"
            f"{escape(str(texto))}</span>")


def contagem(n, palavra="registro"):
    html(f"<div class='caption-count'>&gt; <b>{n}</b> {palavra}{'s' if n != 1 else ''}</div>")


def _cor_texto(mapa):
    def f(v):
        c = mapa.get(v)
        return f"color: {c}; font-weight: 600;" if c else ""
    return f


ESTILO_COLUNAS = {"severidade": COR_SEV, "status": COR_STATUS, "situacao_prazo": COR_PRAZO,
                  "operacao": COR_OPERACAO, "situacao": COR_SITUACAO}

ROTULOS = {
    "id_ocorrencia": "ID", "id": "ID", "hostname": "Hostname", "ip": "IP", "setor": "Setor",
    "responsavel": "Responsável", "cve": "CVE", "titulo": "Título", "cvss": "CVSS",
    "severidade": "Severidade", "status": "Status", "data_deteccao": "Detecção",
    "prazo_correcao": "Prazo", "data_correcao": "Correção", "dias_restantes": "Dias restantes",
    "situacao_prazo": "Situação do prazo", "ferramenta": "Ferramenta", "observacao": "Observação",
    "dias_de_atraso": "Dias de atraso", "tipo": "Tipo", "sistema_operacional": "Sistema operacional",
    "criticidade": "Criticidade", "score_risco": "Score de risco", "situacao": "Situação",
    "pendentes": "Pendentes", "data_publicacao": "Publicação", "solucao": "Solução",
    "ativos_afetados": "Ativos afetados", "data_varredura": "Data", "escopo": "Escopo",
    "executada_por": "Executada por", "ocorrencias_encontradas": "Ocorrências", "nome": "Nome",
    "localizacao": "Localização", "ativos": "Ativos", "email": "E-mail", "cargo": "Cargo",
    "ativos_sob_responsabilidade": "Ativos sob responsabilidade", "data_hora": "Data e hora",
    "usuario_bd": "Usuário do banco", "tabela": "Tabela", "operacao": "Operação",
    "id_registro": "ID do registro", "dias_para_corrigir": "Dias p/ corrigir", "corrigidas": "Corrigidas",
    "media_dias": "Média (dias)", "menor_dias": "Menor", "maior_dias": "Maior", "pct_no_prazo": "% no prazo",
    "ativos_afetados_hoje": "Ativos afetados", "total_deteccoes": "Detecções", "posicao": "Posição",
    "criticas": "Críticas", "altas": "Altas", "medias": "Médias", "baixas": "Baixas",
    "total_pendentes": "Total pendente", "vencidas": "Vencidas", "id_ativo": "ID ativo",
    "usuario_app": "Usuário", "login": "Login", "perfil": "Perfil", "data_cadastro": "Cadastro",
    "ultimo_acesso": "Último acesso",
    "campo": "Campo", "antes": "Antes", "depois": "Depois", "indice": "Índice", "definicao": "Definição",
}


def tabela(df: pd.DataFrame, altura=None, chave=None, ao_selecionar=None):
    """Tabela padronizada: rótulos em português, datas dd/mm/aaaa, status e severidade coloridos.

    Com chave + ao_selecionar, clicar numa linha chama ao_selecionar(linha) uma vez por clique."""
    if df.empty:
        st.info("Nenhum registro encontrado.", icon=":material/inbox:")
        return
    config = {}
    for col in df.columns:
        amostra = df[col].dropna()
        rotulo = ROTULOS.get(col, col.replace("_", " ").capitalize())
        if len(amostra) and isinstance(amostra.iloc[0], datetime):
            config[col] = st.column_config.DatetimeColumn(rotulo, format="DD/MM/YYYY HH:mm:ss")
        elif len(amostra) and isinstance(amostra.iloc[0], date):
            config[col] = st.column_config.DateColumn(rotulo, format="DD/MM/YYYY")
        elif col in ("cvss", "score_risco", "media_dias", "pct_no_prazo"):
            config[col] = st.column_config.NumberColumn(rotulo, format="%.1f")
        else:
            config[col] = st.column_config.Column(rotulo)
    estilo = df.style
    for col, mapa in ESTILO_COLUNAS.items():
        if col in df.columns:
            estilo = estilo.map(_cor_texto(mapa), subset=[col])
    kwargs = {"height": altura} if altura else {}
    if not (chave and ao_selecionar):
        st.dataframe(estilo, hide_index=True, width="stretch", column_config=config, **kwargs)
        return
    # a versão muda depois de cada alteração, o que limpa a seleção antiga
    versao = st.session_state.get("versao_tabelas", 0)
    evento = st.dataframe(estilo, hide_index=True, width="stretch", column_config=config,
                          key=f"tab_{chave}_{versao}", on_select="rerun", selection_mode="single-row", **kwargs)
    linhas = evento.selection.rows
    marca = (versao, tuple(linhas))
    if not linhas:
        st.session_state.pop(f"sel_{chave}", None)
    elif st.session_state.get(f"sel_{chave}") != marca:  # só abre de novo se o clique mudou
        st.session_state[f"sel_{chave}"] = marca
        ao_selecionar(df.iloc[linhas[0]])


def ver_sql(sql, rotulo="Ver SQL executado"):
    with st.expander(rotulo, icon=":material/code:"):
        st.code(sql.strip(), language="sql")


def grafico(fig, altura=340):
    fig.update_layout(
        height=altura, margin=dict(l=0, r=10, t=6, b=0),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, Segoe UI, sans-serif", size=12, color="#9CA3AF"),
        legend=dict(orientation="h", y=-0.16, x=0, title_text="", font=dict(color="#D1D5DB")),
        hoverlabel=dict(bgcolor="#141417", bordercolor=VERMELHO, font=dict(color="#F3F4F6", family="Inter")),
        bargap=0.35)
    fig.update_xaxes(gridcolor="rgba(255,255,255,0.05)", zeroline=False, showline=False, title_font=dict(size=12))
    fig.update_yaxes(gridcolor="rgba(0,0,0,0)", zeroline=False, showline=False, title_text="",
                     tickfont=dict(color="#D1D5DB"))
    st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})


ESCALA_VERMELHA = [[0, "#5A0A0F"], [0.5, "#A3070F"], [1, "#FF1F2D"]]


def avisar(msg, tipo="success"):
    """Guarda uma mensagem para mostrar depois do st.rerun() e limpa as seleções das tabelas."""
    st.session_state.setdefault("avisos", []).append((tipo, msg))
    st.session_state["versao_tabelas"] = st.session_state.get("versao_tabelas", 0) + 1


def mostrar_avisos():
    icones = {"success": ":material/check_circle:", "warning": ":material/warning:", "error": ":material/error:"}
    for tipo, msg in st.session_state.pop("avisos", []):
        getattr(st, tipo)(msg, icon=icones.get(tipo))


def ok(msg):
    st.success(msg, icon=":material/check_circle:")


def erro(msg):
    st.error(msg, icon=":material/error:")


def fmt_data(d):
    return d.strftime("%d/%m/%Y") if d else "-"


def opcoes(sql):
    """Executa um SELECT (id, rótulo) e devolve um dicionário para selectbox."""
    df = db.consultar(sql)
    return dict(zip(df.iloc[:, 0].tolist(), df.iloc[:, 1].tolist())) if not df.empty else {}


def score_ativo(id_ativo):
    v = db.valor("SELECT score_risco FROM ativo WHERE id_ativo = %s", (int(id_ativo),))
    return float(v) if v is not None else 0.0


# ---------------------------------------------------------------------
# PÁGINA: PAINEL
# ---------------------------------------------------------------------
SQL_INDICADORES = """
SELECT (SELECT COUNT(*) FROM ativo WHERE situacao = 'Ativo')                       AS ativos,
       (SELECT COUNT(*) FROM vw_ocorrencias_pendentes)                              AS pendentes,
       (SELECT COUNT(*) FROM vw_ocorrencias_pendentes WHERE severidade = 'Crítica') AS criticas,
       (SELECT COUNT(*) FROM vw_ocorrencias_vencidas)                               AS vencidas,
       (SELECT COUNT(*) FROM ocorrencia WHERE status = 'Corrigida')                 AS corrigidas,
       (SELECT media_dias FROM vw_tempo_medio_correcao WHERE severidade = 'Crítica') AS mttr_critica,
       (SELECT COUNT(*) FROM varredura)                                             AS varreduras
"""


def alerta_critico():
    """Destaque para a ocorrência crítica com mais dias de atraso (se houver)."""
    df = db.consultar("SELECT id_ocorrencia, hostname, cve, cvss, titulo, -dias_restantes AS dias_de_atraso "
                      "FROM vw_ocorrencias_pendentes "
                      "WHERE severidade = 'Crítica' AND prazo_correcao < CURRENT_DATE "
                      "ORDER BY dias_de_atraso DESC, cvss DESC")
    if df.empty:
        return
    o = df.iloc[0]
    html(f"""<div class='alerta'>
      <div class='alerta-ic'>{icone('warning')}</div>
      <div><div class='alerta-tag'>Alerta · prazo vencido</div>
        <div class='alerta-tit'>Vulnerabilidade crítica sem correção</div>
        <div class='alerta-txt'>Ativo <b>{escape(o.hostname)}</b> com <code>{escape(o.cve)}</code>
          (CVSS {float(o.cvss):.1f}) · {escape(o.titulo)}</div></div>
      <div class='alerta-side'><div class='alerta-num'>{int(o.dias_de_atraso)}d</div>
        <div class='alerta-num-l'>de atraso{f" · +{len(df) - 1} crítica(s) vencida(s)" if len(df) > 1 else ""}</div></div>
    </div>""")
    with st.container(key="alerta_acao"):
        if st.button("Ver detalhes e tratar", icon=":material/arrow_forward:", type="primary",
                     key="alerta_detalhes"):
            dialogo_ocorrencia(int(o.id_ocorrencia))


def medidor_risco(pend):
    """Rosca com as ocorrências pendentes por severidade (estilo 'Risco geral')."""
    total = int(pend["qtd"].sum())
    esq, dir_ = st.columns([1.25, 1], gap="small")
    with esq:
        if total == 0:
            st.info("Nenhuma ocorrência pendente.", icon=":material/verified:")
            return
        fig = go.Figure(go.Pie(
            labels=pend["severidade"], values=pend["qtd"], hole=.74, sort=False, direction="clockwise",
            marker=dict(colors=[COR_SEV[s] for s in pend["severidade"]], line=dict(color="#0E0E11", width=3)),
            textinfo="none", hovertemplate="%{label}: %{value} pendente(s)<extra></extra>"))
        fig.add_annotation(text=f"<b>{total}</b>", x=.5, y=.56, showarrow=False,
                           font=dict(family="Orbitron, Inter, sans-serif", size=34, color="#F9FAFB"))
        fig.add_annotation(text="PENDENTES", x=.5, y=.38, showarrow=False,
                           font=dict(family="JetBrains Mono, monospace", size=10, color="#9CA3AF"))
        fig.update_layout(showlegend=False)
        grafico(fig, 250)
    with dir_:
        linhas = ""
        for s, q in zip(pend["severidade"], pend["qtd"]):
            pct = 100 * q / total
            linhas += (f"<div class='leg-row'><i style='background:{COR_SEV[s]};color:{COR_SEV[s]}'></i>{s}"
                       f"<span>{int(q)}</span></div><div class='leg-bar'>"
                       f"<div style='width:{pct:.0f}%;background:{COR_SEV[s]}'></div></div>")
        html(f"<div class='leg'>{linhas}</div>")


def pagina_painel():
    cabecalho("Painel", "Painel de risco", "Visão geral da segurança dos seus ativos")
    mostrar_avisos()
    ind = db.consultar(SQL_INDICADORES).iloc[0]
    mttr = f"{ind.mttr_critica:.1f}<small>dias</small>" if pd.notna(ind.mttr_critica) else "-"
    kpis([
        ("dns", "Ativos monitorados", int(ind.ativos), f"{int(ind.varreduras)} varreduras realizadas", "#60A5FA"),
        ("bug_report", "Ocorrências pendentes", int(ind.pendentes), "abertas ou em correção", "#F97316"),
        ("warning", "Críticas pendentes", int(ind.criticas), "prazo de 7 dias", VERMELHO),
        ("schedule", "Prazo vencido", int(ind.vencidas), "precisam de ação imediata", VERMELHO),
        ("check_circle", "Corrigidas", int(ind.corrigidas), "desde a primeira varredura", "#22C55E"),
        ("timer", "Tempo médio (críticas)", mttr, "da detecção à correção", "#FBBF24"),
    ])
    alerta_critico()

    esq, dir_ = st.columns([1, 1.45], gap="medium")
    with esq, painel():
        secao("Risco geral", "Ocorrências pendentes por severidade")
        pend = db.consultar("SELECT severidade, COUNT(*) AS qtd FROM vw_ocorrencias_pendentes GROUP BY severidade")
        pend = (pd.DataFrame({"severidade": SEVERIDADES})
                .merge(pend, how="left", on="severidade").fillna({"qtd": 0}))
        medidor_risco(pend)

    with dir_, painel():
        secao("Pendências por setor", "Ocorrências abertas ou em correção, por severidade")
        resumo = db.consultar("SELECT * FROM vw_resumo_setor")
        longo = resumo.melt(id_vars="setor", value_vars=["criticas", "altas", "medias", "baixas"],
                            var_name="sev", value_name="qtd")
        longo["Severidade"] = longo["sev"].map(
            {"criticas": "Crítica", "altas": "Alta", "medias": "Média", "baixas": "Baixa"})
        ordem = resumo.sort_values("total_pendentes", ascending=False)["setor"].tolist()
        fig = px.bar(longo, y="setor", x="qtd", color="Severidade", orientation="h",
                     color_discrete_map=COR_SEV,
                     category_orders={"setor": ordem, "Severidade": SEVERIDADES},
                     labels={"setor": "", "qtd": "Ocorrências pendentes"})
        fig.update_traces(marker_line_width=0)
        fig.update_xaxes(title_text="")
        grafico(fig, 290)

    esq, dir_ = st.columns(2, gap="medium")
    with esq, painel():
        secao("Ativos mais expostos", "Score = soma do CVSS pendente × (criticidade ÷ 5)")
        top = db.consultar("SELECT hostname, score_risco, criticas, pendentes "
                           "FROM vw_ranking_ativos WHERE score_risco > 0 ORDER BY posicao LIMIT 10")
        fig = px.bar(top, x="score_risco", y="hostname", orientation="h", text="score_risco",
                     labels={"hostname": "", "score_risco": "Score de risco"},
                     hover_data={"pendentes": True, "criticas": True})
        fig.update_traces(marker=dict(color=top["score_risco"], colorscale=ESCALA_VERMELHA, line_width=0),
                          texttemplate="%{text:.1f}", textposition="outside",
                          textfont=dict(color="#F3F4F6", family="Orbitron, Inter, sans-serif", size=11),
                          cliponaxis=False)
        fig.update_yaxes(categoryorder="total ascending", tickfont=dict(family="JetBrains Mono, monospace"))
        grafico(fig, 360)

    with dir_, painel():
        secao("Vulnerabilidades mais presentes hoje", "CVEs com mais ativos afetados no momento")
        tabela(db.consultar("SELECT cve, severidade, ativos_afetados_hoje, titulo "
                            "FROM vw_vulnerabilidades_frequentes WHERE ativos_afetados_hoje > 0 "
                            "ORDER BY ativos_afetados_hoje DESC, cvss DESC LIMIT 8"))

    with painel():
        secao("Ocorrências com prazo vencido",
              "Ordenadas pelo atraso. Clique em uma linha para atualizar ou fechar a ocorrência")
        tabela(db.consultar("SELECT * FROM vw_ocorrencias_vencidas ORDER BY dias_de_atraso DESC"),
               chave="painel_vencidas", ao_selecionar=lambda r: dialogo_ocorrencia(int(r.id_ocorrencia)))

    with painel():
        secao("Tempo médio de correção", "Prazo esperado: Crítica 7 dias, Alta 30, Média 90, Baixa 180")
        mttr_df = db.consultar("SELECT * FROM vw_tempo_medio_correcao")
        mttr_df["ordem"] = mttr_df["severidade"].map({s: i for i, s in enumerate(SEVERIDADES)})
        tabela(mttr_df.sort_values("ordem").drop(columns="ordem"))

    ver_sql(SQL_INDICADORES, "Ver SQL dos indicadores")


def editor_ocorrencia(id_oc, prefixo):
    """Ficha da ocorrência pendente com as ações: em correção, fechar, aceitar risco, excluir."""
    df = db.consultar("SELECT * FROM vw_ocorrencias_pendentes WHERE id_ocorrencia = %s", (id_oc,))
    if df.empty:
        st.info(f"A ocorrência #{id_oc} não está mais pendente (já foi fechada, aceita ou excluída).",
                icon=":material/info:")
        return
    det = df.iloc[0]
    dias = int(det.dias_restantes)
    prazo_txt = f"{abs(dias)} dia(s) de atraso" if dias < 0 else f"faltam {dias} dia(s)"
    html(f"""
    <div class='ficha'>
      <div><div class='k'>Ativo</div><div class='v'>{escape(det.hostname)}</div></div>
      <div><div class='k'>Severidade</div><div class='v'>{badge(det.severidade, COR_SEV[det.severidade])}</div></div>
      <div><div class='k'>Prazo</div><div class='v'>{fmt_data(det.prazo_correcao)}
           <span style='font-weight:500;font-size:13px;color:{COR_PRAZO[det.situacao_prazo]}'>&nbsp;{prazo_txt}</span></div></div>
      <div><div class='k'>Score atual do ativo</div><div class='v mono'>{score_ativo(int(det.id_ativo)):.1f}</div></div>
      <div class='ficha-desc'><b>{escape(det.cve)}</b> &nbsp; {escape(det.titulo)}
        {('<br>Observação: ' + escape(det.observacao)) if det.observacao else ''}</div>
    </div>""")

    obs = st.text_input("Observação (opcional; obrigatória para aceitar o risco)", key=f"{prefixo}_obs_{id_oc}")
    b = st.columns(4)
    acao = None
    if b[0].button("Marcar em correção", icon=":material/build:", width="stretch",
                   disabled=det.status == "Em correção", key=f"{prefixo}_corr_{id_oc}"):
        acao = ("UPDATE ocorrencia SET status = 'Em correção', "
                "observacao = COALESCE(NULLIF(%s, ''), observacao) WHERE id_ocorrencia = %s", (obs, id_oc))
    if b[1].button("Fechar como corrigida", icon=":material/check_circle:", type="primary", width="stretch",
        key=f"{prefixo}_fechar_{id_oc}"):
        acao = ("CALL sp_fechar_ocorrencia(%s, %s, NULL, NULL)", (id_oc, obs))
    if b[2].button("Aceitar o risco", icon=":material/gavel:", width="stretch", key=f"{prefixo}_aceitar_{id_oc}"):
        if not obs.strip():
            erro("Para aceitar o risco, escreva a justificativa no campo de observação.")
        else:
            acao = ("UPDATE ocorrencia SET status = 'Risco aceito', observacao = %s "
                    "WHERE id_ocorrencia = %s", (obs, id_oc))
    confirmar = b[3].checkbox("Confirmo a exclusão", key=f"{prefixo}_conf_{id_oc}")
    if b[3].button("Excluir ocorrência", icon=":material/delete:", disabled=not confirmar, width="stretch",
        key=f"{prefixo}_excluir_{id_oc}"):
        acao = ("DELETE FROM ocorrencia WHERE id_ocorrencia = %s", (id_oc,))

    if acao:
        try:
            antes = score_ativo(int(det.id_ativo))
            ret = db.executar(*acao)
            depois = score_ativo(int(det.id_ativo))
            msg = f"Ocorrência #{id_oc} atualizada."
            if acao[0].startswith("CALL"):
                msg = f"Ocorrência #{id_oc}: {ret[1]}"
            elif acao[0].startswith("DELETE"):
                msg = f"Ocorrência #{id_oc} excluída."
            avisar(f"{msg}  \nScore do ativo **{det.hostname}** recalculado pela trigger: **{antes} → {depois}**")
            st.rerun()
        except ErroBanco as e:
            erro(str(e))
    ver_sql("""
-- Marcar em correção
UPDATE ocorrencia SET status = 'Em correção' WHERE id_ocorrencia = {id};

-- Fechar (stored procedure; a trigger preenche data_correcao e recalcula o score)
CALL sp_fechar_ocorrencia({id}, '{observação}', NULL, NULL);

-- Aceitar risco
UPDATE ocorrencia SET status = 'Risco aceito', observacao = '{justificativa}' WHERE id_ocorrencia = {id};

-- Excluir
DELETE FROM ocorrencia WHERE id_ocorrencia = {id};""", "Ver SQL das ações")


@st.dialog("Tratar ocorrência", width="large")
def dialogo_ocorrencia(id_oc):
    editor_ocorrencia(int(id_oc), "dlg")


# ---------------------------------------------------------------------
# PÁGINA: OCORRÊNCIAS
# ---------------------------------------------------------------------
def pagina_ocorrencias():
    cabecalho("Ocorrências", "Ocorrências", "Vulnerabilidades encontradas nos ativos e o andamento da correção")
    mostrar_avisos()
    aba1, aba2, aba3, aba4 = st.tabs(["Pendentes", "Registrar nova", "Atualizar ou fechar", "Histórico completo"])

    with aba1:
        f = st.columns(4)
        setores = db.consultar("SELECT nome FROM setor ORDER BY nome")["nome"].tolist()
        f_setor = f[0].multiselect("Setor", setores, placeholder="Todos")
        f_sev = f[1].multiselect("Severidade", SEVERIDADES, placeholder="Todas")
        f_prazo = f[2].multiselect("Situação do prazo", ["Vencida", "Vence em até 7 dias", "No prazo"],
                                   placeholder="Todas")
        f_status = f[3].multiselect("Status", ["Aberta", "Em correção"], placeholder="Todos")

        filtros, params = [], []
        for campo, valores in (("setor", f_setor), ("severidade", f_sev),
                               ("situacao_prazo", f_prazo), ("status", f_status)):
            if valores:
                filtros.append(f"{campo} = ANY(%s)")
                params.append(valores)
        sql = ("SELECT id_ocorrencia, hostname, setor, cve, titulo, severidade, cvss, status,\n"
               "       data_deteccao, prazo_correcao, dias_restantes, situacao_prazo, responsavel\n"
               "  FROM vw_ocorrencias_pendentes\n")
        if filtros:
            sql += " WHERE " + "\n   AND ".join(filtros) + "\n"
        sql += " ORDER BY dias_restantes, cvss DESC"
        df = db.consultar(sql, params)
        contagem(len(df), "ocorrência")
        st.caption("Clique em uma linha para abrir a ocorrência e atualizá-la ou fechá-la.")
        tabela(df, altura=500, chave="pendentes",
               ao_selecionar=lambda r: dialogo_ocorrencia(int(r.id_ocorrencia)))
        ver_sql(sql)

    with aba2:
        secao("Registrar ocorrência",
              "Executa a stored procedure sp_registrar_ocorrencia: impede duplicidade e marca reincidências. "
              "O prazo de correção é calculado pela trigger.")
        ativos = opcoes("SELECT id_ativo, hostname || '   ' || host(ip) FROM ativo "
                        "WHERE situacao = 'Ativo' ORDER BY hostname")
        vulns = opcoes("SELECT cve, cve || '   ' || severidade || '   ' || titulo "
                       "FROM vulnerabilidade ORDER BY cvss DESC, cve")
        varreds = opcoes("SELECT id_varredura, to_char(data_varredura, 'DD/MM/YYYY') || '   ' || ferramenta "
                         "|| '   ' || escopo FROM varredura ORDER BY data_varredura DESC")
        with st.form("nova_ocorrencia"):
            id_ativo = st.selectbox("Ativo", list(ativos), format_func=ativos.get)
            cve = st.selectbox("Vulnerabilidade (CVE)", list(vulns), format_func=vulns.get)
            id_varr = st.selectbox("Varredura que detectou", list(varreds), format_func=varreds.get)
            enviar = st.form_submit_button("Registrar ocorrência", type="primary", icon=":material/add:")
        sql = "CALL sp_registrar_ocorrencia(%s, %s, %s, NULL);"
        if enviar:
            try:
                antes = score_ativo(id_ativo)
                (resultado,) = db.executar(sql, (id_ativo, cve, id_varr))
                depois = score_ativo(id_ativo)
                if resultado.startswith("Nada"):
                    st.warning(resultado, icon=":material/warning:")
                else:
                    prazo = db.valor("SELECT prazo_correcao FROM ocorrencia WHERE id_ativo = %s "
                                     "ORDER BY id_ocorrencia DESC LIMIT 1", (id_ativo,))
                    ok(f"{resultado}  \nPrazo de correção definido pela trigger: **{fmt_data(prazo)}**  \n"
                       f"Score de risco do ativo recalculado pela trigger: **{antes} → {depois}**")
            except ErroBanco as e:
                erro(str(e))
        ver_sql("CALL sp_registrar_ocorrencia({id_ativo}, '{cve}', {id_varredura}, NULL);")

    with aba3:
        pend = opcoes("SELECT id_ocorrencia, '#' || id_ocorrencia || '   ' || hostname || '   ' || cve "
                      "|| '   ' || severidade || '   ' || status FROM vw_ocorrencias_pendentes "
                      "ORDER BY dias_restantes")
        if not pend:
            st.info("Não há ocorrências pendentes.", icon=":material/inbox:")
        else:
            id_oc = st.selectbox("Ocorrência pendente", list(pend), format_func=pend.get)
            editor_ocorrencia(id_oc, "aba")

    with aba4:
        busca = st.text_input("Buscar por hostname ou CVE", placeholder="ex.: srv-ad01 ou CVE-2021-44228")
        sql = """SELECT o.id_ocorrencia, a.hostname, v.cve, v.severidade, o.status,
       o.data_deteccao, o.prazo_correcao, o.data_correcao,
       o.data_correcao - o.data_deteccao AS dias_para_corrigir,
       vr.ferramenta, o.observacao
  FROM ocorrencia o
  JOIN ativo a           ON a.id_ativo = o.id_ativo
  JOIN vulnerabilidade v ON v.id_vulnerabilidade = o.id_vulnerabilidade
  JOIN varredura vr      ON vr.id_varredura = o.id_varredura
 WHERE a.hostname ILIKE %(b)s OR v.cve ILIKE %(b)s
 ORDER BY o.data_deteccao DESC, o.id_ocorrencia DESC"""
        df = db.consultar(sql, {"b": f"%{busca.strip()}%"})
        contagem(len(df))
        tabela(df, altura=520)
        ver_sql(sql)


# ---------------------------------------------------------------------
# PÁGINA: ATIVOS
# ---------------------------------------------------------------------
SQL_LISTAR_ATIVOS = """SELECT a.id_ativo AS id, a.hostname, host(a.ip) AS ip, a.tipo, a.sistema_operacional,
       s.nome AS setor, r.nome AS responsavel, a.criticidade, a.score_risco, a.situacao,
       COUNT(o.id_ocorrencia) AS pendentes
  FROM ativo a
  JOIN setor s       ON s.id_setor = a.id_setor
  JOIN responsavel r ON r.id_responsavel = a.id_responsavel
  LEFT JOIN ocorrencia o ON o.id_ativo = a.id_ativo AND o.status IN ('Aberta', 'Em correção')
 WHERE (%(setor)s IS NULL OR s.nome = %(setor)s)
   AND (%(tipo)s IS NULL OR a.tipo = %(tipo)s)
 GROUP BY a.id_ativo, s.nome, r.nome
 ORDER BY a.score_risco DESC, a.hostname"""

SQL_HISTORICO_ATIVO = """SELECT v.cve, v.titulo, v.severidade, vr.ferramenta, o.data_deteccao,
       o.prazo_correcao, o.status, o.data_correcao
  FROM ocorrencia o
  JOIN vulnerabilidade v ON v.id_vulnerabilidade = o.id_vulnerabilidade
  JOIN varredura vr      ON vr.id_varredura = o.id_varredura
 WHERE o.id_ativo = %s
 ORDER BY o.data_deteccao DESC"""


def form_ativo(prefixo, atual=None):
    setores = opcoes("SELECT id_setor, nome FROM setor ORDER BY nome")
    resps = opcoes("SELECT id_responsavel, nome || ' (' || cargo || ')' FROM responsavel ORDER BY nome")
    atual = atual or {}
    c1, c2 = st.columns(2)
    hostname = c1.text_input("Hostname", atual.get("hostname", ""), key=f"{prefixo}_h")
    ip = c2.text_input("Endereço IP", atual.get("ip", ""), placeholder="10.10.1.100", key=f"{prefixo}_ip")
    tipo = c1.selectbox("Tipo", TIPOS, index=TIPOS.index(atual["tipo"]) if atual else 0, key=f"{prefixo}_t")
    so = c2.text_input("Sistema operacional ou firmware", atual.get("sistema_operacional", "") or "",
                       key=f"{prefixo}_so")
    lista_s, lista_r = list(setores), list(resps)
    setor = c1.selectbox("Setor", lista_s, format_func=setores.get,
                         index=lista_s.index(atual["id_setor"]) if atual else 0, key=f"{prefixo}_s")
    resp = c2.selectbox("Responsável", lista_r, format_func=resps.get,
                        index=lista_r.index(atual["id_responsavel"]) if atual else 0, key=f"{prefixo}_r")
    crit = st.slider("Criticidade (1 = baixa importância, 5 = essencial para a organização)", 1, 5,
                     int(atual.get("criticidade", 3)), key=f"{prefixo}_c")
    return dict(hostname=hostname.strip(), ip=ip.strip(), tipo=tipo, so=so.strip() or None,
                setor=setor, resp=resp, crit=crit)


def pagina_ativos():
    cabecalho("Ativos", "Ativos", "Servidores, estações e equipamentos de rede monitorados")
    mostrar_avisos()
    aba1, aba2, aba3, aba4 = st.tabs(["Listar", "Cadastrar", "Editar", "Excluir"])

    with aba1:
        c = st.columns(2)
        setores = ["Todos"] + db.consultar("SELECT nome FROM setor ORDER BY nome")["nome"].tolist()
        f_setor = c[0].selectbox("Setor", setores)
        f_tipo = c[1].selectbox("Tipo", ["Todos"] + TIPOS)
        df = db.consultar(SQL_LISTAR_ATIVOS, {"setor": None if f_setor == "Todos" else f_setor,
                                              "tipo": None if f_tipo == "Todos" else f_tipo})
        contagem(len(df), "ativo")
        tabela(df, altura=420)
        ver_sql(SQL_LISTAR_ATIVOS)

        st.write("")
        with painel():
            secao("Histórico de vulnerabilidades de um ativo",
                  "Relacionamento ativo → ocorrência → vulnerabilidade → varredura")
            ativos = opcoes("SELECT id_ativo, hostname FROM ativo ORDER BY hostname")
            id_a = st.selectbox("Ativo", list(ativos), format_func=ativos.get, key="hist_ativo",
                                label_visibility="collapsed")
            tabela(db.consultar(SQL_HISTORICO_ATIVO, (id_a,)))
            ver_sql(SQL_HISTORICO_ATIVO)

    with aba2:
        with st.form("cad_ativo", clear_on_submit=True):
            d = form_ativo("cad")
            enviar = st.form_submit_button("Cadastrar ativo", type="primary", icon=":material/add:")
        sql = ("INSERT INTO ativo (hostname, ip, tipo, sistema_operacional, criticidade, id_setor, id_responsavel)\n"
               "VALUES (%s, %s, %s, %s, %s, %s, %s)\nRETURNING id_ativo;")
        if enviar:
            if not d["hostname"] or not d["ip"]:
                erro("Preencha hostname e IP.")
            else:
                try:
                    (novo,) = db.executar(sql, (d["hostname"], d["ip"], d["tipo"], d["so"], d["crit"],
                                                d["setor"], d["resp"]))
                    ok(f"Ativo **{d['hostname']}** cadastrado com id {novo}.")
                except ErroBanco as e:
                    erro(str(e))
        ver_sql(sql)

    with aba3:
        ativos = opcoes("SELECT id_ativo, hostname FROM ativo ORDER BY hostname")
        id_a = st.selectbox("Ativo para editar", list(ativos), format_func=ativos.get, key="edit_sel")
        atual = db.consultar("SELECT hostname, host(ip) AS ip, tipo, sistema_operacional, criticidade, "
                             "id_setor, id_responsavel, situacao, score_risco FROM ativo WHERE id_ativo = %s",
                             (id_a,)).iloc[0].to_dict()
        with st.form(f"edit_ativo_{id_a}"):
            d = form_ativo(f"ed{id_a}", atual)
            situacao = st.radio("Situação", ["Ativo", "Inativo"], horizontal=True,
                                index=0 if atual["situacao"] == "Ativo" else 1, key=f"sit{id_a}")
            enviar = st.form_submit_button("Salvar alterações", type="primary", icon=":material/save:")
        sql = ("UPDATE ativo\n   SET hostname = %s, ip = %s, tipo = %s, sistema_operacional = %s,\n"
               "       criticidade = %s, id_setor = %s, id_responsavel = %s, situacao = %s\n WHERE id_ativo = %s;")
        if enviar:
            try:
                db.executar(sql, (d["hostname"], d["ip"], d["tipo"], d["so"], d["crit"], d["setor"],
                                  d["resp"], situacao, id_a))
                depois = score_ativo(id_a)
                extra = ""
                if d["crit"] != atual["criticidade"]:
                    extra = (f"  \nA criticidade mudou, então a trigger refez o score: "
                             f"**{float(atual['score_risco'])} → {depois}**")
                avisar(f"Ativo **{d['hostname']}** atualizado.{extra}")
                st.rerun()
            except ErroBanco as e:
                erro(str(e))
        ver_sql(sql)

    with aba4:
        ativos = opcoes("SELECT id_ativo, hostname FROM ativo ORDER BY hostname")
        id_a = st.selectbox("Ativo para excluir", list(ativos), format_func=ativos.get, key="del_sel")
        qtd = db.valor("SELECT COUNT(*) FROM ocorrencia WHERE id_ativo = %s", (id_a,))
        st.warning(f"Este ativo tem **{qtd}** ocorrência(s) no histórico. Elas serão apagadas junto "
                   "(ON DELETE CASCADE). Se o equipamento só saiu de uso, prefira marcá-lo como Inativo na aba Editar.",
                   icon=":material/warning:")
        conf = st.checkbox("Confirmo a exclusão", key=f"del_conf_{id_a}")
        sql = "DELETE FROM ativo WHERE id_ativo = %s;"
        if st.button("Excluir ativo", disabled=not conf, type="primary", icon=":material/delete:"):
            try:
                db.executar(sql, (id_a,))
                avisar(f"Ativo **{ativos[id_a]}** excluído (e suas ocorrências). A exclusão ficou registrada na auditoria.")
                st.rerun()
            except ErroBanco as e:
                erro(str(e))
        ver_sql(sql)


# ---------------------------------------------------------------------
# PÁGINA: VULNERABILIDADES
# ---------------------------------------------------------------------
def pagina_vulnerabilidades():
    cabecalho("Vulnerabilidades", "Vulnerabilidades",
              "Catálogo de CVEs. A severidade é definida automaticamente pela nota CVSS (trigger)")
    mostrar_avisos()
    aba1, aba2, aba3, aba4 = st.tabs(["Catálogo", "Cadastrar", "Editar", "Excluir"])

    with aba1:
        c = st.columns([1, 2])
        f_sev = c[0].multiselect("Severidade", SEVERIDADES, placeholder="Todas")
        busca = c[1].text_input("Buscar por CVE ou título")
        sql = """SELECT v.cve, v.titulo, v.cvss, v.severidade, v.data_publicacao, v.solucao,
       COUNT(o.id_ocorrencia) FILTER (WHERE o.status IN ('Aberta','Em correção')) AS ativos_afetados
  FROM vulnerabilidade v
  LEFT JOIN ocorrencia o ON o.id_vulnerabilidade = v.id_vulnerabilidade
 WHERE (v.cve ILIKE %(b)s OR v.titulo ILIKE %(b)s)
   AND (cardinality(%(sev)s::varchar[]) = 0 OR v.severidade = ANY(%(sev)s::varchar[]))
 GROUP BY v.id_vulnerabilidade
 ORDER BY v.cvss DESC, v.cve"""
        df = db.consultar(sql, {"b": f"%{busca.strip()}%", "sev": f_sev})
        contagem(len(df), "vulnerabilidade")
        tabela(df, altura=500)
        ver_sql(sql)

    with aba2:
        with st.form("cad_vuln", clear_on_submit=True):
            c1, c2 = st.columns([2, 1])
            cve = c1.text_input("Código CVE", placeholder="CVE-2024-12345")
            cvss = c2.number_input("Nota CVSS", 0.0, 10.0, 5.0, 0.1, format="%.1f")
            tit = st.text_input("Título")
            desc = st.text_area("Descrição")
            sol = st.text_area("Solução recomendada")
            pub = st.date_input("Data de publicação", value=None, format="DD/MM/YYYY")
            enviar = st.form_submit_button("Cadastrar vulnerabilidade", type="primary", icon=":material/add:")
        sql = ("INSERT INTO vulnerabilidade (cve, titulo, descricao, cvss, solucao, data_publicacao)\n"
               "VALUES (%s, %s, %s, %s, %s, %s)\nRETURNING severidade;")
        if enviar:
            if not cve.strip() or not tit.strip():
                erro("Preencha o código CVE e o título.")
            else:
                try:
                    (sev,) = db.executar(sql, (cve.strip().upper(), tit.strip(), desc or None, cvss,
                                               sol or None, pub))
                    ok(f"{cve.strip().upper()} cadastrada. Severidade calculada pela trigger: **{sev}**")
                except ErroBanco as e:
                    erro(str(e))
        ver_sql(sql)

    with aba3:
        vulns = opcoes("SELECT id_vulnerabilidade, cve || '   ' || titulo FROM vulnerabilidade ORDER BY cve")
        id_v = st.selectbox("Vulnerabilidade", list(vulns), format_func=vulns.get, key="ed_v")
        at = db.consultar("SELECT * FROM vulnerabilidade WHERE id_vulnerabilidade = %s", (id_v,)).iloc[0]
        with st.form(f"ed_vuln_{id_v}"):
            tit = st.text_input("Título", at.titulo)
            cvss = st.number_input("Nota CVSS", 0.0, 10.0, float(at.cvss), 0.1, format="%.1f")
            desc = st.text_area("Descrição", at.descricao or "")
            sol = st.text_area("Solução recomendada", at.solucao or "")
            enviar = st.form_submit_button("Salvar alterações", type="primary", icon=":material/save:")
        sql = ("UPDATE vulnerabilidade\n   SET titulo = %s, cvss = %s, descricao = %s, solucao = %s\n"
               " WHERE id_vulnerabilidade = %s\nRETURNING severidade;")
        if enviar:
            try:
                (sev,) = db.executar(sql, (tit, cvss, desc or None, sol or None, id_v))
                extra = "" if sev == at.severidade else (
                    f"  \nO CVSS mudou e a trigger reclassificou: **{at.severidade} → {sev}**")
                avisar(f"{at.cve} atualizada.{extra}")
                st.rerun()
            except ErroBanco as e:
                erro(str(e))
        ver_sql(sql)

    with aba4:
        vulns = opcoes("SELECT id_vulnerabilidade, cve || '   ' || titulo FROM vulnerabilidade ORDER BY cve")
        id_v = st.selectbox("Vulnerabilidade", list(vulns), format_func=vulns.get, key="del_v")
        qtd = db.valor("SELECT COUNT(*) FROM ocorrencia WHERE id_vulnerabilidade = %s", (id_v,))
        if qtd:
            st.info(f"Esta CVE tem {qtd} ocorrência(s) registrada(s). O banco vai bloquear a exclusão "
                    "(chave estrangeira sem CASCADE) para não perder o histórico.", icon=":material/info:")
        conf = st.checkbox("Confirmo a exclusão", key=f"del_v_conf_{id_v}")
        sql = "DELETE FROM vulnerabilidade WHERE id_vulnerabilidade = %s;"
        if st.button("Excluir vulnerabilidade", disabled=not conf, type="primary", icon=":material/delete:"):
            try:
                db.executar(sql, (id_v,))
                avisar(f"{vulns[id_v].split()[0]} excluída.")
                st.rerun()
            except ErroBanco as e:
                erro(str(e))
        ver_sql(sql)


# ---------------------------------------------------------------------
# PÁGINA: VARREDURAS
# ---------------------------------------------------------------------
def pagina_varreduras():
    cabecalho("Varreduras", "Varreduras", "Execuções de scanners de vulnerabilidade (OpenVAS, Nessus, Nmap)")
    mostrar_avisos()
    aba1, aba2, aba3 = st.tabs(["Listar", "Registrar", "Excluir"])

    with aba1:
        sql = """SELECT vr.id_varredura AS id, vr.data_varredura, vr.ferramenta, vr.escopo,
       r.nome AS executada_por, COUNT(o.id_ocorrencia) AS ocorrencias_encontradas, vr.observacao
  FROM varredura vr
  JOIN responsavel r     ON r.id_responsavel = vr.id_responsavel
  LEFT JOIN ocorrencia o ON o.id_varredura = vr.id_varredura
 GROUP BY vr.id_varredura, r.nome
 ORDER BY vr.data_varredura DESC"""
        df = db.consultar(sql)
        if not df.empty:
            with painel():
                secao("Ocorrências encontradas por varredura")
                graf = df.sort_values("data_varredura").copy()
                graf["rotulo"] = graf["data_varredura"].map(fmt_data) + "<br>" + graf["ferramenta"]
                fig = px.bar(graf, x="rotulo", y="ocorrencias_encontradas", text="ocorrencias_encontradas",
                             labels={"rotulo": "", "ocorrencias_encontradas": "Ocorrências"})
                fig.update_traces(marker=dict(color=VERMELHO, line=dict(color="#FF4D57", width=1)),
                                  textposition="outside", cliponaxis=False,
                                  textfont=dict(color="#F3F4F6", family="Orbitron, Inter, sans-serif", size=11))
                fig.update_xaxes(gridcolor="rgba(0,0,0,0)", tickfont=dict(color="#D1D5DB"))
                fig.update_yaxes(gridcolor="rgba(255,255,255,0.05)")
                grafico(fig, 280)
        tabela(df)
        ver_sql(sql)

    with aba2:
        resps = opcoes("SELECT id_responsavel, nome FROM responsavel ORDER BY nome")
        with st.form("cad_varr", clear_on_submit=True):
            c1, c2 = st.columns(2)
            data_v = c1.date_input("Data", value=date.today(), format="DD/MM/YYYY")
            ferr = c2.selectbox("Ferramenta", FERRAMENTAS)
            escopo = c1.text_input("Escopo (rede ou faixa)", placeholder="10.10.0.0/16")
            resp = c2.selectbox("Executada por", list(resps), format_func=resps.get)
            obs = st.text_area("Observação")
            enviar = st.form_submit_button("Registrar varredura", type="primary", icon=":material/add:")
        sql = ("INSERT INTO varredura (data_varredura, ferramenta, escopo, observacao, id_responsavel)\n"
               "VALUES (%s, %s, %s, %s, %s)\nRETURNING id_varredura;")
        if enviar:
            if not escopo.strip():
                erro("Informe o escopo.")
            else:
                try:
                    (novo,) = db.executar(sql, (data_v, ferr, escopo.strip(), obs or None, resp))
                    ok(f"Varredura #{novo} registrada. Agora registre as ocorrências encontradas na página Ocorrências.")
                except ErroBanco as e:
                    erro(str(e))
        ver_sql(sql)

    with aba3:
        varreds = opcoes("SELECT id_varredura, '#' || id_varredura || '   ' || to_char(data_varredura, 'DD/MM/YYYY') "
                         "|| '   ' || ferramenta FROM varredura ORDER BY data_varredura DESC")
        id_v = st.selectbox("Varredura", list(varreds), format_func=varreds.get)
        st.caption("Varreduras que já têm ocorrências não podem ser excluídas (integridade referencial).")
        conf = st.checkbox("Confirmo a exclusão", key=f"del_varr_{id_v}")
        sql = "DELETE FROM varredura WHERE id_varredura = %s;"
        if st.button("Excluir varredura", disabled=not conf, type="primary", icon=":material/delete:"):
            try:
                db.executar(sql, (id_v,))
                avisar("Varredura excluída.")
                st.rerun()
            except ErroBanco as e:
                erro(str(e))
        ver_sql(sql)


# ---------------------------------------------------------------------
# PÁGINA: SETORES E RESPONSÁVEIS
# ---------------------------------------------------------------------
def pagina_cadastros():
    cabecalho("Cadastros", "Setores e responsáveis", "Estrutura da organização e quem responde por cada ativo")
    mostrar_avisos()
    esq, dir_ = st.columns(2, gap="medium")

    with esq:
        with painel():
            secao("Setores")
            sql = """SELECT s.id_setor AS id, s.nome, s.localizacao, COUNT(a.id_ativo) AS ativos
  FROM setor s LEFT JOIN ativo a ON a.id_setor = s.id_setor
 GROUP BY s.id_setor ORDER BY s.nome"""
            tabela(db.consultar(sql))
            ver_sql(sql)
        with st.form("cad_setor", clear_on_submit=True):
            secao("Novo setor")
            nome = st.text_input("Nome do setor")
            loc = st.text_input("Localização")
            enviar = st.form_submit_button("Cadastrar setor", icon=":material/add:")
        if enviar and nome.strip():
            try:
                db.executar("INSERT INTO setor (nome, localizacao) VALUES (%s, %s)", (nome.strip(), loc or None))
                avisar(f"Setor **{nome}** cadastrado.")
                st.rerun()
            except ErroBanco as e:
                erro(str(e))

    with dir_:
        with painel():
            secao("Responsáveis")
            sql = """SELECT r.id_responsavel AS id, r.nome, r.email, r.cargo, s.nome AS setor,
       COUNT(a.id_ativo) AS ativos_sob_responsabilidade
  FROM responsavel r
  JOIN setor s ON s.id_setor = r.id_setor
  LEFT JOIN ativo a ON a.id_responsavel = r.id_responsavel
 GROUP BY r.id_responsavel, s.nome ORDER BY r.nome"""
            tabela(db.consultar(sql))
            ver_sql(sql)
        setores = opcoes("SELECT id_setor, nome FROM setor ORDER BY nome")
        with st.form("cad_resp", clear_on_submit=True):
            secao("Novo responsável")
            c1, c2 = st.columns(2)
            nome = c1.text_input("Nome")
            email = c2.text_input("E-mail")
            cargo = c1.text_input("Cargo")
            setor = c2.selectbox("Setor", list(setores), format_func=setores.get)
            enviar = st.form_submit_button("Cadastrar responsável", icon=":material/add:")
        if enviar and nome.strip() and email.strip():
            try:
                db.executar("INSERT INTO responsavel (nome, email, cargo, id_setor) VALUES (%s, %s, %s, %s)",
                            (nome.strip(), email.strip().lower(), cargo or None, setor))
                avisar(f"Responsável **{nome}** cadastrado.")
                st.rerun()
            except ErroBanco as e:
                erro(str(e))


# ---------------------------------------------------------------------
# PÁGINA: RELATÓRIOS (VIEWS) E OTIMIZAÇÃO
# ---------------------------------------------------------------------
VIEWS = {
    "vw_ranking_ativos": "Ranking dos ativos mais expostos, pelo score de risco",
    "vw_ocorrencias_pendentes": "Ocorrências pendentes com detalhes e situação do prazo",
    "vw_ocorrencias_vencidas": "Ocorrências que passaram do prazo de correção",
    "vw_resumo_setor": "Quantidade de pendências por setor e severidade",
    "vw_tempo_medio_correcao": "Tempo médio de correção e % corrigido dentro do prazo",
    "vw_vulnerabilidades_frequentes": "CVEs mais encontradas no parque",
}

SQL_PLANO = """SELECT id_ocorrencia, prazo_correcao
  FROM ocorrencia
 WHERE status IN ('Aberta', 'Em correção')
   AND prazo_correcao < CURRENT_DATE"""


def pagina_relatorios():
    cabecalho("Relatórios", "Relatórios", "Consultas às views do banco e análise de desempenho")
    aba1, aba2 = st.tabs(["Views", "Otimização com índices"])

    with aba1:
        nome = st.selectbox("View", list(VIEWS), format_func=lambda v: f"{v}   ·   {VIEWS[v]}")
        df = db.consultar(f"SELECT * FROM {nome}")
        contagem(len(df), "linha")
        tabela(df, altura=480)
        definicao = db.valor("SELECT pg_get_viewdef(%s::regclass, true)", (nome,))
        ver_sql(f"CREATE OR REPLACE VIEW {nome} AS\n{definicao}", "Ver definição da view")

    with aba2:
        with painel():
            secao("Plano de execução da consulta de ocorrências vencidas",
                  "O índice parcial idx_ocorrencia_pendente_prazo guarda só as ocorrências pendentes, "
                  "ordenadas pelo prazo.")
            st.code(SQL_PLANO, language="sql")
            st.caption("Com poucos dados o PostgreSQL pode achar mais barato ler a tabela inteira (Seq Scan). "
                       "Por isso a segunda execução desliga a leitura sequencial, para mostrar o índice sendo usado.")
            if st.button("Executar EXPLAIN ANALYZE", type="primary", icon=":material/play_arrow:"):
                con = db.conectar()
                try:
                    with con.cursor() as cur:
                        cur.execute("EXPLAIN ANALYZE " + SQL_PLANO)
                        normal = "\n".join(r[0] for r in cur.fetchall())
                        cur.execute("SET LOCAL enable_seqscan = off")
                        cur.execute("EXPLAIN ANALYZE " + SQL_PLANO)
                        com_indice = "\n".join(r[0] for r in cur.fetchall())
                    con.rollback()
                finally:
                    con.close()
                c1, c2 = st.columns(2)
                with c1:
                    secao("Plano escolhido pelo PostgreSQL")
                    st.code(normal, language="text")
                with c2:
                    secao("Forçando o uso do índice")
                    st.code(com_indice, language="text")
        st.write("")
        secao("Índices do banco")
        tabela(db.consultar("""SELECT indexname AS indice, tablename AS tabela, indexdef AS definicao
  FROM pg_indexes WHERE schemaname = 'public' ORDER BY tablename, indexname"""))


# ---------------------------------------------------------------------
# PÁGINA: AUDITORIA
# ---------------------------------------------------------------------
def pagina_auditoria():
    cabecalho("Auditoria", "Auditoria", "Registro automático (trigger) de toda inclusão, alteração e exclusão")
    c = st.columns(3)
    f_tab = c[0].selectbox("Tabela", ["Todas", "ativo", "vulnerabilidade", "ocorrencia", "usuario"])
    f_op = c[1].selectbox("Operação", ["Todas", "INSERT", "UPDATE", "DELETE"])
    logins = db.consultar("SELECT DISTINCT usuario_app FROM auditoria WHERE usuario_app IS NOT NULL "
                          "ORDER BY 1")["usuario_app"].tolist()
    f_usu = c[2].selectbox("Usuário", ["Todos"] + logins)
    sql = """SELECT id_auditoria AS id, data_hora, usuario_app, tabela, operacao, id_registro, usuario_bd
  FROM auditoria
 WHERE (%(t)s IS NULL OR tabela = %(t)s)
   AND (%(o)s IS NULL OR operacao = %(o)s)
   AND (%(u)s IS NULL OR usuario_app = %(u)s)
 ORDER BY data_hora DESC, id_auditoria DESC
 LIMIT 300"""
    df = db.consultar(sql, {"t": None if f_tab == "Todas" else f_tab, "o": None if f_op == "Todas" else f_op,
                            "u": None if f_usu == "Todos" else f_usu})
    if df.empty:
        st.info("Nenhuma alteração registrada ainda. Faça um cadastro, edição ou exclusão em qualquer tela "
                "e volte aqui.", icon=":material/inbox:")
        return
    contagem(len(df))
    tabela(df, altura=320)
    ver_sql(sql)

    st.write("")
    with painel():
        secao("Detalhe do registro", "Comparação entre os dados antes e depois da operação")
        id_aud = st.selectbox("Registro de auditoria", df["id"].tolist(), label_visibility="collapsed",
                              format_func=lambda i: f"#{i}   " + "   ".join(
                                  str(x) for x in df.loc[df.id == i, ["tabela", "operacao", "id_registro",
                                                                      "usuario_app"]].iloc[0]))
        linha = db.consultar("SELECT dados_antigos, dados_novos FROM auditoria WHERE id_auditoria = %s",
                             (id_aud,)).iloc[0]
        antigo, novo = linha.dados_antigos or {}, linha.dados_novos or {}
        campos = list(dict.fromkeys(list(antigo) + list(novo)))
        comp = pd.DataFrame({
            "campo": campos,
            "antes": ["" if antigo.get(k) is None else str(antigo.get(k)) for k in campos],
            "depois": ["" if novo.get(k) is None else str(novo.get(k)) for k in campos],
        })
        comp["alterado"] = comp["antes"] != comp["depois"]
        if st.toggle("Mostrar só os campos alterados", value=bool(antigo and novo)):
            comp = comp[comp["alterado"]]
        tabela(comp.drop(columns="alterado"))


# ---------------------------------------------------------------------
# PÁGINA: USUÁRIOS (só administradores)
# ---------------------------------------------------------------------
def admins_ativos_alem_de(id_usuario):
    return db.valor("SELECT COUNT(*) FROM usuario WHERE perfil = 'Administrador' AND ativo "
                    "AND id_usuario <> %s", (id_usuario,))


def pagina_usuarios():
    cabecalho("Usuários", "Usuários", "Contas de acesso ao sistema. Toda alteração fica registrada na auditoria")
    mostrar_avisos()
    eu = st.session_state["usuario"]
    aba1, aba2, aba3 = st.tabs(["Listar", "Cadastrar", "Editar"])

    with aba1:
        sql = """SELECT id_usuario AS id, nome, login, perfil,
       CASE WHEN ativo THEN 'Ativo' ELSE 'Inativo' END AS situacao,
       data_cadastro, ultimo_acesso
  FROM usuario
 ORDER BY ativo DESC, nome"""
        df = db.consultar(sql)
        contagem(len(df), "usuário")
        tabela(df)
        ver_sql(sql)

    with aba2:
        with st.form("cad_usuario", clear_on_submit=True):
            c1, c2 = st.columns(2)
            nome = c1.text_input("Nome completo")
            login = c2.text_input("Login", placeholder="ex.: maria.souza")
            senha = c1.text_input("Senha", type="password")
            conf = c2.text_input("Confirme a senha", type="password")
            perfil = st.radio("Perfil", auth.PERFIS, index=1, horizontal=True,
                              help="Administrador também gerencia os usuários do sistema.")
            enviar = st.form_submit_button("Cadastrar usuário", type="primary", icon=":material/person_add:")
        sql = "INSERT INTO usuario (nome, login, senha_hash, perfil) VALUES (%s, %s, %s, %s) RETURNING id_usuario;"
        if enviar:
            login = login.strip().lower()
            problema = (("Preencha o nome." if not nome.strip() else None)
                        or auth.validar_login(login) or auth.validar_senha(senha, conf))
            if problema:
                erro(problema)
            else:
                try:
                    (novo,) = db.executar(sql, (nome.strip(), login, auth.gerar_hash(senha), perfil))
                    ok(f"Usuário **{login}** cadastrado (id {novo}, perfil {perfil}).")
                except ErroBanco as e:
                    erro(str(e))
        ver_sql(sql.replace("%s, %s, %s, %s", "'{nome}', '{login}', '{hash PBKDF2 da senha}', '{perfil}'"))

    with aba3:
        usuarios = opcoes("SELECT id_usuario, nome || '   (' || login || ')' FROM usuario ORDER BY nome")
        id_u = st.selectbox("Usuário", list(usuarios), format_func=usuarios.get, key="ed_usu")
        at = db.consultar("SELECT nome, login, perfil, ativo FROM usuario WHERE id_usuario = %s", (id_u,)).iloc[0]
        proprio = id_u == eu["id"]
        with st.form(f"ed_usuario_{id_u}"):
            nome = st.text_input("Nome completo", at.nome)
            c1, c2 = st.columns(2)
            perfil = c1.radio("Perfil", auth.PERFIS, index=auth.PERFIS.index(at.perfil), horizontal=True,
                              disabled=proprio)
            ativo = c2.toggle("Conta ativa", value=bool(at.ativo), disabled=proprio)
            st.caption("Nova senha (deixe em branco para manter a atual)")
            c1, c2 = st.columns(2)
            senha = c1.text_input("Nova senha", type="password")
            conf = c2.text_input("Confirme a nova senha", type="password")
            enviar = st.form_submit_button("Salvar alterações", type="primary", icon=":material/save:")
        if proprio:
            st.caption("Você não pode mudar o próprio perfil nem desativar a própria conta.")
        if enviar:
            problema = "Preencha o nome." if not nome.strip() else None
            if not problema and senha:
                problema = auth.validar_senha(senha, conf)
            perde_admin = at.perfil == "Administrador" and at.ativo and (perfil != "Administrador" or not ativo)
            if not problema and perde_admin and admins_ativos_alem_de(id_u) == 0:
                problema = "Este é o único administrador ativo. Promova outro usuário antes."
            if problema:
                erro(problema)
            else:
                try:
                    if senha:
                        db.executar("UPDATE usuario SET nome = %s, perfil = %s, ativo = %s, senha_hash = %s "
                                    "WHERE id_usuario = %s", (nome.strip(), perfil, ativo, auth.gerar_hash(senha), id_u))
                    else:
                        db.executar("UPDATE usuario SET nome = %s, perfil = %s, ativo = %s WHERE id_usuario = %s",
                                    (nome.strip(), perfil, ativo, id_u))
                    avisar(f"Usuário **{at.login}** atualizado" + (" (senha redefinida)." if senha else "."))
                    st.rerun()
                except ErroBanco as e:
                    erro(str(e))
        st.caption("Contas não são excluídas, só desativadas: assim o histórico da auditoria continua apontando "
                   "para quem fez cada alteração.")


# ---------------------------------------------------------------------
# PÁGINA: MINHA CONTA
# ---------------------------------------------------------------------
def pagina_minha_conta():
    eu = st.session_state["usuario"]
    cabecalho("Minha conta", "Minha conta", f"{eu['nome']} · {eu['login']} · {eu['perfil']}")
    mostrar_avisos()
    with st.form("trocar_senha", clear_on_submit=True):
        secao("Trocar senha")
        atual = st.text_input("Senha atual", type="password")
        c1, c2 = st.columns(2)
        nova = c1.text_input("Nova senha", type="password")
        conf = c2.text_input("Confirme a nova senha", type="password")
        enviar = st.form_submit_button("Trocar senha", type="primary", icon=":material/key:")
    if enviar:
        guardado = db.valor("SELECT senha_hash FROM usuario WHERE id_usuario = %s", (eu["id"],))
        problema = None if auth.conferir_senha(atual, guardado or "") else "A senha atual não confere."
        problema = problema or auth.validar_senha(nova, conf)
        if problema:
            erro(problema)
        else:
            db.executar("UPDATE usuario SET senha_hash = %s WHERE id_usuario = %s", (auth.gerar_hash(nova), eu["id"]))
            avisar("Senha alterada.")
            st.rerun()


# ---------------------------------------------------------------------
# LOGIN
# ---------------------------------------------------------------------
MAX_TENTATIVAS = 5
ESPERA_BLOQUEIO = 30  # segundos


def tela_login():
    html("""<style>
      section[data-testid="stSidebar"], [data-testid="stSidebarCollapsedControl"],
      [data-testid="stExpandSidebarButton"] { display: none !important; }
      .block-container { max-width: 460px !important; padding-top: 7vh !important; }
      .login-logo img { width: 100%; display: block; margin: 0 auto 8px;
        filter: drop-shadow(0 0 30px rgba(229,9,20,.22)); }
      .login-tit { font-family: 'Orbitron', sans-serif; font-size: 18px; font-weight: 700; color: #F3F4F6;
        letter-spacing: .04em; margin: 18px 0 4px; }
      .login-sub { font-size: 13.5px; color: var(--muted); margin-bottom: 14px; }
      .login-rodape { text-align: center; font-size: 12px; color: var(--faint); margin-top: 18px; }
    </style>""")
    html(f"<div class='login-logo'><img alt='Ponto Cego' "
         f"src='data:image/png;base64,{imagem_b64('logo_ponto_cego.png')}'></div>")
    bloqueado_ate = st.session_state.get("login_bloqueado_ate", 0)
    restante = int(bloqueado_ate - time.time())
    with st.form("login"):
        html("<div class='login-tit'>Acesso ao sistema</div>"
             "<div class='login-sub'>Entre com seu usuário e senha.</div>")
        login = st.text_input("Usuário", placeholder="seu login")
        senha = st.text_input("Senha", type="password")
        entrar = st.form_submit_button("Entrar", type="primary", icon=":material/login:", width="stretch")
    if entrar:
        if restante > 0:
            erro(f"Muitas tentativas. Aguarde {restante} segundo(s) e tente de novo.")
        else:
            try:
                usuario = auth.autenticar(login, senha)
            except ErroBanco as e:
                erro(f"Não foi possível consultar os usuários: {e}  \n"
                     "Se o banco é de uma versão anterior, rode `python instalar_banco.py` de novo.")
                st.stop()
            if usuario:
                st.session_state.pop("login_falhas", None)
                st.session_state["usuario"] = usuario
                st.rerun()
            falhas = st.session_state.get("login_falhas", 0) + 1
            st.session_state["login_falhas"] = falhas
            if falhas >= MAX_TENTATIVAS:
                st.session_state["login_bloqueado_ate"] = time.time() + ESPERA_BLOQUEIO
                st.session_state["login_falhas"] = 0
            erro("Usuário ou senha incorretos, ou conta desativada.")
    html("<div class='login-rodape'>Banco de Dados II · Unimontes</div>")


# ---------------------------------------------------------------------
# NAVEGAÇÃO
# ---------------------------------------------------------------------
PAGINAS = {
    "Painel": (":material/space_dashboard:", pagina_painel),
    "Ocorrências": (":material/bug_report:", pagina_ocorrencias),
    "Ativos": (":material/dns:", pagina_ativos),
    "Vulnerabilidades": (":material/shield:", pagina_vulnerabilidades),
    "Varreduras": (":material/radar:", pagina_varreduras),
    "Setores e responsáveis": (":material/apartment:", pagina_cadastros),
    "Relatórios": (":material/analytics:", pagina_relatorios),
    "Auditoria": (":material/history:", pagina_auditoria),
    "Usuários": (":material/group:", pagina_usuarios),
    "Minha conta": (":material/account_circle:", pagina_minha_conta),
}
SO_ADMIN = {"Usuários"}

conectado, falha = db.testar_conexao()

if not conectado:
    cabecalho("Conexão", "Não foi possível conectar ao banco",
              "Confira se o PostgreSQL está rodando e se as configurações estão corretas")
    st.code(falha)
    st.markdown("1. Confira se o serviço do PostgreSQL está ativo.  \n"
                "2. Rode `python instalar_banco.py` para criar o banco **gestao_vulnerabilidades**.  \n"
                "3. Confira a senha em **app/config.py**.")
    st.stop()

# Toda alteração vai para a auditoria com o login da sessão de quem fez
db.definir_provedor_usuario(lambda: (st.session_state.get("usuario") or {}).get("login"))

usuario = st.session_state.get("usuario")
if not usuario:
    tela_login()
    st.stop()
admin = usuario["perfil"] == "Administrador"
visiveis = [p for p in PAGINAS if admin or p not in SO_ADMIN]

with st.sidebar:
    html(f"<div class='brand'><img alt='Ponto Cego' "
         f"src='data:image/png;base64,{imagem_b64('logo_ponto_cego_compacta.png')}'></div>"
         "<div class='brand-tag'>Descubra vulnerabilidades<br>em seus ativos</div>")
    html("<div class='nav-label'>Menu</div>")
    pagina = st.radio("Menu", visiveis, label_visibility="collapsed", key="menu",
                      format_func=lambda p: f"{PAGINAS[p][0]}&nbsp;&nbsp;{p}")
    iniciais = "".join(parte[0] for parte in usuario["nome"].split()[:2]).upper()
    html(f"<div class='side-user'><div class='avatar'>{escape(iniciais)}</div><div>"
         f"<div class='side-user-nome'>{escape(usuario['nome'])}</div>"
         f"<div class='side-user-perfil'>{escape(usuario['perfil'])} · {escape(usuario['login'])}</div>"
         f"</div></div>")
    if st.button("Sair", icon=":material/logout:", width="stretch", key="sair"):
        for chave in list(st.session_state):
            del st.session_state[chave]
        st.rerun()
    html(f"<div class='side-foot'><div class='conn'><span class='dot'></span>PostgreSQL conectado</div>"
         f"<div class='side-meta'>Banco <code>{escape(db.DB_CONFIG['dbname'])}</code><br>"
         f"Banco de Dados II · Unimontes</div></div>")
    html("<div class='side-sys'>sys.monitor · <b>online</b></div>")

try:
    PAGINAS[pagina][1]()
except ErroBanco as e:
    erro(f"Erro no banco de dados: {e}")
