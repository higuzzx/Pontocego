"""Funções de acesso ao banco (camada de dados da aplicação)."""
from decimal import Decimal

import pandas as pd
import psycopg2

from config import DB_CONFIG


class ErroBanco(Exception):
    """Erro do PostgreSQL traduzido para uma mensagem amigável."""


# Função que devolve o login de quem está usando a interface. A aplicação
# registra uma função que lê a sessão do usuário na hora de cada alteração
# (assim funciona também dentro de janelas e trechos que rodam em outra thread).
_provedor_usuario = None


def definir_provedor_usuario(funcao):
    """Registra a função que informa quem está logado; o login vai para a auditoria."""
    global _provedor_usuario
    _provedor_usuario = funcao


def usuario_atual():
    try:
        return _provedor_usuario() if _provedor_usuario else None
    except Exception:  # noqa: BLE001  (fora de uma sessão do Streamlit)
        return None


def conectar():
    return psycopg2.connect(**DB_CONFIG)


def _traduzir(e: psycopg2.Error) -> ErroBanco:
    codigo = e.pgcode or ""
    detalhe = (e.diag.message_primary or str(e)).strip()
    if codigo == "23503":  # foreign_key_violation
        return ErroBanco("Não é possível concluir: existem registros ligados a este item. " + detalhe)
    if codigo == "23505":  # unique_violation
        return ErroBanco("Já existe um registro com esse valor (campo único). " + detalhe)
    if codigo == "23514":  # check_violation
        return ErroBanco("Valor fora das regras do banco (restrição CHECK). " + detalhe)
    if codigo == "22P02":  # invalid_text_representation (ex.: IP inválido)
        return ErroBanco("Formato inválido. " + detalhe)
    return ErroBanco(detalhe)


def _df(cur) -> pd.DataFrame:
    if cur.description is None:
        return pd.DataFrame()
    colunas = [c.name for c in cur.description]
    linhas = cur.fetchall()
    df = pd.DataFrame(linhas, columns=colunas)
    for col in df.columns:  # NUMERIC do Postgres vem como Decimal; converte para float
        amostra = df[col].dropna()
        if len(amostra) and isinstance(amostra.iloc[0], Decimal):
            df[col] = df[col].astype(float)
    return df


def consultar(sql: str, params=None) -> pd.DataFrame:
    """Executa um SELECT e devolve um DataFrame."""
    try:
        with conectar() as con, con.cursor() as cur:
            cur.execute(sql, params)
            return _df(cur)
    except psycopg2.Error as e:
        raise _traduzir(e) from e


def valor(sql: str, params=None):
    """Executa um SELECT que devolve um único valor."""
    try:
        with conectar() as con, con.cursor() as cur:
            cur.execute(sql, params)
            linha = cur.fetchone()
            return linha[0] if linha else None
    except psycopg2.Error as e:
        raise _traduzir(e) from e


def executar(sql: str, params=None):
    """Executa INSERT/UPDATE/DELETE/CALL com commit.
    Devolve a primeira linha retornada (RETURNING ou INOUT da procedure), se houver."""
    con = conectar()
    try:
        with con.cursor() as cur:
            # variável de sessão lida pela trigger de auditoria (vale só nesta transação)
            cur.execute("SELECT set_config('app.usuario', %s, true)", (usuario_atual() or "",))
            cur.execute(sql, params)
            linha = cur.fetchone() if cur.description else None
            linhas_afetadas = cur.rowcount
        con.commit()
        return linha if linha is not None else linhas_afetadas
    except psycopg2.Error as e:
        con.rollback()
        raise _traduzir(e) from e
    finally:
        con.close()


def testar_conexao():
    try:
        with conectar() as con, con.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM ativo")
            return True, None
    except Exception as e:  # noqa: BLE001
        return False, str(e)
