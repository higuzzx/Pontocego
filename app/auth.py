"""Login do sistema: hash de senha e autenticação de usuários.

As senhas são guardadas como PBKDF2-SHA256 com salt aleatório
(formato: pbkdf2_sha256$iteracoes$salt_base64$hash_base64).
"""
import base64
import hashlib
import hmac
import os
import re

import db

ITERACOES = 240_000
SENHA_MINIMA = 6
PADRAO_LOGIN = re.compile(r"^[a-z0-9._-]{3,30}$")
PERFIS = ["Administrador", "Analista"]


def gerar_hash(senha: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), salt, ITERACOES)
    return f"pbkdf2_sha256${ITERACOES}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def conferir_senha(senha: str, guardado: str) -> bool:
    try:
        algoritmo, iteracoes, salt, esperado = guardado.split("$")
        if algoritmo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), base64.b64decode(salt), int(iteracoes))
        return hmac.compare_digest(dk, base64.b64decode(esperado))
    except (ValueError, TypeError):
        return False


# Hash usado quando o login não existe, para a resposta levar o mesmo tempo
# (não dá pistas de quais logins existem).
_HASH_FALSO = gerar_hash(os.urandom(8).hex())


def autenticar(login: str, senha: str):
    """Devolve os dados do usuário se login e senha conferem (e a conta está ativa); senão None."""
    login = (login or "").strip().lower()
    df = db.consultar("SELECT id_usuario, nome, login, senha_hash, perfil, ativo "
                      "FROM usuario WHERE login = %s", (login,))
    if df.empty:
        conferir_senha(senha, _HASH_FALSO)
        return None
    u = df.iloc[0]
    if not conferir_senha(senha, u.senha_hash) or not bool(u.ativo):
        return None
    db.executar("UPDATE usuario SET ultimo_acesso = CURRENT_TIMESTAMP WHERE id_usuario = %s",
                (int(u.id_usuario),))
    return {"id": int(u.id_usuario), "nome": u.nome, "login": u.login, "perfil": u.perfil}


def validar_login(login: str):
    """Devolve uma mensagem de erro, ou None se o login é válido."""
    if not PADRAO_LOGIN.match(login):
        return "O login deve ter de 3 a 30 caracteres: letras minúsculas, números, ponto, hífen ou sublinhado."
    return None


def validar_senha(senha: str, confirmacao: str):
    if len(senha) < SENHA_MINIMA:
        return f"A senha deve ter pelo menos {SENHA_MINIMA} caracteres."
    if senha != confirmacao:
        return "A confirmação não confere com a senha."
    return None
