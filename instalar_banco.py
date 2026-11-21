"""Cria o banco gestao_vulnerabilidades e roda o script completo (estrutura + dados).

Uso:  python instalar_banco.py
Atenção: se o banco já existir, ele é APAGADO e criado de novo (volta aos dados de exemplo).
"""
import sys
from pathlib import Path

import psycopg2
from psycopg2 import sql

sys.path.insert(0, str(Path(__file__).parent / "app"))
from config import DB_CONFIG  # noqa: E402

NOME = DB_CONFIG["dbname"]
SCRIPT = Path(__file__).parent / "sql" / "banco_completo.sql"


def main():
    print(f"Conectando ao PostgreSQL em {DB_CONFIG['host']}:{DB_CONFIG['port']} como {DB_CONFIG['user']}...")
    admin = dict(DB_CONFIG, dbname="postgres")
    try:
        con = psycopg2.connect(**admin)
    except psycopg2.OperationalError as e:
        print("\nNão consegui conectar. Confira se o PostgreSQL está rodando e se a senha em app/config.py está certa.")
        print(e)
        sys.exit(1)

    con.autocommit = True
    with con.cursor() as cur:
        cur.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = %s AND pid <> pg_backend_pid()", (NOME,))
        cur.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(NOME)))
        cur.execute(sql.SQL("CREATE DATABASE {} ENCODING 'UTF8' TEMPLATE template0").format(sql.Identifier(NOME)))
    con.close()
    print(f"Banco '{NOME}' criado.")

    con = psycopg2.connect(**DB_CONFIG)
    with con, con.cursor() as cur:
        cur.execute(SCRIPT.read_text(encoding="utf-8"))
        cur.execute("SELECT (SELECT COUNT(*) FROM ativo), (SELECT COUNT(*) FROM vulnerabilidade), "
                    "(SELECT COUNT(*) FROM ocorrencia)")
        ativos, vulns, ocorr = cur.fetchone()
    con.close()
    print(f"Estrutura e dados carregados: {ativos} ativos, {vulns} vulnerabilidades, {ocorr} ocorrências.")
    print("\nPronto! Agora rode:  streamlit run app/app.py")


if __name__ == "__main__":
    main()
