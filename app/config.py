"""Configuração de conexão com o PostgreSQL.

Troque a SENHA abaixo pela senha que você definiu ao instalar o PostgreSQL.
"""
import os

DB_CONFIG = {
    "host": os.getenv("PGHOST", "localhost"),
    "port": int(os.getenv("PGPORT", "5432")),
    "user": os.getenv("PGUSER", "postgres"),
    "password": os.getenv("PGPASSWORD", "postgres"),  # <- sua senha aqui
    "dbname": os.getenv("PGDATABASE", "gestao_vulnerabilidades"),
}
