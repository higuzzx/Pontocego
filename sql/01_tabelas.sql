-- =====================================================================
-- Sistema de Gestão de Vulnerabilidades de Ativos (SGVA)
-- Banco de Dados II - Seminário II - Unimontes
-- Script 01: criação das tabelas
-- SGBD: PostgreSQL 14 ou superior
-- =====================================================================

-- Permite rodar o script de novo sem erro (apaga a estrutura anterior)
DROP TABLE IF EXISTS auditoria       CASCADE;
DROP TABLE IF EXISTS usuario         CASCADE;
DROP TABLE IF EXISTS ocorrencia      CASCADE;
DROP TABLE IF EXISTS varredura       CASCADE;
DROP TABLE IF EXISTS vulnerabilidade CASCADE;
DROP TABLE IF EXISTS ativo           CASCADE;
DROP TABLE IF EXISTS responsavel     CASCADE;
DROP TABLE IF EXISTS setor           CASCADE;

-- ---------------------------------------------------------------------
-- SETOR: setores/departamentos da organização onde ficam os ativos
-- ---------------------------------------------------------------------
CREATE TABLE setor (
    id_setor     SERIAL       PRIMARY KEY,
    nome         VARCHAR(60)  NOT NULL UNIQUE,
    localizacao  VARCHAR(80)
);

-- ---------------------------------------------------------------------
-- RESPONSAVEL: pessoas responsáveis pelos ativos e pelas varreduras
-- ---------------------------------------------------------------------
CREATE TABLE responsavel (
    id_responsavel  SERIAL        PRIMARY KEY,
    nome            VARCHAR(80)   NOT NULL,
    email           VARCHAR(100)  NOT NULL UNIQUE,
    cargo           VARCHAR(50),
    id_setor        INT           NOT NULL REFERENCES setor (id_setor)
);

-- ---------------------------------------------------------------------
-- ATIVO: equipamentos de TI (servidores, estações, switches...)
-- score_risco é calculado automaticamente por trigger
-- ---------------------------------------------------------------------
CREATE TABLE ativo (
    id_ativo             SERIAL        PRIMARY KEY,
    hostname             VARCHAR(60)   NOT NULL UNIQUE,
    ip                   INET          NOT NULL UNIQUE,
    tipo                 VARCHAR(20)   NOT NULL
                         CHECK (tipo IN ('Servidor', 'Estação', 'Switch', 'Roteador',
                                         'Firewall', 'Impressora', 'Access Point')),
    sistema_operacional  VARCHAR(60),
    criticidade          SMALLINT      NOT NULL CHECK (criticidade BETWEEN 1 AND 5),
    score_risco          NUMERIC(6,1)  NOT NULL DEFAULT 0,
    situacao             VARCHAR(10)   NOT NULL DEFAULT 'Ativo'
                         CHECK (situacao IN ('Ativo', 'Inativo')),
    data_cadastro        DATE          NOT NULL DEFAULT CURRENT_DATE,
    id_setor             INT           NOT NULL REFERENCES setor (id_setor),
    id_responsavel       INT           NOT NULL REFERENCES responsavel (id_responsavel)
);

-- ---------------------------------------------------------------------
-- VULNERABILIDADE: catálogo de vulnerabilidades conhecidas (CVE)
-- severidade é definida automaticamente por trigger a partir do CVSS
-- ---------------------------------------------------------------------
CREATE TABLE vulnerabilidade (
    id_vulnerabilidade  SERIAL        PRIMARY KEY,
    cve                 VARCHAR(20)   NOT NULL UNIQUE
                        CHECK (cve ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    titulo              VARCHAR(120)  NOT NULL,
    descricao           TEXT,
    cvss                NUMERIC(3,1)  NOT NULL CHECK (cvss BETWEEN 0 AND 10),
    severidade          VARCHAR(10)   NOT NULL,
    solucao             TEXT,
    data_publicacao     DATE
);

-- ---------------------------------------------------------------------
-- VARREDURA: cada execução de scanner (Nmap, OpenVAS, Nessus...)
-- ---------------------------------------------------------------------
CREATE TABLE varredura (
    id_varredura    SERIAL        PRIMARY KEY,
    data_varredura  DATE          NOT NULL DEFAULT CURRENT_DATE,
    ferramenta      VARCHAR(30)   NOT NULL,
    escopo          VARCHAR(80)   NOT NULL,
    observacao      TEXT,
    id_responsavel  INT           NOT NULL REFERENCES responsavel (id_responsavel)
);

-- ---------------------------------------------------------------------
-- OCORRENCIA: vulnerabilidade encontrada em um ativo numa varredura
-- prazo_correcao e data_correcao são preenchidos por trigger
-- ---------------------------------------------------------------------
CREATE TABLE ocorrencia (
    id_ocorrencia       SERIAL       PRIMARY KEY,
    id_ativo            INT          NOT NULL REFERENCES ativo (id_ativo) ON DELETE CASCADE,
    id_vulnerabilidade  INT          NOT NULL REFERENCES vulnerabilidade (id_vulnerabilidade),
    id_varredura        INT          NOT NULL REFERENCES varredura (id_varredura),
    data_deteccao       DATE         NOT NULL DEFAULT CURRENT_DATE,
    prazo_correcao      DATE         NOT NULL,
    status              VARCHAR(15)  NOT NULL DEFAULT 'Aberta'
                        CHECK (status IN ('Aberta', 'Em correção', 'Corrigida', 'Risco aceito')),
    data_correcao       DATE,
    observacao          TEXT,
    CHECK (data_correcao IS NULL OR data_correcao >= data_deteccao)
);

-- ---------------------------------------------------------------------
-- USUARIO: contas de acesso ao sistema (login da interface).
-- A senha nunca é guardada em texto: só o hash PBKDF2-SHA256 com salt.
-- ---------------------------------------------------------------------
CREATE TABLE usuario (
    id_usuario     SERIAL       PRIMARY KEY,
    nome           VARCHAR(80)  NOT NULL,
    login          VARCHAR(30)  NOT NULL UNIQUE CHECK (login = lower(login) AND login ~ '^[a-z0-9._-]{3,30}$'),
    senha_hash     VARCHAR(200) NOT NULL,
    perfil         VARCHAR(15)  NOT NULL DEFAULT 'Analista'
                   CHECK (perfil IN ('Administrador', 'Analista')),
    ativo          BOOLEAN      NOT NULL DEFAULT TRUE,
    data_cadastro  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ultimo_acesso  TIMESTAMP
);

-- ---------------------------------------------------------------------
-- AUDITORIA: log automático (por trigger) de toda alteração
-- em ativo, vulnerabilidade, ocorrencia e usuario.
-- usuario_app = login de quem estava usando o sistema (vem da sessão);
-- usuario_bd  = usuário do PostgreSQL que executou o comando.
-- ---------------------------------------------------------------------
CREATE TABLE auditoria (
    id_auditoria   BIGSERIAL    PRIMARY KEY,
    tabela         VARCHAR(30)  NOT NULL,
    operacao       VARCHAR(10)  NOT NULL,
    id_registro    INT          NOT NULL,
    dados_antigos  JSONB,
    dados_novos    JSONB,
    usuario_app    VARCHAR(30),
    usuario_bd     VARCHAR(60)  NOT NULL DEFAULT CURRENT_USER,
    data_hora      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);
