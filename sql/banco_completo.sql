-- Arquivo único com os scripts 01 a 06 (estrutura + dados)


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


-- =====================================================================
-- Script 02: funções e triggers (automatizações do sistema)
-- =====================================================================

-- ---------------------------------------------------------------------
-- FUNÇÃO AUXILIAR: converte a nota CVSS (0 a 10) em severidade,
-- seguindo a escala oficial do CVSS v3
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_severidade_cvss(p_cvss NUMERIC)
RETURNS VARCHAR AS $$
BEGIN
    RETURN CASE
        WHEN p_cvss >= 9.0 THEN 'Crítica'
        WHEN p_cvss >= 7.0 THEN 'Alta'
        WHEN p_cvss >= 4.0 THEN 'Média'
        WHEN p_cvss >  0.0 THEN 'Baixa'
        ELSE 'Nenhuma'
    END;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- ---------------------------------------------------------------------
-- FUNÇÃO AUXILIAR: calcula o score de risco de um ativo
-- score = soma dos CVSS das ocorrências pendentes x (criticidade / 5)
-- Assim, um servidor crítico (5) pesa o dobro de um ativo de criticidade
-- média (2,5) com as mesmas falhas.
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_calcular_score(p_id_ativo INT)
RETURNS NUMERIC AS $$
DECLARE
    v_score NUMERIC;
BEGIN
    SELECT COALESCE(ROUND(SUM(v.cvss) * a.criticidade / 5.0, 1), 0)
      INTO v_score
      FROM ativo a
      LEFT JOIN ocorrencia o
             ON o.id_ativo = a.id_ativo
            AND o.status IN ('Aberta', 'Em correção')
      LEFT JOIN vulnerabilidade v
             ON v.id_vulnerabilidade = o.id_vulnerabilidade
     WHERE a.id_ativo = p_id_ativo
     GROUP BY a.criticidade;

    RETURN COALESCE(v_score, 0);
END;
$$ LANGUAGE plpgsql;


-- =====================================================================
-- TRIGGER 1: define a severidade automaticamente a partir do CVSS
-- Dispara antes de inserir uma vulnerabilidade ou alterar seu CVSS
-- =====================================================================
CREATE OR REPLACE FUNCTION trg_fn_definir_severidade()
RETURNS TRIGGER AS $$
BEGIN
    NEW.severidade := fn_severidade_cvss(NEW.cvss);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_definir_severidade
BEFORE INSERT OR UPDATE OF cvss ON vulnerabilidade
FOR EACH ROW EXECUTE FUNCTION trg_fn_definir_severidade();


-- =====================================================================
-- TRIGGER 2: regras automáticas da ocorrência
--  a) no cadastro, calcula o prazo de correção (SLA) pela severidade:
--     Crítica = 7 dias | Alta = 30 | Média = 90 | Baixa = 180
--  b) quando o status vira "Corrigida", preenche a data de correção
--  c) se a ocorrência for reaberta, limpa a data de correção
-- =====================================================================
CREATE OR REPLACE FUNCTION trg_fn_regras_ocorrencia()
RETURNS TRIGGER AS $$
DECLARE
    v_severidade VARCHAR;
BEGIN
    IF TG_OP = 'INSERT' AND NEW.prazo_correcao IS NULL THEN
        SELECT severidade INTO v_severidade
          FROM vulnerabilidade
         WHERE id_vulnerabilidade = NEW.id_vulnerabilidade;

        NEW.prazo_correcao := NEW.data_deteccao + CASE v_severidade
            WHEN 'Crítica' THEN 7
            WHEN 'Alta'    THEN 30
            WHEN 'Média'   THEN 90
            ELSE 180
        END;
    END IF;

    IF NEW.status = 'Corrigida' AND NEW.data_correcao IS NULL THEN
        NEW.data_correcao := CURRENT_DATE;
    ELSIF NEW.status IN ('Aberta', 'Em correção') THEN
        NEW.data_correcao := NULL;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_regras_ocorrencia
BEFORE INSERT OR UPDATE ON ocorrencia
FOR EACH ROW EXECUTE FUNCTION trg_fn_regras_ocorrencia();


-- =====================================================================
-- TRIGGER 3: recalcula o score de risco do ativo sempre que uma
-- ocorrência é cadastrada, alterada (ex.: corrigida) ou excluída
-- =====================================================================
CREATE OR REPLACE FUNCTION trg_fn_recalcular_risco()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP IN ('INSERT', 'UPDATE') THEN
        UPDATE ativo
           SET score_risco = fn_calcular_score(NEW.id_ativo)
         WHERE id_ativo = NEW.id_ativo;
    END IF;

    -- Na exclusão, ou se a ocorrência mudou de ativo, recalcula o antigo
    IF TG_OP = 'DELETE' OR (TG_OP = 'UPDATE' AND OLD.id_ativo <> NEW.id_ativo) THEN
        UPDATE ativo
           SET score_risco = fn_calcular_score(OLD.id_ativo)
         WHERE id_ativo = OLD.id_ativo;
    END IF;

    RETURN NULL;  -- trigger AFTER: o retorno é ignorado
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_recalcular_risco
AFTER INSERT OR UPDATE OR DELETE ON ocorrencia
FOR EACH ROW EXECUTE FUNCTION trg_fn_recalcular_risco();


-- =====================================================================
-- TRIGGER 4: se a criticidade de um ativo mudar, o score é refeito
-- =====================================================================
CREATE OR REPLACE FUNCTION trg_fn_criticidade_ativo()
RETURNS TRIGGER AS $$
BEGIN
    NEW.score_risco := COALESCE((
        SELECT ROUND(SUM(v.cvss) * NEW.criticidade / 5.0, 1)
          FROM ocorrencia o
          JOIN vulnerabilidade v ON v.id_vulnerabilidade = o.id_vulnerabilidade
         WHERE o.id_ativo = NEW.id_ativo
           AND o.status IN ('Aberta', 'Em correção')
    ), 0);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_criticidade_ativo
BEFORE UPDATE OF criticidade ON ativo
FOR EACH ROW EXECUTE FUNCTION trg_fn_criticidade_ativo();


-- =====================================================================
-- TRIGGER 5: auditoria. Grava em "auditoria" quem alterou o quê e quando,
-- guardando o registro antes e depois em formato JSON.
-- Usada nas tabelas ativo, vulnerabilidade, ocorrencia e usuario.
-- O parâmetro TG_ARGV[0] informa o nome da chave primária da tabela.
-- O login de quem usa a interface chega pela variável de sessão
-- app.usuario (a aplicação faz set_config antes de cada alteração).
-- =====================================================================
CREATE OR REPLACE FUNCTION trg_fn_auditoria()
RETURNS TRIGGER AS $$
DECLARE
    v_antigo JSONB;
    v_novo   JSONB;
BEGIN
    -- O hash da senha nunca vai para o log
    IF TG_OP <> 'INSERT' THEN v_antigo := to_jsonb(OLD) - 'senha_hash'; END IF;
    IF TG_OP <> 'DELETE' THEN v_novo   := to_jsonb(NEW) - 'senha_hash'; END IF;

    -- Não registra atualizações em que só mudou um campo automático:
    -- score_risco (consequência de uma ocorrência já auditada) ou
    -- ultimo_acesso (cada login do usuário). Troca de senha é registrada.
    IF TG_OP = 'UPDATE'
       AND (v_antigo - 'score_risco' - 'ultimo_acesso') = (v_novo - 'score_risco' - 'ultimo_acesso')
       AND (to_jsonb(OLD) ->> 'senha_hash') IS NOT DISTINCT FROM (to_jsonb(NEW) ->> 'senha_hash') THEN
        RETURN NULL;
    END IF;

    INSERT INTO auditoria (tabela, operacao, id_registro, dados_antigos, dados_novos, usuario_app)
    VALUES (TG_TABLE_NAME, TG_OP,
            (COALESCE(v_novo, v_antigo) ->> TG_ARGV[0])::INT,
            v_antigo, v_novo,
            NULLIF(current_setting('app.usuario', true), ''));

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_auditoria_ativo
AFTER INSERT OR UPDATE OR DELETE ON ativo
FOR EACH ROW EXECUTE FUNCTION trg_fn_auditoria('id_ativo');

CREATE TRIGGER trg_auditoria_vulnerabilidade
AFTER INSERT OR UPDATE OR DELETE ON vulnerabilidade
FOR EACH ROW EXECUTE FUNCTION trg_fn_auditoria('id_vulnerabilidade');

CREATE TRIGGER trg_auditoria_ocorrencia
AFTER INSERT OR UPDATE OR DELETE ON ocorrencia
FOR EACH ROW EXECUTE FUNCTION trg_fn_auditoria('id_ocorrencia');

CREATE TRIGGER trg_auditoria_usuario
AFTER INSERT OR UPDATE OR DELETE ON usuario
FOR EACH ROW EXECUTE FUNCTION trg_fn_auditoria('id_usuario');


-- =====================================================================
-- Script 03: stored procedures
-- Executadas com CALL nome_da_procedure(...)
-- =====================================================================

-- ---------------------------------------------------------------------
-- PROCEDURE 1: registrar uma ocorrência a partir do código CVE
--  - procura a vulnerabilidade pelo CVE (erro se não existir)
--  - se o ativo já tem essa CVE pendente, não duplica
--  - se a CVE já tinha sido corrigida antes no mesmo ativo,
--    registra marcando como REINCIDÊNCIA
-- Exemplo: CALL sp_registrar_ocorrencia(3, 'CVE-2021-44228', 8, NULL);
-- ---------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE sp_registrar_ocorrencia(
    p_id_ativo      INT,
    p_cve           VARCHAR,
    p_id_varredura  INT,
    INOUT p_resultado TEXT DEFAULT NULL
)
LANGUAGE plpgsql AS $$
DECLARE
    v_id_vuln       INT;
    v_id_existente  INT;
    v_data          DATE;
    v_reincidencia  BOOLEAN;
    v_novo_id       INT;
BEGIN
    SELECT id_vulnerabilidade INTO v_id_vuln
      FROM vulnerabilidade
     WHERE cve = UPPER(TRIM(p_cve));

    IF v_id_vuln IS NULL THEN
        RAISE EXCEPTION 'A vulnerabilidade % não está cadastrada.', p_cve;
    END IF;

    SELECT id_ocorrencia INTO v_id_existente
      FROM ocorrencia
     WHERE id_ativo = p_id_ativo
       AND id_vulnerabilidade = v_id_vuln
       AND status IN ('Aberta', 'Em correção');

    IF v_id_existente IS NOT NULL THEN
        p_resultado := format('Nada foi inserido: a ocorrência #%s já está pendente para este ativo.',
                              v_id_existente);
        RETURN;
    END IF;

    SELECT data_varredura INTO v_data
      FROM varredura WHERE id_varredura = p_id_varredura;

    IF v_data IS NULL THEN
        RAISE EXCEPTION 'Varredura % não encontrada.', p_id_varredura;
    END IF;

    SELECT EXISTS (
        SELECT 1 FROM ocorrencia
         WHERE id_ativo = p_id_ativo
           AND id_vulnerabilidade = v_id_vuln
           AND status = 'Corrigida'
    ) INTO v_reincidencia;

    INSERT INTO ocorrencia (id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, observacao)
    VALUES (p_id_ativo, v_id_vuln, p_id_varredura, v_data,
            CASE WHEN v_reincidencia
                 THEN 'REINCIDÊNCIA: falha já havia sido corrigida antes neste ativo.' END)
    RETURNING id_ocorrencia INTO v_novo_id;

    p_resultado := format('Ocorrência #%s registrada%s.', v_novo_id,
                          CASE WHEN v_reincidencia THEN ' (reincidência)' ELSE '' END);
END;
$$;


-- ---------------------------------------------------------------------
-- PROCEDURE 2: fechar (marcar como corrigida) uma ocorrência
-- Devolve em p_dias quantos dias a correção levou e informa
-- se foi feita dentro do prazo.
-- Exemplo: CALL sp_fechar_ocorrencia(15, 'Patch aplicado', NULL, NULL);
-- ---------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE sp_fechar_ocorrencia(
    p_id_ocorrencia  INT,
    p_observacao     TEXT,
    INOUT p_dias      INT  DEFAULT NULL,
    INOUT p_resultado TEXT DEFAULT NULL
)
LANGUAGE plpgsql AS $$
DECLARE
    v_ocorrencia ocorrencia%ROWTYPE;
BEGIN
    SELECT * INTO v_ocorrencia
      FROM ocorrencia
     WHERE id_ocorrencia = p_id_ocorrencia;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Ocorrência % não encontrada.', p_id_ocorrencia;
    END IF;

    IF v_ocorrencia.status = 'Corrigida' THEN
        RAISE EXCEPTION 'A ocorrência % já estava corrigida.', p_id_ocorrencia;
    END IF;

    -- A trigger trg_regras_ocorrencia preenche a data_correcao
    -- e a trg_recalcular_risco atualiza o score do ativo
    UPDATE ocorrencia
       SET status = 'Corrigida',
           observacao = COALESCE(NULLIF(TRIM(p_observacao), ''), observacao)
     WHERE id_ocorrencia = p_id_ocorrencia;

    p_dias := CURRENT_DATE - v_ocorrencia.data_deteccao;
    p_resultado := CASE
        WHEN CURRENT_DATE <= v_ocorrencia.prazo_correcao
            THEN format('Corrigida em %s dia(s), dentro do prazo.', p_dias)
        ELSE format('Corrigida em %s dia(s), %s dia(s) após o prazo.',
                    p_dias, CURRENT_DATE - v_ocorrencia.prazo_correcao)
    END;
END;
$$;


-- =====================================================================
-- Script 04: views (visões)
-- Consultas prontas que juntam várias tabelas e facilitam relatórios
-- =====================================================================

-- ---------------------------------------------------------------------
-- VIEW 1: ocorrências pendentes com todos os detalhes e situação do prazo
-- Junta as 6 tabelas principais. É a base da tela de ocorrências.
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW vw_ocorrencias_pendentes AS
SELECT o.id_ocorrencia,
       a.hostname,
       a.ip,
       s.nome                              AS setor,
       r.nome                              AS responsavel,
       v.cve,
       v.titulo,
       v.cvss,
       v.severidade,
       o.status,
       o.data_deteccao,
       o.prazo_correcao,
       o.prazo_correcao - CURRENT_DATE     AS dias_restantes,
       CASE
           WHEN o.prazo_correcao < CURRENT_DATE      THEN 'Vencida'
           WHEN o.prazo_correcao <= CURRENT_DATE + 7 THEN 'Vence em até 7 dias'
           ELSE 'No prazo'
       END                                 AS situacao_prazo,
       vr.ferramenta,
       o.observacao,
       o.id_ativo
  FROM ocorrencia o
  JOIN ativo           a  ON a.id_ativo = o.id_ativo
  JOIN setor           s  ON s.id_setor = a.id_setor
  JOIN responsavel     r  ON r.id_responsavel = a.id_responsavel
  JOIN vulnerabilidade v  ON v.id_vulnerabilidade = o.id_vulnerabilidade
  JOIN varredura       vr ON vr.id_varredura = o.id_varredura
 WHERE o.status IN ('Aberta', 'Em correção');


-- ---------------------------------------------------------------------
-- VIEW 2: ocorrências com o prazo de correção vencido
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW vw_ocorrencias_vencidas AS
SELECT id_ocorrencia, hostname, setor, responsavel, cve, titulo,
       severidade, status, prazo_correcao,
       CURRENT_DATE - prazo_correcao AS dias_de_atraso
  FROM vw_ocorrencias_pendentes
 WHERE prazo_correcao < CURRENT_DATE;


-- ---------------------------------------------------------------------
-- VIEW 3: ranking dos ativos mais expostos (maior score de risco)
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW vw_ranking_ativos AS
SELECT RANK() OVER (ORDER BY a.score_risco DESC)             AS posicao,
       a.id_ativo,
       a.hostname,
       a.ip,
       a.tipo,
       a.sistema_operacional,
       s.nome                                                AS setor,
       r.nome                                                AS responsavel,
       a.criticidade,
       a.score_risco,
       COUNT(o.id_ocorrencia)                                AS pendentes,
       COUNT(o.id_ocorrencia) FILTER (WHERE v.severidade = 'Crítica') AS criticas,
       COUNT(o.id_ocorrencia) FILTER (WHERE o.prazo_correcao < CURRENT_DATE) AS vencidas
  FROM ativo a
  JOIN setor s       ON s.id_setor = a.id_setor
  JOIN responsavel r ON r.id_responsavel = a.id_responsavel
  LEFT JOIN ocorrencia o
         ON o.id_ativo = a.id_ativo
        AND o.status IN ('Aberta', 'Em correção')
  LEFT JOIN vulnerabilidade v ON v.id_vulnerabilidade = o.id_vulnerabilidade
 WHERE a.situacao = 'Ativo'
 GROUP BY a.id_ativo, s.nome, r.nome;


-- ---------------------------------------------------------------------
-- VIEW 4: resumo por setor (quantidade de pendências por severidade)
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW vw_resumo_setor AS
SELECT s.nome                                                          AS setor,
       COUNT(DISTINCT a.id_ativo)                                      AS ativos,
       COUNT(o.id_ocorrencia) FILTER (WHERE v.severidade = 'Crítica')  AS criticas,
       COUNT(o.id_ocorrencia) FILTER (WHERE v.severidade = 'Alta')     AS altas,
       COUNT(o.id_ocorrencia) FILTER (WHERE v.severidade = 'Média')    AS medias,
       COUNT(o.id_ocorrencia) FILTER (WHERE v.severidade = 'Baixa')    AS baixas,
       COUNT(o.id_ocorrencia)                                          AS total_pendentes,
       COUNT(o.id_ocorrencia) FILTER (WHERE o.prazo_correcao < CURRENT_DATE) AS vencidas
  FROM setor s
  LEFT JOIN ativo a      ON a.id_setor = s.id_setor
  LEFT JOIN ocorrencia o ON o.id_ativo = a.id_ativo
                        AND o.status IN ('Aberta', 'Em correção')
  LEFT JOIN vulnerabilidade v ON v.id_vulnerabilidade = o.id_vulnerabilidade
 GROUP BY s.nome;


-- ---------------------------------------------------------------------
-- VIEW 5: tempo médio de correção (MTTR) por severidade
-- e percentual de correções feitas dentro do prazo
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW vw_tempo_medio_correcao AS
SELECT v.severidade,
       COUNT(*)                                                   AS corrigidas,
       ROUND(AVG(o.data_correcao - o.data_deteccao), 1)           AS media_dias,
       MIN(o.data_correcao - o.data_deteccao)                     AS menor_dias,
       MAX(o.data_correcao - o.data_deteccao)                     AS maior_dias,
       ROUND(100.0 * COUNT(*) FILTER (WHERE o.data_correcao <= o.prazo_correcao)
             / COUNT(*), 1)                                       AS pct_no_prazo
  FROM ocorrencia o
  JOIN vulnerabilidade v ON v.id_vulnerabilidade = o.id_vulnerabilidade
 WHERE o.status = 'Corrigida'
 GROUP BY v.severidade;


-- ---------------------------------------------------------------------
-- VIEW 6: vulnerabilidades mais frequentes no parque
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW vw_vulnerabilidades_frequentes AS
SELECT v.cve,
       v.titulo,
       v.cvss,
       v.severidade,
       COUNT(o.id_ocorrencia)                                               AS total_deteccoes,
       COUNT(o.id_ocorrencia) FILTER (WHERE o.status IN ('Aberta', 'Em correção')) AS ativos_afetados_hoje
  FROM vulnerabilidade v
  LEFT JOIN ocorrencia o ON o.id_vulnerabilidade = v.id_vulnerabilidade
 GROUP BY v.id_vulnerabilidade;


-- =====================================================================
-- Script 05: índices
-- Obs.: o PostgreSQL já cria índice automaticamente para toda PRIMARY KEY
-- e UNIQUE (ex.: vulnerabilidade.cve, ativo.ip, ativo.hostname).
-- Os índices abaixo aceleram as consultas mais usadas pelo sistema.
-- =====================================================================

-- Chaves estrangeiras de ocorrencia: usadas em todos os JOINs das views
CREATE INDEX idx_ocorrencia_ativo  ON ocorrencia (id_ativo);
CREATE INDEX idx_ocorrencia_vuln   ON ocorrencia (id_vulnerabilidade);
CREATE INDEX idx_ocorrencia_varred ON ocorrencia (id_varredura);

-- Filtro por status (tela de ocorrências, relatórios)
CREATE INDEX idx_ocorrencia_status ON ocorrencia (status);

-- ÍNDICE PARCIAL: indexa só as ocorrências pendentes, ordenadas por prazo.
-- Fica bem menor que um índice comum, porque as corrigidas (a maioria
-- com o passar do tempo) ficam de fora. Acelera a view de vencidas.
CREATE INDEX idx_ocorrencia_pendente_prazo
    ON ocorrencia (prazo_correcao)
 WHERE status IN ('Aberta', 'Em correção');

-- ÍNDICE ÚNICO PARCIAL (regra de integridade):
-- impede que o mesmo ativo tenha a mesma CVE pendente duas vezes,
-- mas permite registrar de novo depois de corrigida (reincidência).
CREATE UNIQUE INDEX uq_ocorrencia_pendente
    ON ocorrencia (id_ativo, id_vulnerabilidade)
 WHERE status IN ('Aberta', 'Em correção');

-- Ativos: filtro por setor e ordenação pelo ranking de risco
CREATE INDEX idx_ativo_setor ON ativo (id_setor);
CREATE INDEX idx_ativo_score ON ativo (score_risco DESC);

-- Vulnerabilidades: filtro por severidade
CREATE INDEX idx_vulnerabilidade_severidade ON vulnerabilidade (severidade);

-- Auditoria: consulta sempre os registros mais recentes primeiro
CREATE INDEX idx_auditoria_data   ON auditoria (data_hora DESC);
CREATE INDEX idx_auditoria_tabela ON auditoria (tabela, id_registro);


-- =====================================================================
-- Script 06: dados de exemplo (FICTÍCIOS) para testes e demonstração
-- As CVEs são reais (catálogo público do NVD); ativos, pessoas e
-- ocorrências são inventados.
-- =====================================================================

INSERT INTO setor (nome, localizacao) VALUES
    ('DTI - Infraestrutura', 'Prédio da Reitoria, sala 12'),
    ('DTI - Sistemas', 'Prédio da Reitoria, sala 14'),
    ('Reitoria', 'Prédio da Reitoria, 2º andar'),
    ('Secretaria Acadêmica', 'Prédio Central, térreo'),
    ('Financeiro', 'Prédio da Reitoria, 1º andar'),
    ('Recursos Humanos', 'Prédio da Reitoria, 1º andar'),
    ('Biblioteca Central', 'Prédio da Biblioteca'),
    ('Laboratórios CCET', 'Prédio 6, bloco B');

INSERT INTO responsavel (nome, email, cargo, id_setor) VALUES
    ('Rafael Antunes', 'rafael.antunes@sgva.exemplo.br', 'Analista de Redes', (SELECT id_setor FROM setor WHERE nome = 'DTI - Infraestrutura')),
    ('Camila Duarte', 'camila.duarte@sgva.exemplo.br', 'Analista de Segurança da Informação', (SELECT id_setor FROM setor WHERE nome = 'DTI - Infraestrutura')),
    ('Bruno Teixeira', 'bruno.teixeira@sgva.exemplo.br', 'Técnico de Suporte', (SELECT id_setor FROM setor WHERE nome = 'DTI - Infraestrutura')),
    ('Eduardo Fonseca', 'eduardo.fonseca@sgva.exemplo.br', 'Técnico de Suporte', (SELECT id_setor FROM setor WHERE nome = 'DTI - Infraestrutura')),
    ('Larissa Prates', 'larissa.prates@sgva.exemplo.br', 'Analista de Sistemas', (SELECT id_setor FROM setor WHERE nome = 'DTI - Sistemas')),
    ('Marcos Vieira', 'marcos.vieira@sgva.exemplo.br', 'Administrador de Banco de Dados', (SELECT id_setor FROM setor WHERE nome = 'DTI - Sistemas')),
    ('Patrícia Lopes', 'patricia.lopes@sgva.exemplo.br', 'Técnica de Laboratório', (SELECT id_setor FROM setor WHERE nome = 'Laboratórios CCET'));

-- A severidade NÃO é informada: a trigger trg_definir_severidade calcula pelo CVSS
INSERT INTO vulnerabilidade (cve, titulo, descricao, cvss, solucao, data_publicacao) VALUES
    ('CVE-2021-44228', 'Log4Shell: execução remota de código no Apache Log4j',
     'Falha na biblioteca Log4j 2 permite que um atacante execute código remotamente enviando uma string JNDI maliciosa que é registrada em log.',
     10.0, 'Atualizar o Log4j para 2.17.1 ou superior.', '2021-12-10'),
    ('CVE-2017-0144', 'EternalBlue: execução remota de código no SMBv1',
     'Falha no SMBv1 do Windows explorada pelo ransomware WannaCry.',
     8.1, 'Aplicar o boletim MS17-010 e desativar o SMBv1.', '2017-03-17'),
    ('CVE-2019-0708', 'BlueKeep: execução remota de código no RDP',
     'Falha no Remote Desktop Services permite execução de código sem autenticação.',
     9.8, 'Aplicar a atualização de maio/2019 e ativar NLA no RDP.', '2019-05-16'),
    ('CVE-2021-34527', 'PrintNightmare: execução de código no Spooler de Impressão',
     'Falha no serviço Print Spooler do Windows permite execução remota de código com privilégios de SYSTEM.',
     8.8, 'Aplicar a atualização KB5004945 ou desativar o Spooler onde não for necessário.', '2021-07-02'),
    ('CVE-2020-1472', 'Zerologon: elevação de privilégio no Netlogon',
     'Falha criptográfica no protocolo Netlogon permite assumir o controlador de domínio.',
     10.0, 'Aplicar a atualização de agosto/2020 e ativar o modo de imposição do Netlogon.', '2020-08-17'),
    ('CVE-2020-0796', 'SMBGhost: execução remota de código no SMBv3',
     'Falha na compressão do SMBv3 em versões 1903/1909 do Windows 10.',
     10.0, 'Aplicar a atualização KB4551762 ou desativar a compressão SMBv3.', '2020-03-12'),
    ('CVE-2014-0160', 'Heartbleed: vazamento de memória no OpenSSL',
     'Falha na extensão heartbeat do OpenSSL permite ler a memória do servidor, incluindo chaves privadas.',
     7.5, 'Atualizar o OpenSSL para 1.0.1g ou superior e trocar os certificados.', '2014-04-07'),
    ('CVE-2022-0847', 'Dirty Pipe: elevação de privilégio no kernel Linux',
     'Falha no kernel Linux permite que usuário comum sobrescreva arquivos somente leitura.',
     7.8, 'Atualizar o kernel para 5.16.11, 5.15.25, 5.10.102 ou superior.', '2022-03-10'),
    ('CVE-2021-4034', 'PwnKit: elevação de privilégio no pkexec (polkit)',
     'Falha no pkexec permite que qualquer usuário local obtenha root.',
     7.8, 'Atualizar o pacote polkit.', '2022-01-28'),
    ('CVE-2024-6387', 'regreSSHion: execução remota de código no OpenSSH',
     'Condição de corrida no tratamento de sinais do sshd permite execução de código como root.',
     8.1, 'Atualizar o OpenSSH para 9.8p1 ou superior.', '2024-07-01'),
    ('CVE-2024-3094', 'Backdoor na biblioteca xz/liblzma',
     'Versões 5.6.0 e 5.6.1 do xz continham código malicioso que compromete o sshd.',
     10.0, 'Voltar o xz-utils para versão não afetada (5.4.x).', '2024-03-29'),
    ('CVE-2021-41773', 'Path traversal no Apache HTTP Server 2.4.49',
     'Permite ler arquivos fora da raiz do site e, em algumas configurações, executar código.',
     7.5, 'Atualizar o Apache para 2.4.51 ou superior.', '2021-10-05'),
    ('CVE-2023-44487', 'HTTP/2 Rapid Reset: negação de serviço',
     'Abuso do cancelamento de streams do HTTP/2 permite derrubar servidores web.',
     7.5, 'Atualizar o servidor web e limitar resets de stream por conexão.', '2023-10-10'),
    ('CVE-2018-0171', 'Cisco Smart Install: execução remota de código',
     'Falha no recurso Smart Install do Cisco IOS/IOS XE permite executar código no switch.',
     9.8, 'Desativar o Smart Install (no vstack) e atualizar o IOS.', '2018-03-28'),
    ('CVE-2023-20198', 'Cisco IOS XE: elevação de privilégio na interface web',
     'Permite criar conta de administrador pela interface web sem autenticação.',
     10.0, 'Desativar o ip http server e atualizar o IOS XE.', '2023-10-16'),
    ('CVE-2016-2183', 'SWEET32: cifra 3DES fraca em TLS',
     'Uso de cifras de bloco de 64 bits permite recuperar dados em sessões longas.',
     7.5, 'Desativar cifras 3DES/DES nos serviços TLS.', '2016-09-01'),
    ('CVE-2023-48795', 'Terrapin: ataque de truncamento no SSH',
     'Permite remover mensagens no início da sessão SSH e enfraquecer a segurança.',
     5.9, 'Atualizar o servidor SSH e desativar ChaCha20-Poly1305 e modos EtM vulneráveis.', '2023-12-18'),
    ('CVE-2014-3566', 'POODLE: vulnerabilidade no SSL 3.0',
     'Ataque de padding oracle permite decifrar dados em conexões SSL 3.0.',
     3.4, 'Desativar o SSL 3.0.', '2014-10-15'),
    ('CVE-2017-15906', 'OpenSSH: criação de arquivos no modo somente leitura do SFTP',
     'O sftp-server permite criar arquivos vazios mesmo em modo somente leitura.',
     5.3, 'Atualizar o OpenSSH para 7.6 ou superior.', '2017-10-26'),
    ('CVE-2023-38408', 'OpenSSH: execução remota pelo ssh-agent (PKCS#11)',
     'Agente SSH encaminhado pode ser usado para carregar bibliotecas e executar código.',
     9.8, 'Atualizar o OpenSSH para 9.3p2 ou superior.', '2023-07-20'),
    ('CVE-2022-26134', 'Confluence: injeção OGNL com execução remota de código',
     'Permite que atacante não autenticado execute código no Confluence Server.',
     9.8, 'Atualizar o Confluence para versão corrigida.', '2022-06-03'),
    ('CVE-2021-26855', 'ProxyLogon: falsificação de requisição no Exchange',
     'Falha SSRF no Exchange Server usada em cadeia para invadir servidores de e-mail.',
     9.8, 'Aplicar as atualizações de março/2021 do Exchange.', '2021-03-03'),
    ('CVE-2022-22965', 'Spring4Shell: execução remota de código no Spring Framework',
     'Falha de data binding em aplicações Spring MVC rodando no Tomcat com JDK 9+.',
     9.8, 'Atualizar o Spring Framework para 5.3.18 ou 5.2.20.', '2022-04-01'),
    ('CVE-2023-4863', 'Estouro de buffer no libwebp (navegadores)',
     'Imagem WebP maliciosa pode executar código no navegador.',
     8.8, 'Atualizar Chrome, Edge e Firefox.', '2023-09-12'),
    ('CVE-2023-36884', 'Execução remota de código via documentos do Office',
     'Documento Office manipulado pode executar código ao ser aberto.',
     8.8, 'Aplicar as atualizações do Office e do Windows de agosto/2023.', '2023-07-11'),
    ('CVE-2024-21413', 'MonikerLink: execução remota de código no Outlook',
     'Link manipulado em e-mail pode vazar credenciais NTLM e executar código.',
     9.8, 'Aplicar a atualização de fevereiro/2024 do Office.', '2024-02-13'),
    ('CVE-2020-1938', 'Ghostcat: leitura de arquivos pelo conector AJP do Tomcat',
     'O conector AJP permite ler arquivos da aplicação e, em alguns casos, executar código.',
     9.8, 'Desativar o conector AJP ou atualizar o Tomcat.', '2020-02-24'),
    ('CVE-2019-0211', 'Apache HTTP Server: elevação de privilégio local',
     'Processo filho com poucos privilégios pode executar código como root.',
     7.8, 'Atualizar o Apache para 2.4.39 ou superior.', '2019-04-08'),
    ('CVE-2015-4000', 'Logjam: rebaixamento do Diffie-Hellman em TLS',
     'Permite forçar o uso de chaves DH de exportação fracas.',
     3.7, 'Desativar cifras DHE_EXPORT e usar grupos DH de 2048 bits.', '2015-05-21'),
    ('CVE-2021-3449', 'OpenSSL: negação de serviço na renegociação TLS',
     'Mensagem de renegociação manipulada derruba o servidor TLS.',
     5.9, 'Atualizar o OpenSSL para 1.1.1k ou superior.', '2021-03-25'),
    ('CVE-2018-15473', 'OpenSSH: enumeração de usuários',
     'Permite descobrir quais nomes de usuário existem no servidor SSH.',
     5.3, 'Atualizar o OpenSSH para 7.8 ou superior.', '2018-08-17');

INSERT INTO ativo (hostname, ip, tipo, sistema_operacional, criticidade, data_cadastro, id_setor, id_responsavel) VALUES
    ('srv-ad01', '10.10.1.10', 'Servidor', 'Windows Server 2016', 5, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'DTI - Infraestrutura'), (SELECT id_responsavel FROM responsavel WHERE email = 'rafael.antunes@sgva.exemplo.br')),
    ('srv-ad02', '10.10.1.11', 'Servidor', 'Windows Server 2016', 5, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'DTI - Infraestrutura'), (SELECT id_responsavel FROM responsavel WHERE email = 'rafael.antunes@sgva.exemplo.br')),
    ('srv-arquivos01', '10.10.1.20', 'Servidor', 'Windows Server 2008 R2', 4, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'DTI - Infraestrutura'), (SELECT id_responsavel FROM responsavel WHERE email = 'bruno.teixeira@sgva.exemplo.br')),
    ('srv-email01', '10.10.1.30', 'Servidor', 'Windows Server 2016 (Exchange 2016)', 4, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'DTI - Infraestrutura'), (SELECT id_responsavel FROM responsavel WHERE email = 'rafael.antunes@sgva.exemplo.br')),
    ('srv-impressao01', '10.10.1.40', 'Servidor', 'Windows Server 2019', 2, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'DTI - Infraestrutura'), (SELECT id_responsavel FROM responsavel WHERE email = 'bruno.teixeira@sgva.exemplo.br')),
    ('srv-backup01', '10.10.1.50', 'Servidor', 'Debian 12', 4, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'DTI - Infraestrutura'), (SELECT id_responsavel FROM responsavel WHERE email = 'camila.duarte@sgva.exemplo.br')),
    ('srv-monitor01', '10.10.1.60', 'Servidor', 'CentOS 6 (Zabbix)', 3, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'DTI - Infraestrutura'), (SELECT id_responsavel FROM responsavel WHERE email = 'camila.duarte@sgva.exemplo.br')),
    ('srv-portal01', '10.10.2.10', 'Servidor', 'Ubuntu 20.04 (Apache 2.4.49)', 5, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'DTI - Sistemas'), (SELECT id_responsavel FROM responsavel WHERE email = 'larissa.prates@sgva.exemplo.br')),
    ('srv-portal02', '10.10.2.11', 'Servidor', 'Ubuntu 22.04 (Nginx)', 4, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'DTI - Sistemas'), (SELECT id_responsavel FROM responsavel WHERE email = 'larissa.prates@sgva.exemplo.br')),
    ('srv-academico01', '10.10.2.20', 'Servidor', 'CentOS 7 (Tomcat 9)', 5, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'DTI - Sistemas'), (SELECT id_responsavel FROM responsavel WHERE email = 'larissa.prates@sgva.exemplo.br')),
    ('srv-bd01', '10.10.2.30', 'Servidor', 'Debian 11 (PostgreSQL 13)', 5, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'DTI - Sistemas'), (SELECT id_responsavel FROM responsavel WHERE email = 'marcos.vieira@sgva.exemplo.br')),
    ('srv-wiki01', '10.10.2.40', 'Servidor', 'Ubuntu 18.04 (Confluence 7)', 2, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'DTI - Sistemas'), (SELECT id_responsavel FROM responsavel WHERE email = 'larissa.prates@sgva.exemplo.br')),
    ('fw-borda01', '10.10.0.1', 'Firewall', 'pfSense 2.6', 5, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'DTI - Infraestrutura'), (SELECT id_responsavel FROM responsavel WHERE email = 'camila.duarte@sgva.exemplo.br')),
    ('rt-borda01', '10.10.0.2', 'Roteador', 'Cisco IOS XE 17.3', 5, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'DTI - Infraestrutura'), (SELECT id_responsavel FROM responsavel WHERE email = 'rafael.antunes@sgva.exemplo.br')),
    ('sw-core01', '10.10.0.3', 'Switch', 'Cisco IOS XE 16.12', 5, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'DTI - Infraestrutura'), (SELECT id_responsavel FROM responsavel WHERE email = 'rafael.antunes@sgva.exemplo.br')),
    ('sw-reitoria01', '10.10.10.2', 'Switch', 'Cisco IOS 15.2', 3, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'Reitoria'), (SELECT id_responsavel FROM responsavel WHERE email = 'rafael.antunes@sgva.exemplo.br')),
    ('sw-biblioteca01', '10.10.20.2', 'Switch', 'Cisco IOS 15.2', 2, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'Biblioteca Central'), (SELECT id_responsavel FROM responsavel WHERE email = 'rafael.antunes@sgva.exemplo.br')),
    ('sw-lab-ccet01', '10.10.30.2', 'Switch', 'Cisco IOS 15.0', 2, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'Laboratórios CCET'), (SELECT id_responsavel FROM responsavel WHERE email = 'rafael.antunes@sgva.exemplo.br')),
    ('ap-biblioteca01', '10.10.20.5', 'Access Point', 'Ubiquiti UniFi AC Lite', 1, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'Biblioteca Central'), (SELECT id_responsavel FROM responsavel WHERE email = 'bruno.teixeira@sgva.exemplo.br')),
    ('est-reitoria-01', '10.10.10.21', 'Estação', 'Windows 10 22H2', 3, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'Reitoria'), (SELECT id_responsavel FROM responsavel WHERE email = 'eduardo.fonseca@sgva.exemplo.br')),
    ('est-reitoria-02', '10.10.10.22', 'Estação', 'Windows 10 22H2', 3, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'Reitoria'), (SELECT id_responsavel FROM responsavel WHERE email = 'eduardo.fonseca@sgva.exemplo.br')),
    ('est-secacad-01', '10.10.11.21', 'Estação', 'Windows 10 1909', 3, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'Secretaria Acadêmica'), (SELECT id_responsavel FROM responsavel WHERE email = 'eduardo.fonseca@sgva.exemplo.br')),
    ('est-secacad-02', '10.10.11.22', 'Estação', 'Windows 11 23H2', 3, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'Secretaria Acadêmica'), (SELECT id_responsavel FROM responsavel WHERE email = 'eduardo.fonseca@sgva.exemplo.br')),
    ('est-financeiro-01', '10.10.12.21', 'Estação', 'Windows 10 22H2', 4, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'Financeiro'), (SELECT id_responsavel FROM responsavel WHERE email = 'eduardo.fonseca@sgva.exemplo.br')),
    ('est-financeiro-02', '10.10.12.22', 'Estação', 'Windows 10 1909', 4, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'Financeiro'), (SELECT id_responsavel FROM responsavel WHERE email = 'eduardo.fonseca@sgva.exemplo.br')),
    ('est-rh-01', '10.10.13.21', 'Estação', 'Windows 11 23H2', 3, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'Recursos Humanos'), (SELECT id_responsavel FROM responsavel WHERE email = 'eduardo.fonseca@sgva.exemplo.br')),
    ('est-biblioteca-01', '10.10.20.21', 'Estação', 'Windows 10 22H2', 1, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'Biblioteca Central'), (SELECT id_responsavel FROM responsavel WHERE email = 'eduardo.fonseca@sgva.exemplo.br')),
    ('lab-ccet-01', '10.10.30.21', 'Estação', 'Windows 10 22H2', 1, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'Laboratórios CCET'), (SELECT id_responsavel FROM responsavel WHERE email = 'patricia.lopes@sgva.exemplo.br')),
    ('lab-ccet-02', '10.10.30.22', 'Estação', 'Windows 7 SP1', 1, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'Laboratórios CCET'), (SELECT id_responsavel FROM responsavel WHERE email = 'patricia.lopes@sgva.exemplo.br')),
    ('lab-ccet-03', '10.10.30.23', 'Estação', 'Ubuntu 22.04 Desktop', 1, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'Laboratórios CCET'), (SELECT id_responsavel FROM responsavel WHERE email = 'patricia.lopes@sgva.exemplo.br')),
    ('imp-secacad-01', '10.10.11.50', 'Impressora', 'HP LaserJet M404 (firmware 2019)', 1, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'Secretaria Acadêmica'), (SELECT id_responsavel FROM responsavel WHERE email = 'bruno.teixeira@sgva.exemplo.br')),
    ('imp-financeiro-01', '10.10.12.50', 'Impressora', 'HP LaserJet M404 (firmware 2019)', 1, '2026-07-06', (SELECT id_setor FROM setor WHERE nome = 'Financeiro'), (SELECT id_responsavel FROM responsavel WHERE email = 'bruno.teixeira@sgva.exemplo.br'));

INSERT INTO varredura (data_varredura, ferramenta, escopo, observacao, id_responsavel) VALUES
    ('2026-07-06', 'Nmap', '10.10.0.0/16', 'Varredura de descoberta para levantar o inventário de ativos.', (SELECT id_responsavel FROM responsavel WHERE email = 'rafael.antunes@sgva.exemplo.br')),
    ('2026-07-20', 'OpenVAS', '10.10.0.0/16', 'Primeira varredura completa de vulnerabilidades.', (SELECT id_responsavel FROM responsavel WHERE email = 'camila.duarte@sgva.exemplo.br')),
    ('2026-08-17', 'OpenVAS', '10.10.0.0/16', 'Varredura mensal.', (SELECT id_responsavel FROM responsavel WHERE email = 'camila.duarte@sgva.exemplo.br')),
    ('2026-09-14', 'Nessus Essentials', '10.10.1.0/24, 10.10.2.0/24', 'Varredura autenticada só nos servidores.', (SELECT id_responsavel FROM responsavel WHERE email = 'camila.duarte@sgva.exemplo.br')),
    ('2026-10-05', 'OpenVAS', '10.10.0.0/16', 'Varredura mensal.', (SELECT id_responsavel FROM responsavel WHERE email = 'camila.duarte@sgva.exemplo.br')),
    ('2026-10-26', 'Nmap (scripts NSE vulners)', '10.10.0.0/24', 'Checagem dos equipamentos de rede.', (SELECT id_responsavel FROM responsavel WHERE email = 'rafael.antunes@sgva.exemplo.br')),
    ('2026-11-09', 'OpenVAS', '10.10.0.0/16', 'Varredura mensal.', (SELECT id_responsavel FROM responsavel WHERE email = 'camila.duarte@sgva.exemplo.br')),
    ('2026-11-16', 'OpenVAS', '10.10.0.0/16', 'Varredura de verificação após correções.', (SELECT id_responsavel FROM responsavel WHERE email = 'camila.duarte@sgva.exemplo.br'));

-- O prazo_correcao NÃO é informado: a trigger trg_regras_ocorrencia calcula pela severidade.
-- A cada linha inserida, a trigger trg_recalcular_risco atualiza o score do ativo.
INSERT INTO ocorrencia (id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, status, data_correcao, observacao)
SELECT a.id_ativo, v.id_vulnerabilidade, vr.id_varredura, d.data_deteccao::date, d.status, d.data_correcao::date, d.observacao
  FROM (VALUES
    ('ap-biblioteca01', 'CVE-2015-4000', '2026-07-20', 'Corrigida', '2026-11-05', NULL),
    ('est-biblioteca-01', 'CVE-2021-34527', '2026-07-20', 'Corrigida', '2026-09-10', NULL),
    ('est-biblioteca-01', 'CVE-2023-36884', '2026-07-20', 'Corrigida', '2026-08-14', NULL),
    ('est-biblioteca-01', 'CVE-2024-21413', '2026-07-20', 'Corrigida', '2026-08-29', NULL),
    ('est-financeiro-01', 'CVE-2021-34527', '2026-07-20', 'Corrigida', '2026-07-21', NULL),
    ('est-financeiro-01', 'CVE-2023-4863', '2026-07-20', 'Corrigida', '2026-07-24', NULL),
    ('est-financeiro-02', 'CVE-2021-34527', '2026-07-20', 'Corrigida', '2026-09-24', NULL),
    ('est-financeiro-02', 'CVE-2023-36884', '2026-07-20', 'Corrigida', '2026-08-16', NULL),
    ('est-financeiro-02', 'CVE-2023-4863', '2026-07-20', 'Aberta', NULL, NULL),
    ('est-reitoria-01', 'CVE-2023-36884', '2026-07-20', 'Corrigida', '2026-09-22', NULL),
    ('est-reitoria-01', 'CVE-2023-4863', '2026-07-20', 'Corrigida', '2026-08-22', NULL),
    ('est-reitoria-01', 'CVE-2024-21413', '2026-07-20', 'Corrigida', '2026-08-03', NULL),
    ('est-reitoria-02', 'CVE-2021-34527', '2026-07-20', 'Em correção', NULL, NULL),
    ('est-reitoria-02', 'CVE-2024-21413', '2026-07-20', 'Corrigida', '2026-07-24', NULL),
    ('est-rh-01', 'CVE-2023-4863', '2026-07-20', 'Corrigida', '2026-08-11', NULL),
    ('est-rh-01', 'CVE-2024-21413', '2026-07-20', 'Corrigida', '2026-08-03', NULL),
    ('est-secacad-01', 'CVE-2021-34527', '2026-07-20', 'Corrigida', '2026-09-14', NULL),
    ('est-secacad-01', 'CVE-2023-36884', '2026-07-20', 'Corrigida', '2026-09-18', NULL),
    ('fw-borda01', 'CVE-2015-4000', '2026-07-20', 'Em correção', NULL, NULL),
    ('fw-borda01', 'CVE-2021-3449', '2026-07-20', 'Aberta', NULL, NULL),
    ('fw-borda01', 'CVE-2023-48795', '2026-07-20', 'Corrigida', '2026-11-06', NULL),
    ('imp-financeiro-01', 'CVE-2014-3566', '2026-07-20', 'Em correção', NULL, NULL),
    ('imp-secacad-01', 'CVE-2015-4000', '2026-07-20', 'Aberta', NULL, NULL),
    ('imp-secacad-01', 'CVE-2016-2183', '2026-07-20', 'Em correção', NULL, NULL),
    ('lab-ccet-01', 'CVE-2021-34527', '2026-07-20', 'Corrigida', '2026-07-30', NULL),
    ('lab-ccet-01', 'CVE-2023-36884', '2026-07-20', 'Corrigida', '2026-09-13', NULL),
    ('lab-ccet-01', 'CVE-2023-4863', '2026-07-20', 'Corrigida', '2026-07-21', NULL),
    ('lab-ccet-01', 'CVE-2024-21413', '2026-07-20', 'Corrigida', '2026-07-28', NULL),
    ('lab-ccet-02', 'CVE-2017-0144', '2026-07-20', 'Corrigida', '2026-08-03', 'SMBv1 desativado.'),
    ('lab-ccet-02', 'CVE-2019-0708', '2026-07-20', 'Corrigida', '2026-07-22', NULL),
    ('lab-ccet-03', 'CVE-2022-0847', '2026-07-20', 'Corrigida', '2026-09-20', NULL),
    ('lab-ccet-03', 'CVE-2023-38408', '2026-07-20', 'Corrigida', '2026-08-05', NULL),
    ('lab-ccet-03', 'CVE-2023-4863', '2026-07-20', 'Corrigida', '2026-08-24', NULL),
    ('rt-borda01', 'CVE-2016-2183', '2026-07-20', 'Aberta', NULL, NULL),
    ('rt-borda01', 'CVE-2023-20198', '2026-07-20', 'Corrigida', '2026-07-23', NULL),
    ('srv-academico01', 'CVE-2015-4000', '2026-07-20', 'Corrigida', '2026-11-16', NULL),
    ('srv-ad01', 'CVE-2020-1472', '2026-07-20', 'Corrigida', '2026-07-22', NULL),
    ('srv-ad01', 'CVE-2021-34527', '2026-07-20', 'Corrigida', '2026-08-26', NULL),
    ('srv-ad02', 'CVE-2016-2183', '2026-07-20', 'Corrigida', '2026-08-18', NULL),
    ('srv-ad02', 'CVE-2020-1472', '2026-07-20', 'Corrigida', '2026-07-31', 'Correção atrasou por dependência de aplicação legada.'),
    ('srv-arquivos01', 'CVE-2016-2183', '2026-07-20', 'Corrigida', '2026-07-22', NULL),
    ('srv-arquivos01', 'CVE-2017-0144', '2026-07-20', 'Em correção', NULL, NULL),
    ('srv-arquivos01', 'CVE-2019-0708', '2026-07-20', 'Corrigida', '2026-07-22', NULL),
    ('srv-backup01', 'CVE-2024-6387', '2026-07-20', 'Corrigida', '2026-08-11', NULL),
    ('srv-bd01', 'CVE-2022-0847', '2026-07-20', 'Corrigida', '2026-08-28', NULL),
    ('srv-email01', 'CVE-2016-2183', '2026-07-20', 'Corrigida', '2026-08-07', NULL),
    ('srv-email01', 'CVE-2021-26855', '2026-07-20', 'Corrigida', '2026-07-21', NULL),
    ('srv-email01', 'CVE-2021-34527', '2026-07-20', 'Aberta', NULL, NULL),
    ('srv-impressao01', 'CVE-2021-34527', '2026-07-20', 'Aberta', NULL, NULL),
    ('srv-monitor01', 'CVE-2014-0160', '2026-07-20', 'Aberta', NULL, NULL),
    ('srv-monitor01', 'CVE-2014-3566', '2026-07-20', 'Risco aceito', NULL, 'Equipamento legado sem atualização do fabricante; isolado em VLAN restrita.'),
    ('srv-portal01', 'CVE-2019-0211', '2026-07-20', 'Corrigida', '2026-07-31', NULL),
    ('srv-portal01', 'CVE-2021-3449', '2026-07-20', 'Corrigida', '2026-07-21', NULL),
    ('srv-portal01', 'CVE-2021-41773', '2026-07-20', 'Aberta', NULL, NULL),
    ('srv-portal01', 'CVE-2023-44487', '2026-07-20', 'Corrigida', '2026-08-30', NULL),
    ('srv-portal02', 'CVE-2022-0847', '2026-07-20', 'Corrigida', '2026-09-22', NULL),
    ('srv-portal02', 'CVE-2023-44487', '2026-07-20', 'Corrigida', '2026-07-22', NULL),
    ('srv-portal02', 'CVE-2024-6387', '2026-07-20', 'Corrigida', '2026-08-12', NULL),
    ('srv-wiki01', 'CVE-2021-4034', '2026-07-20', 'Em correção', NULL, NULL),
    ('srv-wiki01', 'CVE-2022-26134', '2026-07-20', 'Corrigida', '2026-07-21', NULL),
    ('sw-biblioteca01', 'CVE-2014-3566', '2026-07-20', 'Aberta', NULL, NULL),
    ('sw-biblioteca01', 'CVE-2018-0171', '2026-07-20', 'Corrigida', '2026-08-19', NULL),
    ('sw-core01', 'CVE-2016-2183', '2026-07-20', 'Corrigida', '2026-09-28', NULL),
    ('sw-lab-ccet01', 'CVE-2014-3566', '2026-07-20', 'Aberta', NULL, NULL),
    ('sw-lab-ccet01', 'CVE-2018-0171', '2026-07-20', 'Corrigida', '2026-07-25', NULL),
    ('est-biblioteca-01', 'CVE-2023-4863', '2026-08-17', 'Aberta', NULL, NULL),
    ('est-reitoria-01', 'CVE-2021-34527', '2026-08-17', 'Corrigida', '2026-10-13', NULL),
    ('est-reitoria-02', 'CVE-2023-36884', '2026-08-17', 'Corrigida', '2026-09-21', NULL),
    ('est-secacad-02', 'CVE-2023-4863', '2026-08-17', 'Corrigida', '2026-08-18', NULL),
    ('est-secacad-02', 'CVE-2024-21413', '2026-08-17', 'Corrigida', '2026-08-18', NULL),
    ('imp-financeiro-01', 'CVE-2015-4000', '2026-08-17', 'Risco aceito', NULL, 'Equipamento legado sem atualização do fabricante; isolado em VLAN restrita.'),
    ('imp-secacad-01', 'CVE-2014-3566', '2026-08-17', 'Aberta', NULL, NULL),
    ('rt-borda01', 'CVE-2018-0171', '2026-08-17', 'Corrigida', '2026-09-26', NULL),
    ('srv-academico01', 'CVE-2018-15473', '2026-08-17', 'Corrigida', '2026-10-31', NULL),
    ('srv-ad01', 'CVE-2016-2183', '2026-08-17', 'Corrigida', '2026-08-18', NULL),
    ('srv-portal01', 'CVE-2021-4034', '2026-08-17', 'Corrigida', '2026-10-10', NULL),
    ('srv-academico01', 'CVE-2020-1938', '2026-09-14', 'Corrigida', '2026-09-22', NULL),
    ('srv-academico01', 'CVE-2021-4034', '2026-09-14', 'Corrigida', '2026-11-10', NULL),
    ('srv-ad02', 'CVE-2021-34527', '2026-09-14', 'Corrigida', '2026-10-08', NULL),
    ('srv-monitor01', 'CVE-2017-15906', '2026-09-14', 'Aberta', NULL, NULL),
    ('ap-biblioteca01', 'CVE-2014-3566', '2026-10-05', 'Aberta', NULL, NULL),
    ('est-secacad-01', 'CVE-2020-0796', '2026-10-05', 'Corrigida', '2026-10-11', NULL),
    ('srv-monitor01', 'CVE-2015-4000', '2026-10-05', 'Aberta', NULL, NULL),
    ('srv-portal01', 'CVE-2023-48795', '2026-10-05', 'Aberta', NULL, NULL),
    ('srv-wiki01', 'CVE-2014-3566', '2026-10-05', 'Aberta', NULL, NULL),
    ('sw-core01', 'CVE-2018-0171', '2026-10-05', 'Corrigida', '2026-10-16', NULL),
    ('sw-reitoria01', 'CVE-2018-0171', '2026-10-05', 'Corrigida', '2026-10-07', NULL),
    ('sw-core01', 'CVE-2023-20198', '2026-10-26', 'Corrigida', '2026-11-15', NULL),
    ('sw-reitoria01', 'CVE-2014-3566', '2026-10-26', 'Aberta', NULL, NULL),
    ('est-financeiro-01', 'CVE-2024-21413', '2026-11-09', 'Corrigida', '2026-11-10', NULL),
    ('est-financeiro-02', 'CVE-2020-0796', '2026-11-09', 'Corrigida', '2026-11-10', NULL),
    ('est-reitoria-02', 'CVE-2023-4863', '2026-11-09', 'Aberta', NULL, NULL),
    ('est-secacad-01', 'CVE-2023-4863', '2026-11-09', 'Em correção', NULL, NULL),
    ('imp-financeiro-01', 'CVE-2016-2183', '2026-11-09', 'Aberta', NULL, NULL),
    ('lab-ccet-02', 'CVE-2017-0144', '2026-11-09', 'Aberta', NULL, 'REINCIDÊNCIA: falha já havia sido corrigida antes neste ativo.'),
    ('srv-academico01', 'CVE-2021-44228', '2026-11-09', 'Em correção', NULL, 'Aguardando janela de manutenção para atualizar a aplicação.'),
    ('srv-academico01', 'CVE-2022-22965', '2026-11-09', 'Aberta', NULL, NULL),
    ('srv-arquivos01', 'CVE-2021-34527', '2026-11-09', 'Em correção', NULL, NULL),
    ('srv-backup01', 'CVE-2023-48795', '2026-11-09', 'Em correção', NULL, NULL),
    ('srv-bd01', 'CVE-2021-3449', '2026-11-09', 'Aberta', NULL, NULL),
    ('srv-bd01', 'CVE-2021-4034', '2026-11-09', 'Corrigida', '2026-11-17', NULL),
    ('srv-bd01', 'CVE-2023-48795', '2026-11-09', 'Aberta', NULL, NULL),
    ('srv-monitor01', 'CVE-2016-2183', '2026-11-09', 'Em correção', NULL, NULL),
    ('srv-portal02', 'CVE-2023-48795', '2026-11-09', 'Em correção', NULL, NULL),
    ('est-financeiro-01', 'CVE-2023-36884', '2026-11-16', 'Aberta', NULL, NULL),
    ('srv-backup01', 'CVE-2024-3094', '2026-11-16', 'Aberta', NULL, NULL)
  ) AS d (hostname, cve, data_deteccao, status, data_correcao, observacao)
  JOIN ativo a            ON a.hostname = d.hostname
  JOIN vulnerabilidade v  ON v.cve = d.cve
  JOIN varredura vr       ON vr.data_varredura = d.data_deteccao::date;

-- Usuários iniciais do sistema (senha de ambos: admin).
-- O valor guardado é o hash PBKDF2-SHA256 (240.000 iterações, salt aleatório);
-- troque as senhas pela tela Usuários depois de instalar.
INSERT INTO usuario (nome, login, senha_hash, perfil) VALUES
    ('Administrador', 'admin',
     'pbkdf2_sha256$240000$sCuLuhbYF5OkcCKhM4M8xw==$JoWgsSrRrnRo3h7+Y/6nHCzc5+c2xRONRIQxp68ZJYU=', 'Administrador'),
    ('Higor', 'higor',
     'pbkdf2_sha256$240000$SO/zhnO9jblQzhwltzXoXA==$A8xS9s6IsHhS0hbYxQoUQUkLOj5HKGUZ3bUfExVIWQU=', 'Administrador');

-- Limpa o log gerado pela carga inicial (a auditoria passa a valer a partir daqui)
TRUNCATE auditoria RESTART IDENTITY;
