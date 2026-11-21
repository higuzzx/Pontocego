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
