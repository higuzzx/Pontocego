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
