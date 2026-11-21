--
-- PostgreSQL database dump
--

-- Dumped from database version 16.2
-- Dumped by pg_dump version 16.2

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

ALTER TABLE IF EXISTS ONLY public.varredura DROP CONSTRAINT IF EXISTS varredura_id_responsavel_fkey;
ALTER TABLE IF EXISTS ONLY public.responsavel DROP CONSTRAINT IF EXISTS responsavel_id_setor_fkey;
ALTER TABLE IF EXISTS ONLY public.ocorrencia DROP CONSTRAINT IF EXISTS ocorrencia_id_vulnerabilidade_fkey;
ALTER TABLE IF EXISTS ONLY public.ocorrencia DROP CONSTRAINT IF EXISTS ocorrencia_id_varredura_fkey;
ALTER TABLE IF EXISTS ONLY public.ocorrencia DROP CONSTRAINT IF EXISTS ocorrencia_id_ativo_fkey;
ALTER TABLE IF EXISTS ONLY public.ativo DROP CONSTRAINT IF EXISTS ativo_id_setor_fkey;
ALTER TABLE IF EXISTS ONLY public.ativo DROP CONSTRAINT IF EXISTS ativo_id_responsavel_fkey;
DROP TRIGGER IF EXISTS trg_regras_ocorrencia ON public.ocorrencia;
DROP TRIGGER IF EXISTS trg_recalcular_risco ON public.ocorrencia;
DROP TRIGGER IF EXISTS trg_definir_severidade ON public.vulnerabilidade;
DROP TRIGGER IF EXISTS trg_criticidade_ativo ON public.ativo;
DROP TRIGGER IF EXISTS trg_auditoria_vulnerabilidade ON public.vulnerabilidade;
DROP TRIGGER IF EXISTS trg_auditoria_usuario ON public.usuario;
DROP TRIGGER IF EXISTS trg_auditoria_ocorrencia ON public.ocorrencia;
DROP TRIGGER IF EXISTS trg_auditoria_ativo ON public.ativo;
CREATE OR REPLACE VIEW public.vw_vulnerabilidades_frequentes AS
SELECT
    NULL::character varying(20) AS cve,
    NULL::character varying(120) AS titulo,
    NULL::numeric(3,1) AS cvss,
    NULL::character varying(10) AS severidade,
    NULL::bigint AS total_deteccoes,
    NULL::bigint AS ativos_afetados_hoje;
CREATE OR REPLACE VIEW public.vw_ranking_ativos AS
SELECT
    NULL::bigint AS posicao,
    NULL::integer AS id_ativo,
    NULL::character varying(60) AS hostname,
    NULL::inet AS ip,
    NULL::character varying(20) AS tipo,
    NULL::character varying(60) AS sistema_operacional,
    NULL::character varying(60) AS setor,
    NULL::character varying(80) AS responsavel,
    NULL::smallint AS criticidade,
    NULL::numeric(6,1) AS score_risco,
    NULL::bigint AS pendentes,
    NULL::bigint AS criticas,
    NULL::bigint AS vencidas;
DROP INDEX IF EXISTS public.uq_ocorrencia_pendente;
DROP INDEX IF EXISTS public.idx_vulnerabilidade_severidade;
DROP INDEX IF EXISTS public.idx_ocorrencia_vuln;
DROP INDEX IF EXISTS public.idx_ocorrencia_varred;
DROP INDEX IF EXISTS public.idx_ocorrencia_status;
DROP INDEX IF EXISTS public.idx_ocorrencia_pendente_prazo;
DROP INDEX IF EXISTS public.idx_ocorrencia_ativo;
DROP INDEX IF EXISTS public.idx_auditoria_tabela;
DROP INDEX IF EXISTS public.idx_auditoria_data;
DROP INDEX IF EXISTS public.idx_ativo_setor;
DROP INDEX IF EXISTS public.idx_ativo_score;
ALTER TABLE IF EXISTS ONLY public.vulnerabilidade DROP CONSTRAINT IF EXISTS vulnerabilidade_pkey;
ALTER TABLE IF EXISTS ONLY public.vulnerabilidade DROP CONSTRAINT IF EXISTS vulnerabilidade_cve_key;
ALTER TABLE IF EXISTS ONLY public.varredura DROP CONSTRAINT IF EXISTS varredura_pkey;
ALTER TABLE IF EXISTS ONLY public.usuario DROP CONSTRAINT IF EXISTS usuario_pkey;
ALTER TABLE IF EXISTS ONLY public.usuario DROP CONSTRAINT IF EXISTS usuario_login_key;
ALTER TABLE IF EXISTS ONLY public.setor DROP CONSTRAINT IF EXISTS setor_pkey;
ALTER TABLE IF EXISTS ONLY public.setor DROP CONSTRAINT IF EXISTS setor_nome_key;
ALTER TABLE IF EXISTS ONLY public.responsavel DROP CONSTRAINT IF EXISTS responsavel_pkey;
ALTER TABLE IF EXISTS ONLY public.responsavel DROP CONSTRAINT IF EXISTS responsavel_email_key;
ALTER TABLE IF EXISTS ONLY public.ocorrencia DROP CONSTRAINT IF EXISTS ocorrencia_pkey;
ALTER TABLE IF EXISTS ONLY public.auditoria DROP CONSTRAINT IF EXISTS auditoria_pkey;
ALTER TABLE IF EXISTS ONLY public.ativo DROP CONSTRAINT IF EXISTS ativo_pkey;
ALTER TABLE IF EXISTS ONLY public.ativo DROP CONSTRAINT IF EXISTS ativo_ip_key;
ALTER TABLE IF EXISTS ONLY public.ativo DROP CONSTRAINT IF EXISTS ativo_hostname_key;
ALTER TABLE IF EXISTS public.vulnerabilidade ALTER COLUMN id_vulnerabilidade DROP DEFAULT;
ALTER TABLE IF EXISTS public.varredura ALTER COLUMN id_varredura DROP DEFAULT;
ALTER TABLE IF EXISTS public.usuario ALTER COLUMN id_usuario DROP DEFAULT;
ALTER TABLE IF EXISTS public.setor ALTER COLUMN id_setor DROP DEFAULT;
ALTER TABLE IF EXISTS public.responsavel ALTER COLUMN id_responsavel DROP DEFAULT;
ALTER TABLE IF EXISTS public.ocorrencia ALTER COLUMN id_ocorrencia DROP DEFAULT;
ALTER TABLE IF EXISTS public.auditoria ALTER COLUMN id_auditoria DROP DEFAULT;
ALTER TABLE IF EXISTS public.ativo ALTER COLUMN id_ativo DROP DEFAULT;
DROP VIEW IF EXISTS public.vw_vulnerabilidades_frequentes;
DROP VIEW IF EXISTS public.vw_tempo_medio_correcao;
DROP VIEW IF EXISTS public.vw_resumo_setor;
DROP VIEW IF EXISTS public.vw_ranking_ativos;
DROP VIEW IF EXISTS public.vw_ocorrencias_vencidas;
DROP VIEW IF EXISTS public.vw_ocorrencias_pendentes;
DROP SEQUENCE IF EXISTS public.vulnerabilidade_id_vulnerabilidade_seq;
DROP TABLE IF EXISTS public.vulnerabilidade;
DROP SEQUENCE IF EXISTS public.varredura_id_varredura_seq;
DROP TABLE IF EXISTS public.varredura;
DROP SEQUENCE IF EXISTS public.usuario_id_usuario_seq;
DROP TABLE IF EXISTS public.usuario;
DROP SEQUENCE IF EXISTS public.setor_id_setor_seq;
DROP TABLE IF EXISTS public.setor;
DROP SEQUENCE IF EXISTS public.responsavel_id_responsavel_seq;
DROP TABLE IF EXISTS public.responsavel;
DROP SEQUENCE IF EXISTS public.ocorrencia_id_ocorrencia_seq;
DROP TABLE IF EXISTS public.ocorrencia;
DROP SEQUENCE IF EXISTS public.auditoria_id_auditoria_seq;
DROP TABLE IF EXISTS public.auditoria;
DROP SEQUENCE IF EXISTS public.ativo_id_ativo_seq;
DROP TABLE IF EXISTS public.ativo;
DROP FUNCTION IF EXISTS public.trg_fn_regras_ocorrencia();
DROP FUNCTION IF EXISTS public.trg_fn_recalcular_risco();
DROP FUNCTION IF EXISTS public.trg_fn_definir_severidade();
DROP FUNCTION IF EXISTS public.trg_fn_criticidade_ativo();
DROP FUNCTION IF EXISTS public.trg_fn_auditoria();
DROP PROCEDURE IF EXISTS public.sp_registrar_ocorrencia(IN p_id_ativo integer, IN p_cve character varying, IN p_id_varredura integer, INOUT p_resultado text);
DROP PROCEDURE IF EXISTS public.sp_fechar_ocorrencia(IN p_id_ocorrencia integer, IN p_observacao text, INOUT p_dias integer, INOUT p_resultado text);
DROP FUNCTION IF EXISTS public.fn_severidade_cvss(p_cvss numeric);
DROP FUNCTION IF EXISTS public.fn_calcular_score(p_id_ativo integer);
--
-- Name: fn_calcular_score(integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.fn_calcular_score(p_id_ativo integer) RETURNS numeric
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: fn_severidade_cvss(numeric); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.fn_severidade_cvss(p_cvss numeric) RETURNS character varying
    LANGUAGE plpgsql IMMUTABLE
    AS $$
BEGIN
    RETURN CASE
        WHEN p_cvss >= 9.0 THEN 'Crítica'
        WHEN p_cvss >= 7.0 THEN 'Alta'
        WHEN p_cvss >= 4.0 THEN 'Média'
        WHEN p_cvss >  0.0 THEN 'Baixa'
        ELSE 'Nenhuma'
    END;
END;
$$;


--
-- Name: sp_fechar_ocorrencia(integer, text, integer, text); Type: PROCEDURE; Schema: public; Owner: -
--

CREATE PROCEDURE public.sp_fechar_ocorrencia(IN p_id_ocorrencia integer, IN p_observacao text, INOUT p_dias integer DEFAULT NULL::integer, INOUT p_resultado text DEFAULT NULL::text)
    LANGUAGE plpgsql
    AS $$
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


--
-- Name: sp_registrar_ocorrencia(integer, character varying, integer, text); Type: PROCEDURE; Schema: public; Owner: -
--

CREATE PROCEDURE public.sp_registrar_ocorrencia(IN p_id_ativo integer, IN p_cve character varying, IN p_id_varredura integer, INOUT p_resultado text DEFAULT NULL::text)
    LANGUAGE plpgsql
    AS $$
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


--
-- Name: trg_fn_auditoria(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_fn_auditoria() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: trg_fn_criticidade_ativo(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_fn_criticidade_ativo() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: trg_fn_definir_severidade(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_fn_definir_severidade() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.severidade := fn_severidade_cvss(NEW.cvss);
    RETURN NEW;
END;
$$;


--
-- Name: trg_fn_recalcular_risco(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_fn_recalcular_risco() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: trg_fn_regras_ocorrencia(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_fn_regras_ocorrencia() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: ativo; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ativo (
    id_ativo integer NOT NULL,
    hostname character varying(60) NOT NULL,
    ip inet NOT NULL,
    tipo character varying(20) NOT NULL,
    sistema_operacional character varying(60),
    criticidade smallint NOT NULL,
    score_risco numeric(6,1) DEFAULT 0 NOT NULL,
    situacao character varying(10) DEFAULT 'Ativo'::character varying NOT NULL,
    data_cadastro date DEFAULT CURRENT_DATE NOT NULL,
    id_setor integer NOT NULL,
    id_responsavel integer NOT NULL,
    CONSTRAINT ativo_criticidade_check CHECK (((criticidade >= 1) AND (criticidade <= 5))),
    CONSTRAINT ativo_situacao_check CHECK (((situacao)::text = ANY ((ARRAY['Ativo'::character varying, 'Inativo'::character varying])::text[]))),
    CONSTRAINT ativo_tipo_check CHECK (((tipo)::text = ANY ((ARRAY['Servidor'::character varying, 'Estação'::character varying, 'Switch'::character varying, 'Roteador'::character varying, 'Firewall'::character varying, 'Impressora'::character varying, 'Access Point'::character varying])::text[])))
);


--
-- Name: ativo_id_ativo_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ativo_id_ativo_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ativo_id_ativo_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ativo_id_ativo_seq OWNED BY public.ativo.id_ativo;


--
-- Name: auditoria; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.auditoria (
    id_auditoria bigint NOT NULL,
    tabela character varying(30) NOT NULL,
    operacao character varying(10) NOT NULL,
    id_registro integer NOT NULL,
    dados_antigos jsonb,
    dados_novos jsonb,
    usuario_app character varying(30),
    usuario_bd character varying(60) DEFAULT CURRENT_USER NOT NULL,
    data_hora timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: auditoria_id_auditoria_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.auditoria_id_auditoria_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: auditoria_id_auditoria_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.auditoria_id_auditoria_seq OWNED BY public.auditoria.id_auditoria;


--
-- Name: ocorrencia; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ocorrencia (
    id_ocorrencia integer NOT NULL,
    id_ativo integer NOT NULL,
    id_vulnerabilidade integer NOT NULL,
    id_varredura integer NOT NULL,
    data_deteccao date DEFAULT CURRENT_DATE NOT NULL,
    prazo_correcao date NOT NULL,
    status character varying(15) DEFAULT 'Aberta'::character varying NOT NULL,
    data_correcao date,
    observacao text,
    CONSTRAINT ocorrencia_check CHECK (((data_correcao IS NULL) OR (data_correcao >= data_deteccao))),
    CONSTRAINT ocorrencia_status_check CHECK (((status)::text = ANY ((ARRAY['Aberta'::character varying, 'Em correção'::character varying, 'Corrigida'::character varying, 'Risco aceito'::character varying])::text[])))
);


--
-- Name: ocorrencia_id_ocorrencia_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ocorrencia_id_ocorrencia_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ocorrencia_id_ocorrencia_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ocorrencia_id_ocorrencia_seq OWNED BY public.ocorrencia.id_ocorrencia;


--
-- Name: responsavel; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.responsavel (
    id_responsavel integer NOT NULL,
    nome character varying(80) NOT NULL,
    email character varying(100) NOT NULL,
    cargo character varying(50),
    id_setor integer NOT NULL
);


--
-- Name: responsavel_id_responsavel_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.responsavel_id_responsavel_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: responsavel_id_responsavel_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.responsavel_id_responsavel_seq OWNED BY public.responsavel.id_responsavel;


--
-- Name: setor; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.setor (
    id_setor integer NOT NULL,
    nome character varying(60) NOT NULL,
    localizacao character varying(80)
);


--
-- Name: setor_id_setor_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.setor_id_setor_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: setor_id_setor_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.setor_id_setor_seq OWNED BY public.setor.id_setor;


--
-- Name: usuario; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.usuario (
    id_usuario integer NOT NULL,
    nome character varying(80) NOT NULL,
    login character varying(30) NOT NULL,
    senha_hash character varying(200) NOT NULL,
    perfil character varying(15) DEFAULT 'Analista'::character varying NOT NULL,
    ativo boolean DEFAULT true NOT NULL,
    data_cadastro timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    ultimo_acesso timestamp without time zone,
    CONSTRAINT usuario_login_check CHECK ((((login)::text = lower((login)::text)) AND ((login)::text ~ '^[a-z0-9._-]{3,30}$'::text))),
    CONSTRAINT usuario_perfil_check CHECK (((perfil)::text = ANY ((ARRAY['Administrador'::character varying, 'Analista'::character varying])::text[])))
);


--
-- Name: usuario_id_usuario_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.usuario_id_usuario_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: usuario_id_usuario_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.usuario_id_usuario_seq OWNED BY public.usuario.id_usuario;


--
-- Name: varredura; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.varredura (
    id_varredura integer NOT NULL,
    data_varredura date DEFAULT CURRENT_DATE NOT NULL,
    ferramenta character varying(30) NOT NULL,
    escopo character varying(80) NOT NULL,
    observacao text,
    id_responsavel integer NOT NULL
);


--
-- Name: varredura_id_varredura_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.varredura_id_varredura_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: varredura_id_varredura_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.varredura_id_varredura_seq OWNED BY public.varredura.id_varredura;


--
-- Name: vulnerabilidade; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vulnerabilidade (
    id_vulnerabilidade integer NOT NULL,
    cve character varying(20) NOT NULL,
    titulo character varying(120) NOT NULL,
    descricao text,
    cvss numeric(3,1) NOT NULL,
    severidade character varying(10) NOT NULL,
    solucao text,
    data_publicacao date,
    CONSTRAINT vulnerabilidade_cve_check CHECK (((cve)::text ~ '^CVE-[0-9]{4}-[0-9]{4,}$'::text)),
    CONSTRAINT vulnerabilidade_cvss_check CHECK (((cvss >= (0)::numeric) AND (cvss <= (10)::numeric)))
);


--
-- Name: vulnerabilidade_id_vulnerabilidade_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.vulnerabilidade_id_vulnerabilidade_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: vulnerabilidade_id_vulnerabilidade_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.vulnerabilidade_id_vulnerabilidade_seq OWNED BY public.vulnerabilidade.id_vulnerabilidade;


--
-- Name: vw_ocorrencias_pendentes; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.vw_ocorrencias_pendentes AS
 SELECT o.id_ocorrencia,
    a.hostname,
    a.ip,
    s.nome AS setor,
    r.nome AS responsavel,
    v.cve,
    v.titulo,
    v.cvss,
    v.severidade,
    o.status,
    o.data_deteccao,
    o.prazo_correcao,
    (o.prazo_correcao - CURRENT_DATE) AS dias_restantes,
        CASE
            WHEN (o.prazo_correcao < CURRENT_DATE) THEN 'Vencida'::text
            WHEN (o.prazo_correcao <= (CURRENT_DATE + 7)) THEN 'Vence em até 7 dias'::text
            ELSE 'No prazo'::text
        END AS situacao_prazo,
    vr.ferramenta,
    o.observacao,
    o.id_ativo
   FROM (((((public.ocorrencia o
     JOIN public.ativo a ON ((a.id_ativo = o.id_ativo)))
     JOIN public.setor s ON ((s.id_setor = a.id_setor)))
     JOIN public.responsavel r ON ((r.id_responsavel = a.id_responsavel)))
     JOIN public.vulnerabilidade v ON ((v.id_vulnerabilidade = o.id_vulnerabilidade)))
     JOIN public.varredura vr ON ((vr.id_varredura = o.id_varredura)))
  WHERE ((o.status)::text = ANY ((ARRAY['Aberta'::character varying, 'Em correção'::character varying])::text[]));


--
-- Name: vw_ocorrencias_vencidas; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.vw_ocorrencias_vencidas AS
 SELECT id_ocorrencia,
    hostname,
    setor,
    responsavel,
    cve,
    titulo,
    severidade,
    status,
    prazo_correcao,
    (CURRENT_DATE - prazo_correcao) AS dias_de_atraso
   FROM public.vw_ocorrencias_pendentes
  WHERE (prazo_correcao < CURRENT_DATE);


--
-- Name: vw_ranking_ativos; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.vw_ranking_ativos AS
SELECT
    NULL::bigint AS posicao,
    NULL::integer AS id_ativo,
    NULL::character varying(60) AS hostname,
    NULL::inet AS ip,
    NULL::character varying(20) AS tipo,
    NULL::character varying(60) AS sistema_operacional,
    NULL::character varying(60) AS setor,
    NULL::character varying(80) AS responsavel,
    NULL::smallint AS criticidade,
    NULL::numeric(6,1) AS score_risco,
    NULL::bigint AS pendentes,
    NULL::bigint AS criticas,
    NULL::bigint AS vencidas;


--
-- Name: vw_resumo_setor; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.vw_resumo_setor AS
 SELECT s.nome AS setor,
    count(DISTINCT a.id_ativo) AS ativos,
    count(o.id_ocorrencia) FILTER (WHERE ((v.severidade)::text = 'Crítica'::text)) AS criticas,
    count(o.id_ocorrencia) FILTER (WHERE ((v.severidade)::text = 'Alta'::text)) AS altas,
    count(o.id_ocorrencia) FILTER (WHERE ((v.severidade)::text = 'Média'::text)) AS medias,
    count(o.id_ocorrencia) FILTER (WHERE ((v.severidade)::text = 'Baixa'::text)) AS baixas,
    count(o.id_ocorrencia) AS total_pendentes,
    count(o.id_ocorrencia) FILTER (WHERE (o.prazo_correcao < CURRENT_DATE)) AS vencidas
   FROM (((public.setor s
     LEFT JOIN public.ativo a ON ((a.id_setor = s.id_setor)))
     LEFT JOIN public.ocorrencia o ON (((o.id_ativo = a.id_ativo) AND ((o.status)::text = ANY ((ARRAY['Aberta'::character varying, 'Em correção'::character varying])::text[])))))
     LEFT JOIN public.vulnerabilidade v ON ((v.id_vulnerabilidade = o.id_vulnerabilidade)))
  GROUP BY s.nome;


--
-- Name: vw_tempo_medio_correcao; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.vw_tempo_medio_correcao AS
 SELECT v.severidade,
    count(*) AS corrigidas,
    round(avg((o.data_correcao - o.data_deteccao)), 1) AS media_dias,
    min((o.data_correcao - o.data_deteccao)) AS menor_dias,
    max((o.data_correcao - o.data_deteccao)) AS maior_dias,
    round(((100.0 * (count(*) FILTER (WHERE (o.data_correcao <= o.prazo_correcao)))::numeric) / (count(*))::numeric), 1) AS pct_no_prazo
   FROM (public.ocorrencia o
     JOIN public.vulnerabilidade v ON ((v.id_vulnerabilidade = o.id_vulnerabilidade)))
  WHERE ((o.status)::text = 'Corrigida'::text)
  GROUP BY v.severidade;


--
-- Name: vw_vulnerabilidades_frequentes; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.vw_vulnerabilidades_frequentes AS
SELECT
    NULL::character varying(20) AS cve,
    NULL::character varying(120) AS titulo,
    NULL::numeric(3,1) AS cvss,
    NULL::character varying(10) AS severidade,
    NULL::bigint AS total_deteccoes,
    NULL::bigint AS ativos_afetados_hoje;


--
-- Name: ativo id_ativo; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ativo ALTER COLUMN id_ativo SET DEFAULT nextval('public.ativo_id_ativo_seq'::regclass);


--
-- Name: auditoria id_auditoria; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auditoria ALTER COLUMN id_auditoria SET DEFAULT nextval('public.auditoria_id_auditoria_seq'::regclass);


--
-- Name: ocorrencia id_ocorrencia; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ocorrencia ALTER COLUMN id_ocorrencia SET DEFAULT nextval('public.ocorrencia_id_ocorrencia_seq'::regclass);


--
-- Name: responsavel id_responsavel; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.responsavel ALTER COLUMN id_responsavel SET DEFAULT nextval('public.responsavel_id_responsavel_seq'::regclass);


--
-- Name: setor id_setor; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.setor ALTER COLUMN id_setor SET DEFAULT nextval('public.setor_id_setor_seq'::regclass);


--
-- Name: usuario id_usuario; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usuario ALTER COLUMN id_usuario SET DEFAULT nextval('public.usuario_id_usuario_seq'::regclass);


--
-- Name: varredura id_varredura; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.varredura ALTER COLUMN id_varredura SET DEFAULT nextval('public.varredura_id_varredura_seq'::regclass);


--
-- Name: vulnerabilidade id_vulnerabilidade; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerabilidade ALTER COLUMN id_vulnerabilidade SET DEFAULT nextval('public.vulnerabilidade_id_vulnerabilidade_seq'::regclass);


--
-- Data for Name: ativo; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (18, 'sw-lab-ccet01', '10.10.30.2', 'Switch', 'Cisco IOS 15.0', 2, 1.4, 'Ativo', '2026-07-06', 8, 1);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (17, 'sw-biblioteca01', '10.10.20.2', 'Switch', 'Cisco IOS 15.2', 2, 1.4, 'Ativo', '2026-07-06', 7, 1);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (5, 'srv-impressao01', '10.10.1.40', 'Servidor', 'Windows Server 2019', 2, 3.5, 'Ativo', '2026-07-06', 1, 3);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (4, 'srv-email01', '10.10.1.30', 'Servidor', 'Windows Server 2016 (Exchange 2016)', 4, 7.0, 'Ativo', '2026-07-06', 1, 1);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (30, 'lab-ccet-03', '10.10.30.23', 'Estação', 'Ubuntu 22.04 Desktop', 1, 0.0, 'Ativo', '2026-07-06', 8, 7);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (28, 'lab-ccet-01', '10.10.30.21', 'Estação', 'Windows 10 22H2', 1, 0.0, 'Ativo', '2026-07-06', 8, 7);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (13, 'fw-borda01', '10.10.0.1', 'Firewall', 'pfSense 2.6', 5, 9.6, 'Ativo', '2026-07-06', 1, 2);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (26, 'est-rh-01', '10.10.13.21', 'Estação', 'Windows 11 23H2', 3, 0.0, 'Ativo', '2026-07-06', 6, 4);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (1, 'srv-ad01', '10.10.1.10', 'Servidor', 'Windows Server 2016', 5, 0.0, 'Ativo', '2026-07-06', 1, 1);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (14, 'rt-borda01', '10.10.0.2', 'Roteador', 'Cisco IOS XE 17.3', 5, 7.5, 'Ativo', '2026-07-06', 1, 1);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (31, 'imp-secacad-01', '10.10.11.50', 'Impressora', 'HP LaserJet M404 (firmware 2019)', 1, 2.9, 'Ativo', '2026-07-06', 4, 3);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (23, 'est-secacad-02', '10.10.11.22', 'Estação', 'Windows 11 23H2', 3, 0.0, 'Ativo', '2026-07-06', 4, 4);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (20, 'est-reitoria-01', '10.10.10.21', 'Estação', 'Windows 10 22H2', 3, 0.0, 'Ativo', '2026-07-06', 3, 4);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (27, 'est-biblioteca-01', '10.10.20.21', 'Estação', 'Windows 10 22H2', 1, 1.8, 'Ativo', '2026-07-06', 7, 4);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (2, 'srv-ad02', '10.10.1.11', 'Servidor', 'Windows Server 2016', 5, 0.0, 'Ativo', '2026-07-06', 1, 1);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (12, 'srv-wiki01', '10.10.2.40', 'Servidor', 'Ubuntu 18.04 (Confluence 7)', 2, 4.5, 'Ativo', '2026-07-06', 2, 5);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (8, 'srv-portal01', '10.10.2.10', 'Servidor', 'Ubuntu 20.04 (Apache 2.4.49)', 5, 13.4, 'Ativo', '2026-07-06', 2, 5);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (19, 'ap-biblioteca01', '10.10.20.5', 'Access Point', 'Ubiquiti UniFi AC Lite', 1, 0.7, 'Ativo', '2026-07-06', 7, 3);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (16, 'sw-reitoria01', '10.10.10.2', 'Switch', 'Cisco IOS 15.2', 3, 2.0, 'Ativo', '2026-07-06', 3, 1);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (15, 'sw-core01', '10.10.0.3', 'Switch', 'Cisco IOS XE 16.12', 5, 0.0, 'Ativo', '2026-07-06', 1, 1);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (9, 'srv-portal02', '10.10.2.11', 'Servidor', 'Ubuntu 22.04 (Nginx)', 4, 4.7, 'Ativo', '2026-07-06', 2, 5);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (7, 'srv-monitor01', '10.10.1.60', 'Servidor', 'CentOS 6 (Zabbix)', 3, 14.4, 'Ativo', '2026-07-06', 1, 2);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (11, 'srv-bd01', '10.10.2.30', 'Servidor', 'Debian 11 (PostgreSQL 13)', 5, 11.8, 'Ativo', '2026-07-06', 2, 6);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (3, 'srv-arquivos01', '10.10.1.20', 'Servidor', 'Windows Server 2008 R2', 4, 13.5, 'Ativo', '2026-07-06', 1, 3);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (10, 'srv-academico01', '10.10.2.20', 'Servidor', 'CentOS 7 (Tomcat 9)', 5, 19.8, 'Ativo', '2026-07-06', 2, 5);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (29, 'lab-ccet-02', '10.10.30.22', 'Estação', 'Windows 7 SP1', 1, 1.6, 'Ativo', '2026-07-06', 8, 7);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (32, 'imp-financeiro-01', '10.10.12.50', 'Impressora', 'HP LaserJet M404 (firmware 2019)', 1, 2.2, 'Ativo', '2026-07-06', 5, 3);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (22, 'est-secacad-01', '10.10.11.21', 'Estação', 'Windows 10 1909', 3, 5.3, 'Ativo', '2026-07-06', 4, 4);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (21, 'est-reitoria-02', '10.10.10.22', 'Estação', 'Windows 10 22H2', 3, 10.6, 'Ativo', '2026-07-06', 3, 4);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (25, 'est-financeiro-02', '10.10.12.22', 'Estação', 'Windows 10 1909', 4, 7.0, 'Ativo', '2026-07-06', 5, 4);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (6, 'srv-backup01', '10.10.1.50', 'Servidor', 'Debian 12', 4, 12.7, 'Ativo', '2026-07-06', 1, 2);
INSERT INTO public.ativo (id_ativo, hostname, ip, tipo, sistema_operacional, criticidade, score_risco, situacao, data_cadastro, id_setor, id_responsavel) VALUES (24, 'est-financeiro-01', '10.10.12.21', 'Estação', 'Windows 10 22H2', 4, 7.0, 'Ativo', '2026-07-06', 5, 4);


--
-- Data for Name: auditoria; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: ocorrencia; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (1, 18, 14, 2, '2026-07-20', '2026-07-27', 'Corrigida', '2026-07-25', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (2, 18, 18, 2, '2026-07-20', '2027-01-16', 'Aberta', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (3, 15, 16, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-09-28', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (4, 17, 14, 2, '2026-07-20', '2026-07-27', 'Corrigida', '2026-08-19', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (5, 17, 18, 2, '2026-07-20', '2027-01-16', 'Aberta', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (6, 12, 21, 2, '2026-07-20', '2026-07-27', 'Corrigida', '2026-07-21', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (7, 12, 9, 2, '2026-07-20', '2026-08-19', 'Em correção', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (8, 9, 10, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-08-12', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (9, 9, 13, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-07-22', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (10, 9, 8, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-09-22', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (11, 8, 13, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-08-30', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (12, 8, 12, 2, '2026-07-20', '2026-08-19', 'Aberta', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (13, 8, 30, 2, '2026-07-20', '2026-10-18', 'Corrigida', '2026-07-21', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (14, 8, 28, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-07-31', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (15, 7, 18, 2, '2026-07-20', '2027-01-16', 'Risco aceito', NULL, 'Equipamento legado sem atualização do fabricante; isolado em VLAN restrita.');
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (16, 7, 7, 2, '2026-07-20', '2026-08-19', 'Aberta', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (17, 5, 4, 2, '2026-07-20', '2026-08-19', 'Aberta', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (18, 4, 4, 2, '2026-07-20', '2026-08-19', 'Aberta', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (19, 4, 22, 2, '2026-07-20', '2026-07-27', 'Corrigida', '2026-07-21', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (20, 4, 16, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-08-07', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (21, 11, 8, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-08-28', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (22, 6, 10, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-08-11', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (23, 3, 3, 2, '2026-07-20', '2026-07-27', 'Corrigida', '2026-07-22', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (24, 3, 2, 2, '2026-07-20', '2026-08-19', 'Em correção', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (25, 3, 16, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-07-22', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (26, 2, 5, 2, '2026-07-20', '2026-07-27', 'Corrigida', '2026-07-31', 'Correção atrasou por dependência de aplicação legada.');
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (27, 2, 16, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-08-18', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (28, 1, 4, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-08-26', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (29, 1, 5, 2, '2026-07-20', '2026-07-27', 'Corrigida', '2026-07-22', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (30, 10, 29, 2, '2026-07-20', '2027-01-16', 'Corrigida', '2026-11-16', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (31, 14, 15, 2, '2026-07-20', '2026-07-27', 'Corrigida', '2026-07-23', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (32, 14, 16, 2, '2026-07-20', '2026-08-19', 'Aberta', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (33, 30, 24, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-08-24', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (34, 30, 20, 2, '2026-07-20', '2026-07-27', 'Corrigida', '2026-08-05', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (35, 30, 8, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-09-20', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (36, 29, 3, 2, '2026-07-20', '2026-07-27', 'Corrigida', '2026-07-22', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (37, 29, 2, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-08-03', 'SMBv1 desativado.');
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (38, 28, 26, 2, '2026-07-20', '2026-07-27', 'Corrigida', '2026-07-28', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (39, 28, 24, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-07-21', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (40, 28, 25, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-09-13', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (41, 28, 4, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-07-30', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (42, 31, 16, 2, '2026-07-20', '2026-08-19', 'Em correção', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (43, 31, 29, 2, '2026-07-20', '2027-01-16', 'Aberta', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (44, 32, 18, 2, '2026-07-20', '2027-01-16', 'Em correção', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (45, 13, 17, 2, '2026-07-20', '2026-10-18', 'Corrigida', '2026-11-06', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (46, 13, 30, 2, '2026-07-20', '2026-10-18', 'Aberta', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (47, 13, 29, 2, '2026-07-20', '2027-01-16', 'Em correção', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (48, 22, 25, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-09-18', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (49, 22, 4, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-09-14', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (50, 26, 26, 2, '2026-07-20', '2026-07-27', 'Corrigida', '2026-08-03', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (51, 26, 24, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-08-11', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (52, 21, 26, 2, '2026-07-20', '2026-07-27', 'Corrigida', '2026-07-24', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (53, 21, 4, 2, '2026-07-20', '2026-08-19', 'Em correção', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (54, 20, 26, 2, '2026-07-20', '2026-07-27', 'Corrigida', '2026-08-03', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (55, 20, 24, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-08-22', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (56, 20, 25, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-09-22', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (57, 25, 24, 2, '2026-07-20', '2026-08-19', 'Aberta', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (58, 25, 25, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-08-16', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (59, 25, 4, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-09-24', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (60, 24, 24, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-07-24', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (61, 24, 4, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-07-21', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (62, 27, 26, 2, '2026-07-20', '2026-07-27', 'Corrigida', '2026-08-29', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (63, 27, 25, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-08-14', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (64, 27, 4, 2, '2026-07-20', '2026-08-19', 'Corrigida', '2026-09-10', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (65, 19, 29, 2, '2026-07-20', '2027-01-16', 'Corrigida', '2026-11-05', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (66, 8, 9, 3, '2026-08-17', '2026-09-16', 'Corrigida', '2026-10-10', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (67, 1, 16, 3, '2026-08-17', '2026-09-16', 'Corrigida', '2026-08-18', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (68, 10, 31, 3, '2026-08-17', '2026-11-15', 'Corrigida', '2026-10-31', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (69, 14, 14, 3, '2026-08-17', '2026-08-24', 'Corrigida', '2026-09-26', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (70, 31, 18, 3, '2026-08-17', '2027-02-13', 'Aberta', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (71, 32, 29, 3, '2026-08-17', '2027-02-13', 'Risco aceito', NULL, 'Equipamento legado sem atualização do fabricante; isolado em VLAN restrita.');
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (72, 23, 26, 3, '2026-08-17', '2026-08-24', 'Corrigida', '2026-08-18', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (73, 23, 24, 3, '2026-08-17', '2026-09-16', 'Corrigida', '2026-08-18', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (74, 21, 25, 3, '2026-08-17', '2026-09-16', 'Corrigida', '2026-09-21', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (75, 20, 4, 3, '2026-08-17', '2026-09-16', 'Corrigida', '2026-10-13', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (76, 27, 24, 3, '2026-08-17', '2026-09-16', 'Aberta', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (77, 7, 19, 4, '2026-09-14', '2026-12-13', 'Aberta', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (78, 2, 4, 4, '2026-09-14', '2026-10-14', 'Corrigida', '2026-10-08', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (79, 10, 9, 4, '2026-09-14', '2026-10-14', 'Corrigida', '2026-11-10', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (80, 10, 27, 4, '2026-09-14', '2026-09-21', 'Corrigida', '2026-09-22', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (81, 16, 14, 5, '2026-10-05', '2026-10-12', 'Corrigida', '2026-10-07', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (82, 15, 14, 5, '2026-10-05', '2026-10-12', 'Corrigida', '2026-10-16', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (83, 12, 18, 5, '2026-10-05', '2027-04-03', 'Aberta', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (84, 8, 17, 5, '2026-10-05', '2027-01-03', 'Aberta', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (85, 7, 29, 5, '2026-10-05', '2027-04-03', 'Aberta', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (86, 22, 6, 5, '2026-10-05', '2026-10-12', 'Corrigida', '2026-10-11', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (87, 19, 18, 5, '2026-10-05', '2027-04-03', 'Aberta', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (88, 16, 18, 6, '2026-10-26', '2027-04-24', 'Aberta', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (89, 15, 15, 6, '2026-10-26', '2026-11-02', 'Corrigida', '2026-11-15', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (90, 9, 17, 7, '2026-11-09', '2027-02-07', 'Em correção', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (91, 7, 16, 7, '2026-11-09', '2026-12-09', 'Em correção', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (92, 11, 17, 7, '2026-11-09', '2027-02-07', 'Aberta', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (93, 11, 9, 7, '2026-11-09', '2026-12-09', 'Corrigida', '2026-11-17', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (94, 11, 30, 7, '2026-11-09', '2027-02-07', 'Aberta', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (95, 6, 17, 7, '2026-11-09', '2027-02-07', 'Em correção', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (96, 3, 4, 7, '2026-11-09', '2026-12-09', 'Em correção', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (97, 10, 23, 7, '2026-11-09', '2026-11-16', 'Aberta', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (98, 10, 1, 7, '2026-11-09', '2026-11-16', 'Em correção', NULL, 'Aguardando janela de manutenção para atualizar a aplicação.');
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (99, 29, 2, 7, '2026-11-09', '2026-12-09', 'Aberta', NULL, 'REINCIDÊNCIA: falha já havia sido corrigida antes neste ativo.');
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (100, 32, 16, 7, '2026-11-09', '2026-12-09', 'Aberta', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (101, 22, 24, 7, '2026-11-09', '2026-12-09', 'Em correção', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (102, 21, 24, 7, '2026-11-09', '2026-12-09', 'Aberta', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (103, 25, 6, 7, '2026-11-09', '2026-11-16', 'Corrigida', '2026-11-10', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (104, 24, 26, 7, '2026-11-09', '2026-11-16', 'Corrigida', '2026-11-10', NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (105, 6, 11, 8, '2026-11-16', '2026-11-23', 'Aberta', NULL, NULL);
INSERT INTO public.ocorrencia (id_ocorrencia, id_ativo, id_vulnerabilidade, id_varredura, data_deteccao, prazo_correcao, status, data_correcao, observacao) VALUES (106, 24, 25, 8, '2026-11-16', '2026-12-16', 'Aberta', NULL, NULL);


--
-- Data for Name: responsavel; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.responsavel (id_responsavel, nome, email, cargo, id_setor) VALUES (1, 'Rafael Antunes', 'rafael.antunes@sgva.exemplo.br', 'Analista de Redes', 1);
INSERT INTO public.responsavel (id_responsavel, nome, email, cargo, id_setor) VALUES (2, 'Camila Duarte', 'camila.duarte@sgva.exemplo.br', 'Analista de Segurança da Informação', 1);
INSERT INTO public.responsavel (id_responsavel, nome, email, cargo, id_setor) VALUES (3, 'Bruno Teixeira', 'bruno.teixeira@sgva.exemplo.br', 'Técnico de Suporte', 1);
INSERT INTO public.responsavel (id_responsavel, nome, email, cargo, id_setor) VALUES (4, 'Eduardo Fonseca', 'eduardo.fonseca@sgva.exemplo.br', 'Técnico de Suporte', 1);
INSERT INTO public.responsavel (id_responsavel, nome, email, cargo, id_setor) VALUES (5, 'Larissa Prates', 'larissa.prates@sgva.exemplo.br', 'Analista de Sistemas', 2);
INSERT INTO public.responsavel (id_responsavel, nome, email, cargo, id_setor) VALUES (6, 'Marcos Vieira', 'marcos.vieira@sgva.exemplo.br', 'Administrador de Banco de Dados', 2);
INSERT INTO public.responsavel (id_responsavel, nome, email, cargo, id_setor) VALUES (7, 'Patrícia Lopes', 'patricia.lopes@sgva.exemplo.br', 'Técnica de Laboratório', 8);


--
-- Data for Name: setor; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.setor (id_setor, nome, localizacao) VALUES (1, 'DTI - Infraestrutura', 'Prédio da Reitoria, sala 12');
INSERT INTO public.setor (id_setor, nome, localizacao) VALUES (2, 'DTI - Sistemas', 'Prédio da Reitoria, sala 14');
INSERT INTO public.setor (id_setor, nome, localizacao) VALUES (3, 'Reitoria', 'Prédio da Reitoria, 2º andar');
INSERT INTO public.setor (id_setor, nome, localizacao) VALUES (4, 'Secretaria Acadêmica', 'Prédio Central, térreo');
INSERT INTO public.setor (id_setor, nome, localizacao) VALUES (5, 'Financeiro', 'Prédio da Reitoria, 1º andar');
INSERT INTO public.setor (id_setor, nome, localizacao) VALUES (6, 'Recursos Humanos', 'Prédio da Reitoria, 1º andar');
INSERT INTO public.setor (id_setor, nome, localizacao) VALUES (7, 'Biblioteca Central', 'Prédio da Biblioteca');
INSERT INTO public.setor (id_setor, nome, localizacao) VALUES (8, 'Laboratórios CCET', 'Prédio 6, bloco B');


--
-- Data for Name: usuario; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.usuario (id_usuario, nome, login, senha_hash, perfil, ativo, data_cadastro, ultimo_acesso) VALUES (1, 'Administrador', 'admin', 'pbkdf2_sha256$240000$sCuLuhbYF5OkcCKhM4M8xw==$JoWgsSrRrnRo3h7+Y/6nHCzc5+c2xRONRIQxp68ZJYU=', 'Administrador', true, '2026-11-21 11:23:37.375116', NULL);
INSERT INTO public.usuario (id_usuario, nome, login, senha_hash, perfil, ativo, data_cadastro, ultimo_acesso) VALUES (2, 'Higor', 'higor', 'pbkdf2_sha256$240000$SO/zhnO9jblQzhwltzXoXA==$A8xS9s6IsHhS0hbYxQoUQUkLOj5HKGUZ3bUfExVIWQU=', 'Administrador', true, '2026-11-21 11:23:37.375116', NULL);


--
-- Data for Name: varredura; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.varredura (id_varredura, data_varredura, ferramenta, escopo, observacao, id_responsavel) VALUES (1, '2026-07-06', 'Nmap', '10.10.0.0/16', 'Varredura de descoberta para levantar o inventário de ativos.', 1);
INSERT INTO public.varredura (id_varredura, data_varredura, ferramenta, escopo, observacao, id_responsavel) VALUES (2, '2026-07-20', 'OpenVAS', '10.10.0.0/16', 'Primeira varredura completa de vulnerabilidades.', 2);
INSERT INTO public.varredura (id_varredura, data_varredura, ferramenta, escopo, observacao, id_responsavel) VALUES (3, '2026-08-17', 'OpenVAS', '10.10.0.0/16', 'Varredura mensal.', 2);
INSERT INTO public.varredura (id_varredura, data_varredura, ferramenta, escopo, observacao, id_responsavel) VALUES (4, '2026-09-14', 'Nessus Essentials', '10.10.1.0/24, 10.10.2.0/24', 'Varredura autenticada só nos servidores.', 2);
INSERT INTO public.varredura (id_varredura, data_varredura, ferramenta, escopo, observacao, id_responsavel) VALUES (5, '2026-10-05', 'OpenVAS', '10.10.0.0/16', 'Varredura mensal.', 2);
INSERT INTO public.varredura (id_varredura, data_varredura, ferramenta, escopo, observacao, id_responsavel) VALUES (6, '2026-10-26', 'Nmap (scripts NSE vulners)', '10.10.0.0/24', 'Checagem dos equipamentos de rede.', 1);
INSERT INTO public.varredura (id_varredura, data_varredura, ferramenta, escopo, observacao, id_responsavel) VALUES (7, '2026-11-09', 'OpenVAS', '10.10.0.0/16', 'Varredura mensal.', 2);
INSERT INTO public.varredura (id_varredura, data_varredura, ferramenta, escopo, observacao, id_responsavel) VALUES (8, '2026-11-16', 'OpenVAS', '10.10.0.0/16', 'Varredura de verificação após correções.', 2);


--
-- Data for Name: vulnerabilidade; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (1, 'CVE-2021-44228', 'Log4Shell: execução remota de código no Apache Log4j', 'Falha na biblioteca Log4j 2 permite que um atacante execute código remotamente enviando uma string JNDI maliciosa que é registrada em log.', 10.0, 'Crítica', 'Atualizar o Log4j para 2.17.1 ou superior.', '2021-12-10');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (2, 'CVE-2017-0144', 'EternalBlue: execução remota de código no SMBv1', 'Falha no SMBv1 do Windows explorada pelo ransomware WannaCry.', 8.1, 'Alta', 'Aplicar o boletim MS17-010 e desativar o SMBv1.', '2017-03-17');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (3, 'CVE-2019-0708', 'BlueKeep: execução remota de código no RDP', 'Falha no Remote Desktop Services permite execução de código sem autenticação.', 9.8, 'Crítica', 'Aplicar a atualização de maio/2019 e ativar NLA no RDP.', '2019-05-16');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (4, 'CVE-2021-34527', 'PrintNightmare: execução de código no Spooler de Impressão', 'Falha no serviço Print Spooler do Windows permite execução remota de código com privilégios de SYSTEM.', 8.8, 'Alta', 'Aplicar a atualização KB5004945 ou desativar o Spooler onde não for necessário.', '2021-07-02');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (5, 'CVE-2020-1472', 'Zerologon: elevação de privilégio no Netlogon', 'Falha criptográfica no protocolo Netlogon permite assumir o controlador de domínio.', 10.0, 'Crítica', 'Aplicar a atualização de agosto/2020 e ativar o modo de imposição do Netlogon.', '2020-08-17');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (6, 'CVE-2020-0796', 'SMBGhost: execução remota de código no SMBv3', 'Falha na compressão do SMBv3 em versões 1903/1909 do Windows 10.', 10.0, 'Crítica', 'Aplicar a atualização KB4551762 ou desativar a compressão SMBv3.', '2020-03-12');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (7, 'CVE-2014-0160', 'Heartbleed: vazamento de memória no OpenSSL', 'Falha na extensão heartbeat do OpenSSL permite ler a memória do servidor, incluindo chaves privadas.', 7.5, 'Alta', 'Atualizar o OpenSSL para 1.0.1g ou superior e trocar os certificados.', '2014-04-07');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (8, 'CVE-2022-0847', 'Dirty Pipe: elevação de privilégio no kernel Linux', 'Falha no kernel Linux permite que usuário comum sobrescreva arquivos somente leitura.', 7.8, 'Alta', 'Atualizar o kernel para 5.16.11, 5.15.25, 5.10.102 ou superior.', '2022-03-10');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (9, 'CVE-2021-4034', 'PwnKit: elevação de privilégio no pkexec (polkit)', 'Falha no pkexec permite que qualquer usuário local obtenha root.', 7.8, 'Alta', 'Atualizar o pacote polkit.', '2022-01-28');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (10, 'CVE-2024-6387', 'regreSSHion: execução remota de código no OpenSSH', 'Condição de corrida no tratamento de sinais do sshd permite execução de código como root.', 8.1, 'Alta', 'Atualizar o OpenSSH para 9.8p1 ou superior.', '2024-07-01');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (11, 'CVE-2024-3094', 'Backdoor na biblioteca xz/liblzma', 'Versões 5.6.0 e 5.6.1 do xz continham código malicioso que compromete o sshd.', 10.0, 'Crítica', 'Voltar o xz-utils para versão não afetada (5.4.x).', '2024-03-29');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (12, 'CVE-2021-41773', 'Path traversal no Apache HTTP Server 2.4.49', 'Permite ler arquivos fora da raiz do site e, em algumas configurações, executar código.', 7.5, 'Alta', 'Atualizar o Apache para 2.4.51 ou superior.', '2021-10-05');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (13, 'CVE-2023-44487', 'HTTP/2 Rapid Reset: negação de serviço', 'Abuso do cancelamento de streams do HTTP/2 permite derrubar servidores web.', 7.5, 'Alta', 'Atualizar o servidor web e limitar resets de stream por conexão.', '2023-10-10');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (14, 'CVE-2018-0171', 'Cisco Smart Install: execução remota de código', 'Falha no recurso Smart Install do Cisco IOS/IOS XE permite executar código no switch.', 9.8, 'Crítica', 'Desativar o Smart Install (no vstack) e atualizar o IOS.', '2018-03-28');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (15, 'CVE-2023-20198', 'Cisco IOS XE: elevação de privilégio na interface web', 'Permite criar conta de administrador pela interface web sem autenticação.', 10.0, 'Crítica', 'Desativar o ip http server e atualizar o IOS XE.', '2023-10-16');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (16, 'CVE-2016-2183', 'SWEET32: cifra 3DES fraca em TLS', 'Uso de cifras de bloco de 64 bits permite recuperar dados em sessões longas.', 7.5, 'Alta', 'Desativar cifras 3DES/DES nos serviços TLS.', '2016-09-01');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (17, 'CVE-2023-48795', 'Terrapin: ataque de truncamento no SSH', 'Permite remover mensagens no início da sessão SSH e enfraquecer a segurança.', 5.9, 'Média', 'Atualizar o servidor SSH e desativar ChaCha20-Poly1305 e modos EtM vulneráveis.', '2023-12-18');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (18, 'CVE-2014-3566', 'POODLE: vulnerabilidade no SSL 3.0', 'Ataque de padding oracle permite decifrar dados em conexões SSL 3.0.', 3.4, 'Baixa', 'Desativar o SSL 3.0.', '2014-10-15');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (19, 'CVE-2017-15906', 'OpenSSH: criação de arquivos no modo somente leitura do SFTP', 'O sftp-server permite criar arquivos vazios mesmo em modo somente leitura.', 5.3, 'Média', 'Atualizar o OpenSSH para 7.6 ou superior.', '2017-10-26');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (20, 'CVE-2023-38408', 'OpenSSH: execução remota pelo ssh-agent (PKCS#11)', 'Agente SSH encaminhado pode ser usado para carregar bibliotecas e executar código.', 9.8, 'Crítica', 'Atualizar o OpenSSH para 9.3p2 ou superior.', '2023-07-20');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (21, 'CVE-2022-26134', 'Confluence: injeção OGNL com execução remota de código', 'Permite que atacante não autenticado execute código no Confluence Server.', 9.8, 'Crítica', 'Atualizar o Confluence para versão corrigida.', '2022-06-03');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (22, 'CVE-2021-26855', 'ProxyLogon: falsificação de requisição no Exchange', 'Falha SSRF no Exchange Server usada em cadeia para invadir servidores de e-mail.', 9.8, 'Crítica', 'Aplicar as atualizações de março/2021 do Exchange.', '2021-03-03');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (23, 'CVE-2022-22965', 'Spring4Shell: execução remota de código no Spring Framework', 'Falha de data binding em aplicações Spring MVC rodando no Tomcat com JDK 9+.', 9.8, 'Crítica', 'Atualizar o Spring Framework para 5.3.18 ou 5.2.20.', '2022-04-01');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (24, 'CVE-2023-4863', 'Estouro de buffer no libwebp (navegadores)', 'Imagem WebP maliciosa pode executar código no navegador.', 8.8, 'Alta', 'Atualizar Chrome, Edge e Firefox.', '2023-09-12');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (25, 'CVE-2023-36884', 'Execução remota de código via documentos do Office', 'Documento Office manipulado pode executar código ao ser aberto.', 8.8, 'Alta', 'Aplicar as atualizações do Office e do Windows de agosto/2023.', '2023-07-11');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (26, 'CVE-2024-21413', 'MonikerLink: execução remota de código no Outlook', 'Link manipulado em e-mail pode vazar credenciais NTLM e executar código.', 9.8, 'Crítica', 'Aplicar a atualização de fevereiro/2024 do Office.', '2024-02-13');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (27, 'CVE-2020-1938', 'Ghostcat: leitura de arquivos pelo conector AJP do Tomcat', 'O conector AJP permite ler arquivos da aplicação e, em alguns casos, executar código.', 9.8, 'Crítica', 'Desativar o conector AJP ou atualizar o Tomcat.', '2020-02-24');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (28, 'CVE-2019-0211', 'Apache HTTP Server: elevação de privilégio local', 'Processo filho com poucos privilégios pode executar código como root.', 7.8, 'Alta', 'Atualizar o Apache para 2.4.39 ou superior.', '2019-04-08');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (29, 'CVE-2015-4000', 'Logjam: rebaixamento do Diffie-Hellman em TLS', 'Permite forçar o uso de chaves DH de exportação fracas.', 3.7, 'Baixa', 'Desativar cifras DHE_EXPORT e usar grupos DH de 2048 bits.', '2015-05-21');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (30, 'CVE-2021-3449', 'OpenSSL: negação de serviço na renegociação TLS', 'Mensagem de renegociação manipulada derruba o servidor TLS.', 5.9, 'Média', 'Atualizar o OpenSSL para 1.1.1k ou superior.', '2021-03-25');
INSERT INTO public.vulnerabilidade (id_vulnerabilidade, cve, titulo, descricao, cvss, severidade, solucao, data_publicacao) VALUES (31, 'CVE-2018-15473', 'OpenSSH: enumeração de usuários', 'Permite descobrir quais nomes de usuário existem no servidor SSH.', 5.3, 'Média', 'Atualizar o OpenSSH para 7.8 ou superior.', '2018-08-17');


--
-- Name: ativo_id_ativo_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.ativo_id_ativo_seq', 32, true);


--
-- Name: auditoria_id_auditoria_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.auditoria_id_auditoria_seq', 1, false);


--
-- Name: ocorrencia_id_ocorrencia_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.ocorrencia_id_ocorrencia_seq', 106, true);


--
-- Name: responsavel_id_responsavel_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.responsavel_id_responsavel_seq', 7, true);


--
-- Name: setor_id_setor_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.setor_id_setor_seq', 8, true);


--
-- Name: usuario_id_usuario_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.usuario_id_usuario_seq', 2, true);


--
-- Name: varredura_id_varredura_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.varredura_id_varredura_seq', 8, true);


--
-- Name: vulnerabilidade_id_vulnerabilidade_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.vulnerabilidade_id_vulnerabilidade_seq', 31, true);


--
-- Name: ativo ativo_hostname_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ativo
    ADD CONSTRAINT ativo_hostname_key UNIQUE (hostname);


--
-- Name: ativo ativo_ip_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ativo
    ADD CONSTRAINT ativo_ip_key UNIQUE (ip);


--
-- Name: ativo ativo_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ativo
    ADD CONSTRAINT ativo_pkey PRIMARY KEY (id_ativo);


--
-- Name: auditoria auditoria_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auditoria
    ADD CONSTRAINT auditoria_pkey PRIMARY KEY (id_auditoria);


--
-- Name: ocorrencia ocorrencia_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ocorrencia
    ADD CONSTRAINT ocorrencia_pkey PRIMARY KEY (id_ocorrencia);


--
-- Name: responsavel responsavel_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.responsavel
    ADD CONSTRAINT responsavel_email_key UNIQUE (email);


--
-- Name: responsavel responsavel_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.responsavel
    ADD CONSTRAINT responsavel_pkey PRIMARY KEY (id_responsavel);


--
-- Name: setor setor_nome_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.setor
    ADD CONSTRAINT setor_nome_key UNIQUE (nome);


--
-- Name: setor setor_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.setor
    ADD CONSTRAINT setor_pkey PRIMARY KEY (id_setor);


--
-- Name: usuario usuario_login_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usuario
    ADD CONSTRAINT usuario_login_key UNIQUE (login);


--
-- Name: usuario usuario_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usuario
    ADD CONSTRAINT usuario_pkey PRIMARY KEY (id_usuario);


--
-- Name: varredura varredura_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.varredura
    ADD CONSTRAINT varredura_pkey PRIMARY KEY (id_varredura);


--
-- Name: vulnerabilidade vulnerabilidade_cve_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerabilidade
    ADD CONSTRAINT vulnerabilidade_cve_key UNIQUE (cve);


--
-- Name: vulnerabilidade vulnerabilidade_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerabilidade
    ADD CONSTRAINT vulnerabilidade_pkey PRIMARY KEY (id_vulnerabilidade);


--
-- Name: idx_ativo_score; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ativo_score ON public.ativo USING btree (score_risco DESC);


--
-- Name: idx_ativo_setor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ativo_setor ON public.ativo USING btree (id_setor);


--
-- Name: idx_auditoria_data; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_auditoria_data ON public.auditoria USING btree (data_hora DESC);


--
-- Name: idx_auditoria_tabela; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_auditoria_tabela ON public.auditoria USING btree (tabela, id_registro);


--
-- Name: idx_ocorrencia_ativo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ocorrencia_ativo ON public.ocorrencia USING btree (id_ativo);


--
-- Name: idx_ocorrencia_pendente_prazo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ocorrencia_pendente_prazo ON public.ocorrencia USING btree (prazo_correcao) WHERE ((status)::text = ANY ((ARRAY['Aberta'::character varying, 'Em correção'::character varying])::text[]));


--
-- Name: idx_ocorrencia_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ocorrencia_status ON public.ocorrencia USING btree (status);


--
-- Name: idx_ocorrencia_varred; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ocorrencia_varred ON public.ocorrencia USING btree (id_varredura);


--
-- Name: idx_ocorrencia_vuln; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ocorrencia_vuln ON public.ocorrencia USING btree (id_vulnerabilidade);


--
-- Name: idx_vulnerabilidade_severidade; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vulnerabilidade_severidade ON public.vulnerabilidade USING btree (severidade);


--
-- Name: uq_ocorrencia_pendente; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_ocorrencia_pendente ON public.ocorrencia USING btree (id_ativo, id_vulnerabilidade) WHERE ((status)::text = ANY ((ARRAY['Aberta'::character varying, 'Em correção'::character varying])::text[]));


--
-- Name: vw_ranking_ativos _RETURN; Type: RULE; Schema: public; Owner: -
--

CREATE OR REPLACE VIEW public.vw_ranking_ativos AS
 SELECT rank() OVER (ORDER BY a.score_risco DESC) AS posicao,
    a.id_ativo,
    a.hostname,
    a.ip,
    a.tipo,
    a.sistema_operacional,
    s.nome AS setor,
    r.nome AS responsavel,
    a.criticidade,
    a.score_risco,
    count(o.id_ocorrencia) AS pendentes,
    count(o.id_ocorrencia) FILTER (WHERE ((v.severidade)::text = 'Crítica'::text)) AS criticas,
    count(o.id_ocorrencia) FILTER (WHERE (o.prazo_correcao < CURRENT_DATE)) AS vencidas
   FROM ((((public.ativo a
     JOIN public.setor s ON ((s.id_setor = a.id_setor)))
     JOIN public.responsavel r ON ((r.id_responsavel = a.id_responsavel)))
     LEFT JOIN public.ocorrencia o ON (((o.id_ativo = a.id_ativo) AND ((o.status)::text = ANY ((ARRAY['Aberta'::character varying, 'Em correção'::character varying])::text[])))))
     LEFT JOIN public.vulnerabilidade v ON ((v.id_vulnerabilidade = o.id_vulnerabilidade)))
  WHERE ((a.situacao)::text = 'Ativo'::text)
  GROUP BY a.id_ativo, s.nome, r.nome;


--
-- Name: vw_vulnerabilidades_frequentes _RETURN; Type: RULE; Schema: public; Owner: -
--

CREATE OR REPLACE VIEW public.vw_vulnerabilidades_frequentes AS
 SELECT v.cve,
    v.titulo,
    v.cvss,
    v.severidade,
    count(o.id_ocorrencia) AS total_deteccoes,
    count(o.id_ocorrencia) FILTER (WHERE ((o.status)::text = ANY ((ARRAY['Aberta'::character varying, 'Em correção'::character varying])::text[]))) AS ativos_afetados_hoje
   FROM (public.vulnerabilidade v
     LEFT JOIN public.ocorrencia o ON ((o.id_vulnerabilidade = v.id_vulnerabilidade)))
  GROUP BY v.id_vulnerabilidade;


--
-- Name: ativo trg_auditoria_ativo; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_auditoria_ativo AFTER INSERT OR DELETE OR UPDATE ON public.ativo FOR EACH ROW EXECUTE FUNCTION public.trg_fn_auditoria('id_ativo');


--
-- Name: ocorrencia trg_auditoria_ocorrencia; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_auditoria_ocorrencia AFTER INSERT OR DELETE OR UPDATE ON public.ocorrencia FOR EACH ROW EXECUTE FUNCTION public.trg_fn_auditoria('id_ocorrencia');


--
-- Name: usuario trg_auditoria_usuario; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_auditoria_usuario AFTER INSERT OR DELETE OR UPDATE ON public.usuario FOR EACH ROW EXECUTE FUNCTION public.trg_fn_auditoria('id_usuario');


--
-- Name: vulnerabilidade trg_auditoria_vulnerabilidade; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_auditoria_vulnerabilidade AFTER INSERT OR DELETE OR UPDATE ON public.vulnerabilidade FOR EACH ROW EXECUTE FUNCTION public.trg_fn_auditoria('id_vulnerabilidade');


--
-- Name: ativo trg_criticidade_ativo; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_criticidade_ativo BEFORE UPDATE OF criticidade ON public.ativo FOR EACH ROW EXECUTE FUNCTION public.trg_fn_criticidade_ativo();


--
-- Name: vulnerabilidade trg_definir_severidade; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_definir_severidade BEFORE INSERT OR UPDATE OF cvss ON public.vulnerabilidade FOR EACH ROW EXECUTE FUNCTION public.trg_fn_definir_severidade();


--
-- Name: ocorrencia trg_recalcular_risco; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_recalcular_risco AFTER INSERT OR DELETE OR UPDATE ON public.ocorrencia FOR EACH ROW EXECUTE FUNCTION public.trg_fn_recalcular_risco();


--
-- Name: ocorrencia trg_regras_ocorrencia; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_regras_ocorrencia BEFORE INSERT OR UPDATE ON public.ocorrencia FOR EACH ROW EXECUTE FUNCTION public.trg_fn_regras_ocorrencia();


--
-- Name: ativo ativo_id_responsavel_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ativo
    ADD CONSTRAINT ativo_id_responsavel_fkey FOREIGN KEY (id_responsavel) REFERENCES public.responsavel(id_responsavel);


--
-- Name: ativo ativo_id_setor_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ativo
    ADD CONSTRAINT ativo_id_setor_fkey FOREIGN KEY (id_setor) REFERENCES public.setor(id_setor);


--
-- Name: ocorrencia ocorrencia_id_ativo_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ocorrencia
    ADD CONSTRAINT ocorrencia_id_ativo_fkey FOREIGN KEY (id_ativo) REFERENCES public.ativo(id_ativo) ON DELETE CASCADE;


--
-- Name: ocorrencia ocorrencia_id_varredura_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ocorrencia
    ADD CONSTRAINT ocorrencia_id_varredura_fkey FOREIGN KEY (id_varredura) REFERENCES public.varredura(id_varredura);


--
-- Name: ocorrencia ocorrencia_id_vulnerabilidade_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ocorrencia
    ADD CONSTRAINT ocorrencia_id_vulnerabilidade_fkey FOREIGN KEY (id_vulnerabilidade) REFERENCES public.vulnerabilidade(id_vulnerabilidade);


--
-- Name: responsavel responsavel_id_setor_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.responsavel
    ADD CONSTRAINT responsavel_id_setor_fkey FOREIGN KEY (id_setor) REFERENCES public.setor(id_setor);


--
-- Name: varredura varredura_id_responsavel_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.varredura
    ADD CONSTRAINT varredura_id_responsavel_fkey FOREIGN KEY (id_responsavel) REFERENCES public.responsavel(id_responsavel);


--
-- PostgreSQL database dump complete
--

