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
