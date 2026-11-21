-- =====================================================================
-- Script 07: exemplos de sentenças para o artigo e a apresentação
-- (cadastro, consulta, alteração, exclusão, relacionamentos,
--  uso das views, procedures e otimização)
-- Rode depois dos scripts 01 a 06.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. CADASTRO (INSERT)
-- ---------------------------------------------------------------------

-- 1.1 Cadastrar um novo ativo
INSERT INTO ativo (hostname, ip, tipo, sistema_operacional, criticidade, id_setor, id_responsavel)
VALUES ('srv-moodle01', '10.10.2.50', 'Servidor', 'Ubuntu 22.04 (Moodle 4.1)', 4,
        (SELECT id_setor FROM setor WHERE nome = 'DTI - Sistemas'),
        (SELECT id_responsavel FROM responsavel WHERE email = 'larissa.prates@sgva.exemplo.br'));

-- 1.2 Cadastrar uma vulnerabilidade (a severidade é preenchida pela trigger)
INSERT INTO vulnerabilidade (cve, titulo, cvss, solucao, data_publicacao)
VALUES ('CVE-2023-25690', 'Apache HTTP Server: HTTP request smuggling no mod_proxy',
        9.8, 'Atualizar o Apache para 2.4.56 ou superior.', '2023-03-07');

-- Confere: a severidade foi calculada como 'Crítica'
SELECT cve, cvss, severidade FROM vulnerabilidade WHERE cve = 'CVE-2023-25690';

-- 1.3 Registrar uma varredura
INSERT INTO varredura (data_varredura, ferramenta, escopo, observacao, id_responsavel)
VALUES (CURRENT_DATE, 'OpenVAS', '10.10.2.0/24', 'Varredura de demonstração.',
        (SELECT id_responsavel FROM responsavel WHERE email = 'camila.duarte@sgva.exemplo.br'));

-- 1.4 Registrar ocorrência pela STORED PROCEDURE
-- O CALL não aceita subconsulta nos parâmetros, então primeiro
-- descobrimos os ids (no banco recém-criado: ativo 33 e varredura 9)
SELECT id_ativo FROM ativo WHERE hostname = 'srv-moodle01';
SELECT MAX(id_varredura) FROM varredura;

CALL sp_registrar_ocorrencia(33, 'CVE-2023-25690', 9, NULL);

-- Chamando de novo: a procedure percebe que já existe e não duplica
CALL sp_registrar_ocorrencia(33, 'CVE-2023-25690', 9, NULL);

-- Confere: prazo calculado (7 dias, pois é crítica) e score do ativo atualizado
SELECT o.id_ocorrencia, o.data_deteccao, o.prazo_correcao, a.score_risco
  FROM ocorrencia o JOIN ativo a ON a.id_ativo = o.id_ativo
 WHERE a.hostname = 'srv-moodle01';


-- ---------------------------------------------------------------------
-- 2. CONSULTAS (SELECT), incluindo listagens de relacionamentos
-- ---------------------------------------------------------------------

-- 2.1 Listar todos os ativos de um setor
SELECT hostname, ip, tipo, sistema_operacional, criticidade, score_risco
  FROM ativo
 WHERE id_setor = (SELECT id_setor FROM setor WHERE nome = 'DTI - Sistemas')
 ORDER BY score_risco DESC;

-- 2.2 Relacionamento ativo x setor x responsável
SELECT a.hostname, a.ip, s.nome AS setor, r.nome AS responsavel, r.email
  FROM ativo a
  JOIN setor s       ON s.id_setor = a.id_setor
  JOIN responsavel r ON r.id_responsavel = a.id_responsavel
 ORDER BY s.nome, a.hostname;

-- 2.3 Relacionamento completo: histórico de vulnerabilidades de um ativo
SELECT v.cve, v.titulo, v.severidade, vr.ferramenta, o.data_deteccao,
       o.prazo_correcao, o.status, o.data_correcao
  FROM ocorrencia o
  JOIN vulnerabilidade v ON v.id_vulnerabilidade = o.id_vulnerabilidade
  JOIN varredura vr      ON vr.id_varredura = o.id_varredura
  JOIN ativo a           ON a.id_ativo = o.id_ativo
 WHERE a.hostname = 'srv-academico01'
 ORDER BY o.data_deteccao DESC;

-- 2.4 Quantas ocorrências cada varredura encontrou
SELECT vr.data_varredura, vr.ferramenta, r.nome AS executada_por,
       COUNT(o.id_ocorrencia) AS ocorrencias_encontradas
  FROM varredura vr
  JOIN responsavel r     ON r.id_responsavel = vr.id_responsavel
  LEFT JOIN ocorrencia o ON o.id_varredura = vr.id_varredura
 GROUP BY vr.id_varredura, r.nome
 ORDER BY vr.data_varredura;

-- 2.5 Usando as VIEWS
SELECT * FROM vw_ranking_ativos WHERE posicao <= 10;
SELECT * FROM vw_ocorrencias_vencidas ORDER BY dias_de_atraso DESC;
SELECT * FROM vw_resumo_setor ORDER BY total_pendentes DESC;
SELECT * FROM vw_tempo_medio_correcao;
SELECT * FROM vw_vulnerabilidades_frequentes ORDER BY ativos_afetados_hoje DESC LIMIT 10;


-- ---------------------------------------------------------------------
-- 3. ALTERAÇÃO (UPDATE)
-- ---------------------------------------------------------------------

-- 3.1 Colocar uma ocorrência "Em correção"
--     (no banco recém-criado, a ocorrência registrada no item 1.4 é a 107)
UPDATE ocorrencia
   SET status = 'Em correção',
       observacao = 'Patch agendado para a próxima janela de manutenção.'
 WHERE id_ocorrencia = 107;

-- 3.2 Fechar a ocorrência pela STORED PROCEDURE
--     (a trigger preenche data_correcao e recalcula o score do ativo)
CALL sp_fechar_ocorrencia(107, 'Apache atualizado para 2.4.58.', NULL, NULL);

-- Confere: status, data de correção e score do ativo (voltou a 0)
SELECT o.status, o.data_correcao, a.score_risco
  FROM ocorrencia o JOIN ativo a ON a.id_ativo = o.id_ativo
 WHERE o.id_ocorrencia = 107;

-- 3.3 Alterar a criticidade de um ativo (a trigger refaz o score)
UPDATE ativo SET criticidade = 5 WHERE hostname = 'srv-portal02';

-- 3.4 Corrigir o CVSS de uma vulnerabilidade (a trigger refaz a severidade)
UPDATE vulnerabilidade SET cvss = 7.5 WHERE cve = 'CVE-2023-25690';


-- ---------------------------------------------------------------------
-- 4. EXCLUSÃO (DELETE)
-- ---------------------------------------------------------------------

-- 4.1 Excluir o ativo de demonstração
--     (ON DELETE CASCADE apaga as ocorrências dele junto)
DELETE FROM ativo WHERE hostname = 'srv-moodle01';

-- 4.2 Excluir a vulnerabilidade de demonstração
DELETE FROM vulnerabilidade WHERE cve = 'CVE-2023-25690';

-- 4.3 Excluir varreduras sem nenhuma ocorrência registrada
DELETE FROM varredura vr
 WHERE NOT EXISTS (SELECT 1 FROM ocorrencia o WHERE o.id_varredura = vr.id_varredura)
   AND vr.observacao = 'Varredura de demonstração.';


-- ---------------------------------------------------------------------
-- 5. AUDITORIA: tudo que foi feito acima ficou registrado pela trigger
-- ---------------------------------------------------------------------
SELECT data_hora, usuario_app, usuario_bd, tabela, operacao, id_registro
  FROM auditoria
 ORDER BY data_hora DESC, id_auditoria DESC;


-- ---------------------------------------------------------------------
-- 6. OTIMIZAÇÃO: comparar o plano de execução com e sem índice
-- ---------------------------------------------------------------------
-- Com poucos dados o PostgreSQL pode preferir ler a tabela inteira
-- (Seq Scan) porque é mais barato. Para ver o índice parcial em ação
-- numa tabela pequena, desligamos temporariamente a leitura sequencial:
SET enable_seqscan = off;
EXPLAIN ANALYZE
SELECT id_ocorrencia, prazo_correcao
  FROM ocorrencia
 WHERE status IN ('Aberta', 'Em correção')
   AND prazo_correcao < CURRENT_DATE;
RESET enable_seqscan;
