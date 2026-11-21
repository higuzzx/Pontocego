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
