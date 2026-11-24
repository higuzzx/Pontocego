# Ponto Cego: Sistema de Gestão de Vulnerabilidades de Ativos

Trabalho de Banco de Dados II (Seminário II), Sistemas de Informação, Unimontes.

O sistema registra os ativos de TI de uma organização (servidores, estações, switches...), o catálogo de vulnerabilidades (CVEs), as varreduras feitas com scanners como OpenVAS e Nmap e as ocorrências encontradas em cada ativo. A partir disso ele calcula automaticamente o prazo de correção de cada falha, o score de risco de cada ativo e mostra o que está atrasado.

**Tecnologias:** PostgreSQL + Python (Streamlit, psycopg2, Plotly).

---

## Estrutura das pastas

```
gestao-vulnerabilidades/
├── sql/
│   ├── 01_tabelas.sql            criação das 8 tabelas
│   ├── 02_funcoes_triggers.sql   funções e as 5 triggers
│   ├── 03_procedures.sql         2 stored procedures
│   ├── 04_views.sql              6 views
│   ├── 05_indices.sql            11 índices
│   ├── 06_dados_exemplo.sql      dados fictícios para testes + usuários iniciais
│   ├── 07_consultas_exemplo.sql  exemplos de INSERT, SELECT, UPDATE, DELETE, CALL e EXPLAIN
│   ├── banco_completo.sql        scripts 01 a 06 juntos num arquivo só
│   └── dump_gestao_vulnerabilidades.sql  dump (pg_dump) do banco pronto, para restaurar
├── app/
│   ├── app.py                    interface (todas as telas)
│   ├── db.py                     funções de acesso ao banco
│   ├── especialista.py           sistema especialista de triagem (regras SSVC, motor e autoteste)
│   ├── auth.py                   login: hash de senha (PBKDF2) e autenticação
│   ├── config.py                 dados de conexão (SENHA DO POSTGRES AQUI)
│   └── assets/                   logo oficial do Ponto Cego (PNG com fundo transparente)
├── apresentacao/
│   └── apresentacao_sgva.html    slides (abra no navegador; setas do teclado passam)
├── docs/diagramas/
│   ├── der_conceitual_*.png/svg  DER conceitual com cardinalidades 1:N e N:N
│   └── der_logico_*.png/svg      modelo lógico com tabelas, tipos, PK e FK
│                                 (versão "claro" para o artigo, "escuro" para tela)
├── .streamlit/config.toml        tema visual da interface (paleta Ponto Cego)
├── instalar_banco.py             cria o banco e carrega tudo automaticamente
└── requirements.txt              bibliotecas Python
```

### Apresentação
Abra `apresentacao/apresentacao_sgva.html` em qualquer navegador e aperte **F11** para tela cheia. Passe os slides com as **setas**, **Page Up/Down** ou pelos pontinhos à direita. As fontes e imagens estão dentro do arquivo, então funciona sem internet.

---

## Como rodar (Windows)

### 1. Instalar o PostgreSQL
Baixe em https://www.postgresql.org/download/windows/ (instalador da EDB, versão 14 ou mais nova). Durante a instalação, **anote a senha** que você definir para o usuário `postgres`. Pode deixar a porta padrão 5432.

### 2. Instalar o Python
Baixe em https://www.python.org/downloads/ (3.10 ou mais novo). Na instalação, marque **"Add python.exe to PATH"**.

### 3. Instalar as bibliotecas
Abra o terminal (PowerShell ou CMD) dentro da pasta do projeto e rode:
```
pip install -r requirements.txt
```

### 4. Colocar a senha do banco
Abra `app/config.py` e troque `"postgres"` na linha da senha pela senha do passo 1.

### 5. Criar o banco com os dados de exemplo
```
python instalar_banco.py
```
Isso cria o banco `gestao_vulnerabilidades`, as tabelas, triggers, procedures, views, índices e carrega os dados de teste. **Pode rodar de novo sempre que quiser voltar ao estado inicial** (útil antes da apresentação).

### 6. Abrir o sistema
```
streamlit run app/app.py
```
O navegador abre sozinho em http://localhost:8501.

### 7. Entrar no sistema
| Usuário | Senha | Perfil |
|---|---|---|
| `admin` | `admin` | Administrador |
| `higor` | `admin` | Administrador |

Troque essas senhas em **Minha conta** depois do primeiro acesso. Administradores cadastram outros usuários na página **Usuários** (perfil Administrador ou Analista; o Analista só não gerencia usuários).

### Alternativa: restaurar o dump (sem Python)
O arquivo `sql/dump_gestao_vulnerabilidades.sql` é o banco já pronto (estrutura, dados de exemplo e os usuários acima), gerado com `pg_dump`.

- **pgAdmin:** crie um banco chamado `gestao_vulnerabilidades`, abra o Query Tool nele, carregue `sql/dump_gestao_vulnerabilidades.sql` e execute (F5).
- **Terminal:**
  ```
  createdb -U postgres gestao_vulnerabilidades
  psql -U postgres -d gestao_vulnerabilidades -f sql/dump_gestao_vulnerabilidades.sql
  ```

O dump pode ser rodado de novo no mesmo banco para voltar ao estado inicial (ele apaga e recria tudo).

---

## O que tem no banco

| Recurso | Quantidade | Onde |
|---|---|---|
| Tabelas | 8 (setor, responsavel, ativo, vulnerabilidade, varredura, ocorrencia, usuario, auditoria) | `01_tabelas.sql` |
| Triggers | 5 | `02_funcoes_triggers.sql` |
| Stored procedures | 2 | `03_procedures.sql` |
| Views | 6 | `04_views.sql` |
| Índices | 11 (incluindo 2 índices parciais) | `05_indices.sql` |

### Triggers (automatizações)
1. **trg_definir_severidade**: ao cadastrar ou mudar o CVSS de uma vulnerabilidade, a severidade (Crítica, Alta, Média, Baixa) é definida sozinha.
2. **trg_regras_ocorrencia**: ao registrar uma ocorrência, calcula o prazo de correção pela severidade (Crítica 7 dias, Alta 30, Média 90, Baixa 180). Quando o status vira "Corrigida", preenche a data de correção.
3. **trg_recalcular_risco**: sempre que uma ocorrência entra, muda ou sai, recalcula o score de risco do ativo.
4. **trg_criticidade_ativo**: se a criticidade do ativo mudar, o score é refeito.
5. **trg_auditoria_*** (em 4 tabelas: ativo, vulnerabilidade, ocorrencia e usuario): grava na tabela `auditoria` toda inclusão, alteração e exclusão, com os dados de antes e depois em JSON e o **login de quem fez** (`usuario_app`). A aplicação passa o login para o banco com `set_config('app.usuario', ...)` em cada transação, e a trigger lê com `current_setting`. O hash da senha nunca vai para o log.

**Fórmula do score de risco:** soma das notas CVSS das ocorrências pendentes × (criticidade ÷ 5).

### Stored procedures
- **sp_registrar_ocorrencia**: registra uma ocorrência pelo código CVE, não deixa duplicar e marca reincidência quando a falha já tinha sido corrigida antes.
- **sp_fechar_ocorrencia**: marca como corrigida e devolve quantos dias levou e se foi dentro do prazo.

### Views
`vw_ocorrencias_pendentes`, `vw_ocorrencias_vencidas`, `vw_ranking_ativos`, `vw_resumo_setor`, `vw_tempo_medio_correcao`, `vw_vulnerabilidades_frequentes`.

---

## Roteiro sugerido para a demonstração

0. **Login**: entre como `higor` / `admin`.
1. **Painel**: mostre os indicadores, o gráfico por setor e o ranking de risco. Clique em **Ver detalhes e tratar** no alerta, ou em uma linha da tabela de vencidas, para abrir a ocorrência.
2. **Ocorrências > Registrar nova**: escolha `srv-bd01` + `CVE-2021-44228` (Log4Shell). Aparece o prazo calculado pela trigger e o score do ativo subindo. Clique de novo: a procedure avisa que já existe.
3. **Ocorrências > Pendentes**: clique na linha dessa ocorrência e feche pela janela que abre. A procedure diz quantos dias levou e o score do ativo cai.
4. **Vulnerabilidades > Cadastrar**: cadastre uma CVE com CVSS 9.8 e mostre que a severidade "Crítica" veio da trigger. Depois edite o CVSS para 6.0 e veja virar "Média".
5. **Vulnerabilidades > Excluir**: tente excluir a Log4Shell. O banco bloqueia por causa da chave estrangeira.
6. **Ativos > Editar**: mude a criticidade do `srv-academico01` e mostre o score sendo refeito.
7. **Auditoria**: tudo que foi feito acima aparece registrado, com o antes e depois e o usuário que fez (filtre por **Usuário**).
8. **Relatórios > Otimização**: rode o EXPLAIN ANALYZE e mostre o índice parcial sendo usado.
9. **Sistema especialista**: abra a ocorrência `sw-biblioteca01` + `CVE-2014-3566` e clique em **Analisar com o especialista**. Abra o **Por quê?** de uma pergunta, responda, veja o **Como?** e aceite o risco com a justificativa gerada (detalhes na seção abaixo).

Todas as telas têm o botão **"Ver SQL executado"**, que mostra a sentença usada.

---

## Sistema especialista: triagem e priorização de vulnerabilidades

Responde à pergunta: **"Para esta ocorrência, o que fazer e com que urgência?"** Usa o mesmo banco e a mesma interface do Ponto Cego. O botão **Analisar com o especialista** fica na ficha de toda ocorrência pendente: na janela que abre ao clicar numa ocorrência e em **Ocorrências > Atualizar ou fechar**.

**Base teórica:** SSVC (*Stakeholder-Specific Vulnerability Categorization*) da CISA, a árvore de decisão que analistas usam para priorizar vulnerabilidades. Ela combina 4 pontos de decisão (exploração, automatizável, impacto técnico e impacto na missão e bem-estar) e chega a uma de 4 decisões: **Track**, **Track\***, **Attend** ou **Act**. As 36 folhas da árvore viraram as regras S01 a S36, conferidas com a tabela oficial da CISA publicada pelo CERT/CC (`cisa_coordinator_2_0_3.csv`). A combinação de prevalência na missão com bem-estar segue a Tabela 8 do guia.

### Componentes

| Componente | Onde fica (`app/especialista.py`) |
|---|---|
| Base de fatos (memória de trabalho) | `Motor.fatos`: fatos do banco, respostas do usuário e fatos inferidos |
| Base de conhecimento | `REGRAS`: 63 regras SE ... ENTÃO ..., cada uma com fator de certeza (FC) de 0 a 1 |
| Motor de inferência | `Motor`: **encadeamento para trás**. Parte dos objetivos (decisão e ação) e só pergunta o que alguma regra precisa. Como no MYCIN, antes de avaliar uma regra ele a descarta se alguma premissa já conhecida é falsa, para não fazer perguntas inúteis |
| Incerteza | Fatores de certeza do MYCIN |
| Explicação | **Por quê?** em cada pergunta e **Como?** no resultado |
| Interface | `painel_especialista()` em `app/app.py` |

### Fatos

- **Lidos do banco** (consulta `SQL_FATOS_ESPECIALISTA` em `app.py`): CVSS, severidade, criticidade, tipo, sistema operacional, setor, status, dias em aberto, prazo vencido e reincidência (o mesmo CVE já foi corrigido antes no mesmo ativo).
- **Perguntados ao usuário**: o ativo fica exposto à internet? Há exploit público ou a falha está no catálogo KEV? A exploração pode ser automatizada? Existe patch? O ativo guarda dados pessoais (LGPD)?
- **Perguntados só se as regras não resolvem**: o impacto técnico é perguntado só quando o CVSS fica entre 7,0 e 8,9 (com 9 ou mais, a regra I01 conclui Total; abaixo de 7, a I02 conclui Parcial). Os dados pessoais não são perguntados nos setores Financeiro, Recursos Humanos e Secretaria Acadêmica (regra I06), nem quando nenhuma regra precisa deles.
- **"Não sei"**: o sistema assume o pior caso plausível com FC 0,5, e a certeza do resultado cai.

### Regras

| Grupo | O que fazem |
|---|---|
| I01 a I13 (inferência) | Impacto técnico pelo CVSS, prevalência na missão pela criticidade, dados pessoais pelo setor, bem-estar pela LGPD, Tabela 8 da CISA, SO fora de suporte |
| S01 a S36 (árvore SSVC) | `SE exploração E automatizável E impacto técnico E impacto na missão ENTÃO decisão SSVC` |
| D01 a D03 (decisão) | **D01**: exploit ativo + exposto à internet + criticidade ≥ 4 → Act (FC 0,95). **D02**: reincidente → um nível acima da decisão SSVC (FC 0,9). **D03**: senão, vale a decisão da árvore |
| A01 a A11 (ações) | Aplicar o patch; **A02**: sem patch em servidor → controle compensatório (segmentação ou WAF, FC 0,8); restringir o acesso externo; procurar sinais de invasão; **A06**: reincidente → revisar o processo de patch; avisar o DPO (LGPD); trocar o SO sem suporte; escalar prazo vencido; **A11**: severidade Baixa + não exposto + criticidade ≤ 2 → aceitar o risco e monitorar (FC 0,7) |

A lista completa, com a justificativa de cada regra, aparece na tela em **Base de conhecimento**.

### Fatores de certeza

- Premissas ligadas por E: vale o **menor** FC.
- Conclusão: FC da regra × FC das premissas. Ex.: A11 (0,7) × decisão Track inferida com 0,8 = **0,56**.
- Duas regras com a mesma conclusão: FC1 + FC2 × (1 − FC1).
- Abaixo de 0,2 o fato conta como desconhecido.
- **Resolução de conflito**: quando regras concluem decisões diferentes, prevalece a mais urgente (princípio da precaução). Ex.: a árvore dá Attend, mas a falha é reincidente, então D02 sobe para Act.

### O que ele entrega

- **Decisão SSVC** e **grau de certeza**.
- **Prazo sugerido**: Act, até 2 dias; Attend, metade do prazo padrão da severidade; Track e Track\*, o prazo que a trigger já calculou (se já venceu, replaneja para 30 dias). Nunca passa do prazo do banco enquanto ele não vence.
- **Ações recomendadas**, cada uma com seu FC.
- **Como?**: regras disparadas na ordem, com a conta do FC, e a memória de trabalho (cada fato e de onde veio: banco, resposta ou regra).
- **Por quê?**: a cadeia de regras que levou à pergunta, até o objetivo, com ✓ (premissa confirmada), ✗ (falsa) e ? (ainda não sei).
- **Risco aceito**: quando a regra A11 recomenda aceitar o risco, aparece a justificativa gerada (dá para editar) e o botão que grava o status **Risco aceito** com ela. A alteração fica na auditoria com o login de quem aceitou.

### Exemplos com os dados de exemplo

| Ocorrência | Respostas | Resultado |
|---|---|---|
| `srv-portal01` + CVE-2021-41773 | exploração ativa (KEV), exposto, automatizável, impacto parcial, tem patch, tem dados pessoais | **Act** (D01 e árvore), 100%, prazo de 2 dias; avisar o DPO, restringir o acesso externo, escalar o prazo vencido, trocar o Ubuntu 20.04 |
| `lab-ccet-02` + CVE-2017-0144 (EternalBlue, reincidente) | exploração ativa, não exposto, automatizável, impacto total, sem dados pessoais, tem patch | A árvore dá **Attend**; a reincidência (D02) sobe para **Act**, 90%; revisar o processo de patch e trocar o Windows 7 |
| `sw-biblioteca01` + CVE-2014-3566 (POODLE) | PoC pública, não automatizável, sem dados pessoais, tem patch, não exposto | **Track**, 80%, prazo do banco; recomenda aceitar o risco (56%) e libera o botão **Risco aceito** |

### Autoteste

O motor não depende do Streamlit nem do banco. Para conferir as regras do enunciado, a árvore e os prazos:
```
python app/especialista.py
```

### Referências

- CISA. *Stakeholder-Specific Vulnerability Categorization Guide*. Cybersecurity and Infrastructure Security Agency, nov. 2022.
- CERT/CC. *SSVC: Stakeholder-Specific Vulnerability Categorization*. Tabela `data/csv/cisa/cisa_coordinator_2_0_3.csv`. Disponível em: https://github.com/CERTCC/SSVC.
- SHORTLIFFE, E. H.; BUCHANAN, B. G. A model of inexact reasoning in medicine. *Mathematical Biosciences*, v. 23, n. 3-4, p. 351-379, 1975.

---

## Sobre os dados de exemplo
As CVEs são reais (catálogo público do NVD, notas CVSS v3). Ativos, pessoas, setores e ocorrências são **fictícios**, gerados só para teste. A data de referência dos dados é novembro de 2026, então os prazos "vencidos" fazem sentido nessa época.

---

## Problemas comuns
- **`UnicodeDecodeError` ou erro de autenticação ao conectar:** quase sempre é senha errada em `app/config.py`.
- **`'streamlit' não é reconhecido`:** use `python -m streamlit run app/app.py`.
- **`'pip' não é reconhecido`:** use `python -m pip install -r requirements.txt`.
- **Porta 5432 diferente:** ajuste `PGPORT` em `app/config.py`.
- **Erro ao entrar ("relation usuario does not exist"):** o banco é de uma versão antiga, sem a tabela de usuários. Rode `python instalar_banco.py` de novo ou restaure o dump.
