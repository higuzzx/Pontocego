"""Sistema especialista de triagem e priorização de vulnerabilidades do Ponto Cego.

Pergunta que ele responde: "Para esta ocorrência, o que fazer e com que urgência?"

Base teórica: SSVC (Stakeholder-Specific Vulnerability Categorization) da CISA, guia de novembro de 2022.
As 36 folhas da árvore de decisão da CISA viram 36 regras de produção (S01 a S36). As outras regras
representam o conhecimento de um analista de segurança: inferem fatos a partir do banco (I), ajustam a
decisão (D) e recomendam ações (A).

Partes de um sistema especialista e onde estão aqui:
- base de fatos (memória de trabalho): Motor.fatos, com os fatos do banco, as respostas e o que foi inferido;
- base de conhecimento: REGRAS (SE ... ENTÃO ..., cada uma com fator de certeza de 0 a 1);
- motor de inferência: Motor, por encadeamento para trás; parte dos OBJETIVOS e só pergunta o que precisa;
- incerteza: fatores de certeza do MYCIN (premissas ligadas por E valem o menor FC; a conclusão vale
  FC da regra x FC das premissas; duas regras com a mesma conclusão somam FC1 + FC2 x (1 - FC1));
- explicações: porque() responde "Por quê?"; Motor.disparadas e Motor.memoria() respondem "Como?".

O módulo não depende do Streamlit nem do banco: recebe a ocorrência num dicionário (veja app.py).
Autoteste:  python app/especialista.py
"""
from collections import namedtuple
from datetime import timedelta
from itertools import product

LIMIAR = 0.2      # fato com FC abaixo disso conta como desconhecido (mesmo limiar do MYCIN)
FC_NAO_SEI = 0.5  # certeza do valor assumido quando o usuário responde "Não sei"
NIVEIS = ["Track", "Track*", "Attend", "Act"]  # decisões do SSVC, da menos para a mais urgente
OBJETIVOS = ("decisao", "acao")                # o que o motor tenta provar, nesta ordem

Regra = namedtuple("Regra", "id se entao fc nota")
Pergunta = namedtuple("Pergunta", "texto ajuda opcoes nao_sei")

NOMES = {
    "cvss": "CVSS", "severidade": "severidade", "criticidade": "criticidade do ativo", "tipo": "tipo do ativo",
    "sistema_operacional": "sistema operacional", "setor": "setor", "status": "status",
    "dias_aberto": "dias em aberto", "reincidente": "reincidente", "prazo_vencido": "prazo vencido",
    "exploracao": "exploração", "automatizavel": "automatizável", "exposto": "exposto à internet",
    "patch": "existe patch", "dados_pessoais": "dados pessoais (LGPD)", "impacto_tecnico": "impacto técnico",
    "prevalencia": "prevalência na missão", "bem_estar": "impacto no bem-estar",
    "impacto_missao": "impacto na missão e bem-estar", "so_sem_suporte": "SO sem suporte",
    "decisao_ssvc": "decisão da árvore SSVC", "decisao": "decisão", "acao": "ação",
}

OPERADORES = {
    "=": lambda v, a: v == a,
    "≠": lambda v, a: v != a,
    "≥": lambda v, a: v >= a,
    "≤": lambda v, a: v <= a,
    "<": lambda v, a: v < a,
    "∈": lambda v, a: v in a,
    "contém": lambda v, a: any(p.lower() in str(v).lower() for p in a),
    "é conhecida": lambda v, a: True,  # basta o fato ter valor
}

# Árvore SSVC da CISA (guia de nov/2022; tabela "CISA Coordinator" v2.0.3 do CERT/CC).
# Para cada exploração, 4 linhas: automatizável Não/Parcial, Não/Total, Sim/Parcial, Sim/Total.
# As 3 colunas de cada linha são o impacto na missão e bem-estar Baixo, Médio e Alto.
FOLHAS_SSVC = {
    "Nenhuma": ["Track Track Track", "Track Track Track*", "Track Track Attend", "Track Track Attend"],
    "PoC": ["Track Track Track*", "Track Track* Attend", "Track Track Attend", "Track Track* Attend"],
    "Ativa": ["Track Track Attend", "Track Attend Act", "Attend Attend Act", "Attend Act Act"],
}


def _regras_ssvc():
    regras = []
    for exploracao, linhas in FOLHAS_SSVC.items():
        for (auto, tecnico), linha in zip(product(("Não", "Sim"), ("Parcial", "Total")), linhas):
            for missao, decisao in zip(("Baixo", "Médio", "Alto"), linha.split()):
                regras.append(Regra(
                    "S%02d" % (len(regras) + 1),
                    (("exploracao", "=", exploracao), ("automatizavel", "=", auto),
                     ("impacto_tecnico", "=", tecnico), ("impacto_missao", "=", missao)),
                    ("decisao_ssvc", decisao), 1.0, "Folha %d da árvore de decisão SSVC da CISA." % (len(regras) + 1)))
    return regras


def um_nivel_acima(motor):
    """um nível acima da decisão SSVC"""
    return NIVEIS[min(NIVEIS.index(motor.valor("decisao_ssvc")[0]) + 1, len(NIVEIS) - 1)]


def decisao_da_arvore(motor):
    """a decisão da árvore SSVC"""
    return motor.valor("decisao_ssvc")[0]


# shortcut: lista fixa de SOs fora do suporte padrão em nov/2026 (data dos dados de exemplo); revisar se a data mudar
SO_SEM_SUPORTE = ("Windows 7", "Windows 10", "Windows 11 23H2", "Windows Server 2008", "CentOS 6", "CentOS 7",
                  "Ubuntu 18.04", "Ubuntu 20.04", "Debian 11")
SETORES_DADOS_PESSOAIS = ("Financeiro", "Recursos Humanos", "Secretaria Acadêmica")
ACEITAR = "Aceitar o risco e monitorar nas próximas varreduras."

REGRAS = [
    # ----- I: inferência de fatos a partir do banco -----
    Regra("I01", (("cvss", "≥", 9.0),), ("impacto_tecnico", "Total"), 0.9,
          "Nota 9 ou mais quase sempre vem de falha que dá controle total (ex.: execução remota de código sem login)."),
    Regra("I02", (("cvss", "<", 7.0),), ("impacto_tecnico", "Parcial"), 0.8,
          "Abaixo de 7 o impacto costuma ser limitado. Entre 7 e 8,9 nenhuma regra decide e o sistema pergunta."),
    Regra("I03", (("criticidade", "≥", 4),), ("prevalencia", "Essencial"), 1.0,
          "Criticidade 4 e 5: o ativo sustenta funções essenciais da organização."),
    Regra("I04", (("criticidade", "=", 3),), ("prevalencia", "Suporte"), 1.0,
          "Criticidade 3: o ativo apoia funções essenciais."),
    Regra("I05", (("criticidade", "≤", 2),), ("prevalencia", "Mínima"), 1.0,
          "Criticidade 1 e 2: o ativo não é essencial."),
    Regra("I06", (("setor", "∈", SETORES_DADOS_PESSOAIS),), ("dados_pessoais", "Sim"), 0.7,
          "Esses setores tratam dados pessoais de alunos e servidores por natureza; nos outros, o sistema pergunta."),
    Regra("I07", (("dados_pessoais", "=", "Sim"),), ("bem_estar", "Material"), 0.8,
          "Vazamento de dados pessoais pode causar dano financeiro ou psicológico aos titulares (LGPD). "
          "Adaptação do 'Public Well-being Impact' do SSVC."),
    Regra("I08", (("dados_pessoais", "=", "Não"),), ("bem_estar", "Mínimo"), 1.0,
          "Sem dados pessoais, o dano a pessoas fica abaixo do limiar 'Material'."),
    Regra("I09", (("prevalencia", "=", "Essencial"),), ("impacto_missao", "Alto"), 1.0,
          "Tabela 8 do guia SSVC da CISA."),
    Regra("I10", (("prevalencia", "=", "Suporte"),), ("impacto_missao", "Médio"), 1.0,
          "Tabela 8 do guia SSVC: Suporte dá Médio com bem-estar Mínimo ou Material (o sistema não usa 'Irreversível')."),
    Regra("I11", (("prevalencia", "=", "Mínima"), ("bem_estar", "=", "Material")), ("impacto_missao", "Médio"), 1.0,
          "Tabela 8 do guia SSVC da CISA."),
    Regra("I12", (("prevalencia", "=", "Mínima"), ("bem_estar", "=", "Mínimo")), ("impacto_missao", "Baixo"), 1.0,
          "Tabela 8 do guia SSVC da CISA."),
    Regra("I13", (("sistema_operacional", "contém", SO_SEM_SUPORTE),), ("so_sem_suporte", "Sim"), 0.9,
          "Sistemas fora do suporte padrão do fabricante em nov/2026 (pode existir suporte estendido pago)."),
] + _regras_ssvc() + [
    # ----- D: decisão final (se houver conflito, prevalece a mais urgente) -----
    Regra("D01", (("exploracao", "=", "Ativa"), ("exposto", "=", "Sim"), ("criticidade", "≥", 4)),
          ("decisao", "Act"), 0.95, "Falha explorada na prática, alcançável pela internet, em ativo importante."),
    Regra("D02", (("reincidente", "=", "Sim"), ("decisao_ssvc", "≠", "Act")), ("decisao", um_nivel_acima), 0.9,
          "A falha voltou depois de corrigida: o controle já falhou uma vez, então a prioridade sobe."),
    Regra("D03", (("decisao_ssvc", "é conhecida", None),), ("decisao", decisao_da_arvore), 1.0,
          "Sem regra mais urgente, vale a decisão da árvore SSVC."),
    # ----- A: ações recomendadas -----
    Regra("A01", (("patch", "=", "Sim"),),
          ("acao", "Aplicar a correção do fabricante. Solução do catálogo: {solucao}"), 0.9,
          "Com correção disponível, corrigir é a resposta definitiva."),
    Regra("A02", (("patch", "=", "Não"), ("tipo", "=", "Servidor")),
          ("acao", "Aplicar um controle compensatório até sair a correção: segmentar a rede do servidor "
                   "ou colocar um WAF na frente do serviço."), 0.8,
          "Sem patch, o servidor precisa de outra barreira entre o atacante e a falha."),
    Regra("A03", (("patch", "=", "Não"), ("tipo", "≠", "Servidor")),
          ("acao", "Isolar o equipamento numa VLAN restrita, limitar a gerência por ACL e desativar o "
                   "serviço vulnerável."), 0.7,
          "Sem patch, diminuir quem consegue alcançar o equipamento."),
    Regra("A04", (("exploracao", "∈", ("PoC", "Ativa")), ("exposto", "=", "Sim")),
          ("acao", "Bloquear ou restringir o acesso pela internet ao serviço (firewall/VPN) até concluir a correção."),
          0.85, "Com exploit disponível, a exposição à internet é o caminho mais curto do atacante."),
    Regra("A05", (("exploracao", "=", "Ativa"),),
          ("acao", "Procurar sinais de invasão (logs, contas e processos estranhos) antes de corrigir: "
                   "a falha já é explorada na prática."), 0.8,
          "Falhas exploradas ativamente podem já ter sido usadas contra o ativo."),
    Regra("A06", (("reincidente", "=", "Sim"),),
          ("acao", "Revisar o processo de patch: a falha já tinha sido corrigida neste ativo e voltou "
                   "(imagem desatualizada, reinstalação ou rollback?)."), 0.9,
          "Reincidência indica problema no processo, não só no ativo."),
    Regra("A07", (("decisao", "∈", ("Attend", "Act")), ("dados_pessoais", "=", "Sim")),
          ("acao", "Avisar o encarregado de dados (DPO): o ativo guarda dados pessoais. Se houver indício de "
                   "incidente, avaliar a comunicação à ANPD e aos titulares (LGPD, art. 48)."), 0.9,
          "A LGPD exige comunicar incidentes que possam causar risco ou dano relevante aos titulares."),
    Regra("A08", (("so_sem_suporte", "=", "Sim"),),
          ("acao", "Planejar a atualização ou troca do sistema operacional: {so} saiu do suporte padrão do fabricante."),
          0.9, "Sem suporte, as próximas falhas deixam de ser corrigidas."),
    Regra("A09", (("prazo_vencido", "=", "Sim"), ("decisao", "∈", ("Attend", "Act"))),
          ("acao", "Escalar para a gestão: o prazo de correção registrado no banco já venceu."), 0.9,
          "Falha urgente com prazo estourado precisa de decisão de quem gerencia."),
    Regra("A10", (("status", "=", "Aberta"), ("dias_aberto", "≥", 60)),
          ("acao", "Definir um responsável e uma data: a ocorrência está aberta há {dias_aberto} dias e a "
                   "correção nem começou."), 0.8,
          "Pendência parada tende a ser esquecida."),
    Regra("A11", (("severidade", "=", "Baixa"), ("criticidade", "≤", 2), ("exposto", "=", "Não"),
                  ("decisao", "=", "Track")), ("acao", ACEITAR), 0.7,
          "Baixa severidade, ativo pouco crítico e fora da internet: corrigir pode custar mais do que o risco."),
]

PERGUNTAS = {
    "exploracao": Pergunta(
        "A falha {cve} tem exploit público ou está no catálogo KEV da CISA?",
        "O KEV é a lista da CISA de falhas exploradas na prática: cisa.gov/known-exploited-vulnerabilities-catalog",
        (("Está no KEV ou há relatos de exploração ativa", "Ativa"),
         ("Há prova de conceito pública (Metasploit, Exploit-DB...)", "PoC"),
         ("Não há exploit conhecido", "Nenhuma")),
        "PoC"),
    "exposto": Pergunta(
        "O ativo {hostname} fica exposto à internet?",
        "Alcançável de fora da rede: IP público, porta liberada no firewall ou publicado por um proxy.",
        (("Sim", "Sim"), ("Não", "Não")), "Sim"),
    "automatizavel": Pergunta(
        "Um atacante consegue automatizar a exploração de {cve}, varrendo e invadindo vários alvos sem ajuda humana?",
        "No SSVC, automatizável quer dizer que reconhecimento, preparo, entrega e exploração podem ser automatizados "
        "de forma confiável, como num worm (ex.: WannaCry). Falha que exige clique da vítima ou atacante já dentro "
        "da rede costuma ser 'Não'.",
        (("Sim", "Sim"), ("Não", "Não")), "Sim"),
    "impacto_tecnico": Pergunta(
        "Se explorada, a falha {cve} dá ao atacante controle total do ativo?",
        "Total: executar código como administrador/root ou ler todos os dados do sistema. "
        "Parcial: negação de serviço, vazamento limitado ou depende de outras falhas.",
        (("Sim, controle total", "Total"), ("Não, o impacto é parcial", "Parcial")), "Total"),
    "patch": Pergunta(
        "Já existe correção do fabricante (patch, atualização ou configuração oficial) para {cve}?",
        "Solução registrada no catálogo: {solucao}",
        (("Sim", "Sim"), ("Não", "Não")), "Não"),
    "dados_pessoais": Pergunta(
        "O ativo {hostname} guarda ou processa dados pessoais (LGPD)?",
        "Ex.: nome, CPF, notas, salários ou dados de saúde de alunos, servidores ou terceiros.",
        (("Sim", "Sim"), ("Não", "Não")), "Sim"),
}

SIGNIFICADO = {  # resumo das definições do guia SSVC da CISA
    "Track": "Nenhuma ação imediata: acompanhar e corrigir dentro do prazo padrão.",
    "Track*": "Nenhuma ação imediata, mas há sinais que pedem acompanhamento de perto; corrigir no prazo padrão.",
    "Attend": "Pede a atenção da supervisão (pedir apoio, avisar as áreas envolvidas); corrigir antes do prazo padrão.",
    "Act": "Pede a atenção da supervisão e da liderança, que se reúnem para decidir a resposta; corrigir o quanto antes.",
}

SLA = {"Crítica": 7, "Alta": 30, "Média": 90, "Baixa": 180}  # o mesmo prazo da trigger trg_regras_ocorrencia
GENERICO = {"hostname": "o ativo", "cve": "a CVE", "solucao": "[solução do catálogo]", "so": "[sistema]",
            "dias_aberto": "N"}


def fc_txt(fc):
    return ("%.2f" % fc).replace(".", ",")


def _fmt(x):
    if isinstance(x, tuple):
        return "{" + ", ".join(map(str, x)) + "}"
    if isinstance(x, float):
        return ("%.1f" % x).replace(".", ",")
    return str(x)


def fatos_do_banco(oc):
    """Converte a linha da ocorrência (SQL do app.py) nos fatos que as regras usam."""
    return {"cvss": float(oc["cvss"]), "severidade": oc["severidade"], "criticidade": int(oc["criticidade"]),
            "tipo": oc["tipo"], "sistema_operacional": oc["sistema_operacional"], "setor": oc["setor"],
            "status": oc["status"], "dias_aberto": int(oc["dias_aberto"]),
            "reincidente": "Sim" if oc["reincidente"] else "Não",
            "prazo_vencido": "Sim" if oc["prazo_vencido"] else "Não"}


def contexto(oc):
    """Textos da ocorrência que entram nas perguntas e nas ações."""
    return {"hostname": oc["hostname"], "cve": oc["cve"], "solucao": oc["solucao"] or "não cadastrada",
            "so": oc["sistema_operacional"] or "o sistema", "dias_aberto": int(oc["dias_aberto"])}


class _Pendente(Exception):
    def __init__(self, fato, cadeia):
        Exception.__init__(self, fato)
        self.fato, self.cadeia = fato, cadeia


class Motor:
    """Encadeamento para trás com fatores de certeza.

    Cada análise recomeça do zero com as respostas já dadas e para na primeira pergunta que faltar,
    então nada fica guardado entre uma pergunta e outra (combina com as reexecuções do Streamlit)."""

    def __init__(self, fatos, respostas):
        self.respostas = respostas
        self.fatos = {f: {v: 1.0} for f, v in fatos.items() if v is not None}  # fato -> {valor: FC}
        self.origem = {f: "banco" for f in self.fatos}
        self.disparadas = []  # (regra, valor concluído, FC das premissas, FC da conclusão), na ordem
        self.pilha = []       # regras em avaliação agora, do objetivo até a pergunta ("Por quê?")
        self.pendente, self.cadeia = None, []

    def valor(self, fato):
        """Valor atual e FC. Na decisão vale a mais urgente (princípio da precaução); nos outros, a mais certa."""
        vals = {v: fc for v, fc in self.fatos.get(fato, {}).items() if fc >= LIMIAR}
        if not vals:
            return None, 0.0
        v = max(vals, key=NIVEIS.index) if fato == "decisao" else max(vals, key=vals.get)
        return v, vals[v]

    def obter(self, fato):
        if fato not in self.fatos:
            self._investigar(fato)
        return self.valor(fato)

    def _investigar(self, fato):
        self.fatos[fato] = {}  # marca como investigado antes de descer (evita ciclos)
        for regra in REGRAS:
            if regra.entao[0] == fato:
                self._aplicar(regra)
        if not self.fatos[fato] and fato in PERGUNTAS:  # nenhuma regra concluiu: aí sim pergunta
            if fato not in self.respostas:
                raise _Pendente(fato, list(self.pilha))
            v, fc = self.respostas[fato]
            self.fatos[fato] = {v: fc}
            self.origem[fato] = "resposta" if fc == 1 else "resposta 'Não sei' (valor assumido)"

    def _aplicar(self, regra):
        # pré-checagem do MYCIN: se uma premissa já conhecida é falsa, descarta a regra sem perguntar nada
        for fato, op, alvo in regra.se:
            v = self.valor(fato)[0]
            if v is not None and not OPERADORES[op](v, alvo):
                return
        self.pilha.append(regra)
        try:
            fc_premissas = 1.0
            for fato, op, alvo in regra.se:
                v, fc = self.obter(fato)
                if v is None or not OPERADORES[op](v, alvo):
                    return  # premissa falsa ou desconhecida: a regra não dispara
                fc_premissas = min(fc_premissas, fc)
        finally:
            self.pilha.pop()
        fato, valor = regra.entao
        if callable(valor):
            valor = valor(self)
        fc = regra.fc * fc_premissas
        anterior = self.fatos[fato].get(valor, 0.0)
        self.fatos[fato][valor] = anterior + fc * (1 - anterior)
        self.disparadas.append((regra, valor, fc_premissas, fc))

    def acoes(self):
        """Ações recomendadas, da mais para a menos certa (empate: ordem das regras)."""
        vals = self.fatos.get("acao", {}).items()
        return sorted(((t, fc) for t, fc in vals if fc >= LIMIAR), key=lambda x: -x[1])

    def aceitar_risco(self):
        return self.fatos.get("acao", {}).get(ACEITAR, 0.0) >= LIMIAR

    def memoria(self):
        """Memória de trabalho: cada fato conhecido, com valor, FC e de onde veio."""
        linhas = []
        for fato in self.fatos:
            v, fc = self.valor(fato)
            if v is None or fato == "acao":
                continue
            origem = self.origem.get(fato) or "regra " + ", ".join(
                r.id for r, _, _, _ in self.disparadas if r.entao[0] == fato)
            linhas.append((NOMES[fato], _fmt(v), fc_txt(fc), origem))
        # banco primeiro, depois respostas, depois inferidos (cada grupo na ordem em que o motor investigou)
        return sorted(linhas, key=lambda l: 0 if l[3] == "banco" else 1 if l[3].startswith("resposta") else 2)


def analisar(oc, respostas):
    """Roda o motor para a ocorrência. Se faltar resposta, motor.pendente diz qual fato perguntar."""
    m = Motor(fatos_do_banco(oc), respostas)
    try:
        for objetivo in OBJETIVOS:
            m.obter(objetivo)
    except _Pendente as p:
        m.pendente, m.cadeia = p.fato, p.cadeia
    return m


def descrever(regra, motor=None, ctx=None, valor=None):
    """A regra em texto. Com o motor, marca as premissas: ✓ vale, ✗ não vale, ? ainda não sei."""
    premissas = []
    for fato, op, alvo in regra.se:
        t = "%s %s%s" % (NOMES[fato], op, "" if alvo is None else " " + _fmt(alvo))
        if motor is not None:
            v = motor.valor(fato)[0]
            t += " ?" if v is None else (" ✓" if OPERADORES[op](v, alvo) else " ✗")
        premissas.append(t)
    fato, conclusao = regra.entao
    if valor is None:
        valor = conclusao.__doc__ if callable(conclusao) else conclusao
    elif callable(conclusao):
        valor = "%s (%s)" % (valor, conclusao.__doc__)
    if fato == "acao":
        valor = valor.format_map(ctx or GENERICO)
    return "SE %s ENTÃO %s = %s" % (" E ".join(premissas), NOMES[fato], _fmt(valor))


def porque(motor, ctx=None):
    """Explicação "Por quê?": as regras que levaram à pergunta, da mais próxima até o objetivo da análise."""
    linhas, fato = [], motor.pendente
    for i, regra in enumerate(reversed(motor.cadeia)):
        inicio = "Pergunto porque preciso de" if i == 0 else "E preciso de"
        linhas.append((regra.id, "%s «%s» para avaliar a regra %s"
                       % (inicio, NOMES[fato], descrever(regra, motor, ctx))))
        fato = regra.entao[0]
    linhas.append(("", "«%s» é um dos objetivos da análise: o que fazer com esta ocorrência e com que urgência."
                   % NOMES[fato]))
    return linhas


def conflito(motor):
    """Explica a resolução de conflito quando regras diferentes concluem decisões diferentes."""
    vals = sorted(((v, fc) for v, fc in motor.fatos.get("decisao", {}).items() if fc >= LIMIAR),
                  key=lambda x: NIVEIS.index(x[0]))
    if len(vals) < 2:
        return None
    return ("Regras diferentes concluíram decisões diferentes: %s. Prevalece a mais urgente (princípio da precaução)."
            % "; ".join("%s com FC %s" % (v, fc_txt(fc)) for v, fc in vals))


def base_de_conhecimento():
    """Todas as regras em texto (tela e artigo)."""
    return [(r.id, descrever(r), fc_txt(r.fc), r.nota) for r in REGRAS]


def prazo_sugerido(decisao, oc, hoje):
    """Data limite sugerida e o motivo, a partir da decisão e do prazo que o banco já calculou."""
    banco, sev = oc["prazo_correcao"], oc["severidade"]
    sla = SLA.get(sev, 180)
    if decisao in ("Track", "Track*"):
        if banco >= hoje:
            return banco, "%s: prazo padrão de %d dias da severidade %s, já calculado pelo banco." % (decisao, sla, sev)
        return hoje + timedelta(days=30), ("%s: o prazo padrão venceu em %s; replanejar para a próxima janela de "
                                           "manutenção (30 dias)." % (decisao, banco.strftime("%d/%m/%Y")))
    if decisao == "Act":
        dias, motivo = 2, "Act: corrigir o quanto antes (até 2 dias)"
    else:
        dias, motivo = sla // 2, "Attend: antes do prazo padrão (metade dos %d dias da severidade %s)" % (sla, sev)
    data = hoje + timedelta(days=dias)
    if hoje <= banco < data:
        return banco, motivo + "; o prazo do banco é mais cedo e continua valendo."
    return data, motivo + "."


def justificativa(motor, oc):
    """Texto que vai para a observação da ocorrência quando o analista aceita o risco recomendado."""
    regras = ", ".join(dict.fromkeys(r.id for r, _, _, _ in motor.disparadas))
    return ("Risco aceito com apoio do sistema especialista (SSVC): decisão %s, certeza de %d%% para aceitar. "
            "Severidade %s (CVSS %s), criticidade %d, ativo fora da internet. Regras: %s. "
            "Monitorar nas próximas varreduras e reavaliar se surgir exploração ativa."
            % (motor.valor("decisao")[0], round(100 * motor.fatos["acao"][ACEITAR]), oc["severidade"],
               _fmt(float(oc["cvss"])), int(oc["criticidade"]), regras))


# ---------------------------------------------------------------------
# Autoteste: python app/especialista.py
# ---------------------------------------------------------------------
if __name__ == "__main__":
    from datetime import date

    HOJE = date(2026, 11, 24)

    def ocorrencia(**k):
        base = dict(hostname="srv-teste", tipo="Servidor", sistema_operacional="Debian 12", criticidade=5,
                    setor="DTI - Sistemas", cve="CVE-2021-44228", cvss=10.0, severidade="Crítica",
                    solucao="Atualizar o Log4j.", status="Aberta", dias_aberto=15,
                    prazo_correcao=date(2026, 11, 16), prazo_vencido=True, reincidente=False)
        base.update(k)
        return base

    def consultar(oc, respostas):
        """Responde pela tabela (None = 'Não sei'); falha se o motor perguntar algo fora dela."""
        dadas, feitas = {}, []
        while True:
            m = analisar(oc, dadas)
            if not m.pendente:
                return m, feitas
            assert m.pendente in respostas, "pergunta inesperada: " + m.pendente
            assert len(porque(m)) >= 2, "toda pergunta tem 'Por quê?'"
            feitas.append(m.pendente)
            v = respostas[m.pendente]
            dadas[m.pendente] = (v, 1.0) if v is not None else (PERGUNTAS[m.pendente].nao_sei, FC_NAO_SEI)

    def ids(m):
        return [r.id for r, _, _, _ in m.disparadas]

    def tem_acao(m, inicio):
        return any(t.startswith(inicio) for t, _ in m.acoes())

    # base de conhecimento bem formada e árvore igual à da CISA
    assert len({r.id for r in REGRAS}) == len(REGRAS) == len(base_de_conhecimento()) == 13 + 36 + 3 + 11
    arvore = {tuple(p[2] for p in r.se): r.entao[1] for r in REGRAS if r.id.startswith("S")}
    assert arvore[("Ativa", "Sim", "Total", "Alto")] == "Act"
    assert arvore[("Ativa", "Não", "Total", "Médio")] == "Attend"
    assert arvore[("PoC", "Não", "Total", "Médio")] == "Track*"
    assert arvore[("Nenhuma", "Sim", "Parcial", "Alto")] == "Attend"
    assert arvore[("Nenhuma", "Não", "Parcial", "Baixo")] == "Track"

    # a primeira pergunta vem da regra D01, e o "Por quê?" mostra isso
    m = analisar(ocorrencia(), {})
    assert m.pendente == "exploracao" and m.cadeia[-1].id == "D01"
    # pré-checagem: com criticidade 2 a D01 já é falsa, então a pergunta vem da árvore SSVC
    m = analisar(ocorrencia(criticidade=2), {})
    assert m.pendente == "exploracao" and [r.id for r in m.cadeia] == ["D03", "S01"]

    # regra 1 do enunciado: exploit ativo + exposto + criticidade >= 4 -> Act; CVSS 10 dispensa a pergunta do impacto
    m, feitas = consultar(ocorrencia(), {"exploracao": "Ativa", "exposto": "Sim", "automatizavel": "Sim",
                                         "patch": "Sim", "dados_pessoais": "Sim"})
    assert m.valor("decisao")[0] == "Act" and m.valor("decisao")[1] >= 0.95 and "D01" in ids(m)
    assert feitas[:2] == ["exploracao", "exposto"] and "impacto_tecnico" not in feitas
    assert tem_acao(m, "Avisar o encarregado") and tem_acao(m, "Escalar para a gestão")
    assert prazo_sugerido("Act", ocorrencia(), HOJE)[0] == date(2026, 11, 26)

    # regra 2: sem patch em servidor -> controle compensatório (FC 0,8); CVSS 8,1 obriga a perguntar o impacto
    m, feitas = consultar(ocorrencia(cvss=8.1, severidade="Alta"),
                          {"exploracao": "PoC", "automatizavel": "Não", "impacto_tecnico": "Total", "patch": "Não",
                           "exposto": "Não", "dados_pessoais": "Não"})
    assert "impacto_tecnico" in feitas and m.valor("decisao")[0] == "Attend"
    a02 = next(r for r in REGRAS if r.id == "A02")
    assert dict(m.acoes())[a02.entao[1]] == 0.8 and tem_acao(m, "Aplicar um controle compensatório")

    # regra 3: reincidência sobe um nível (Track -> Track*) e pede revisão do processo de patch
    oc = ocorrencia(cvss=5.9, severidade="Média", criticidade=3, reincidente=True,
                    prazo_correcao=date(2027, 1, 1), prazo_vencido=False)
    m, feitas = consultar(oc, {"exploracao": "Nenhuma", "automatizavel": "Não", "patch": "Sim"})
    assert m.valor("decisao_ssvc")[0] == "Track" and m.valor("decisao")[0] == "Track*" and conflito(m)
    assert tem_acao(m, "Revisar o processo de patch") and feitas == ["exploracao", "automatizavel", "patch"]
    assert prazo_sugerido("Track*", oc, HOJE)[0] == date(2027, 1, 1)

    # regra 4: Baixa + não exposto + criticidade <= 2 -> aceitar o risco (FC 0,7 x 0,8 do impacto inferido)
    oc = ocorrencia(tipo="Switch", sistema_operacional="Cisco IOS 15.2", criticidade=2, setor="Biblioteca Central",
                    cve="CVE-2014-3566", cvss=3.4, severidade="Baixa", solucao="Desativar o SSL 3.0.",
                    dias_aberto=127, prazo_correcao=date(2027, 1, 16), prazo_vencido=False)
    m, feitas = consultar(oc, {"exploracao": "PoC", "automatizavel": "Não", "dados_pessoais": "Não",
                               "patch": "Sim", "exposto": "Não"})
    assert m.valor("decisao")[0] == "Track" and m.aceitar_risco()
    assert abs(m.fatos["acao"][ACEITAR] - 0.56) < 1e-9 and "Risco aceito" in justificativa(m, oc)
    assert tem_acao(m, "Definir um responsável")

    # o setor dispensa a pergunta da LGPD; Mínima x Material = Médio (Tabela 8); SO sem suporte vira ação
    oc = ocorrencia(setor="Financeiro", criticidade=1, tipo="Estação", sistema_operacional="Windows 10 22H2",
                    cvss=8.8, severidade="Alta")
    m, feitas = consultar(oc, {"exploracao": "Ativa", "exposto": "Não", "automatizavel": "Não",
                               "impacto_tecnico": "Total", "patch": "Sim"})
    assert "dados_pessoais" not in feitas and m.valor("impacto_missao") == ("Médio", 0.7 * 0.8)
    assert m.valor("decisao")[0] == "Attend" and tem_acao(m, "Planejar a atualização")

    # "Não sei" vira o pior caso plausível, com certeza menor
    m, _ = consultar(ocorrencia(), {"exploracao": None, "exposto": None, "automatizavel": "Sim", "patch": "Sim",
                                    "dados_pessoais": "Sim"})
    assert m.valor("decisao") == ("Attend", FC_NAO_SEI)

    # prazos: Attend = metade do prazo padrão; Track com prazo vencido é replanejado; prazo do banco mais cedo vale
    assert prazo_sugerido("Attend", ocorrencia(severidade="Alta", prazo_correcao=date(2027, 1, 1)),
                          HOJE)[0] == date(2026, 12, 9)
    assert prazo_sugerido("Track", ocorrencia(), HOJE)[0] == date(2026, 12, 24)
    assert prazo_sugerido("Act", ocorrencia(prazo_correcao=date(2026, 11, 25)), HOJE)[0] == date(2026, 11, 25)

    print("especialista: autoteste ok (%d regras)" % len(REGRAS))
