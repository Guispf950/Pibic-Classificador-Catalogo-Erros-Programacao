import requests  # requisições HTTP à API do LLM
import json      # serialização JSON
import re        # extração das linhas do log e ancoragem das anotações inline
import sys       # uso futuro (ex.: sys.exit em erros fatais)
import time      # backoff entre tentativas de retry

# Config central: endereço/modelo/temperatura do LLM e o modo de anotação (ver src/config.py).
from src.config import (
    URL_LLM_LOCAL, NOME_MODELO, MODO_ANOTACAO,
    TEMPERATURA_CLASSIFICACAO, TEMPERATURA_FEEDBACK,
    LLM_TIMEOUT_S, LLM_KEEP_ALIVE,
)

# Classificação DETERMINÍSTICA do erro para CWE (a partir do log da ferramenta).
from src.cwe import classificar_cwe, classificar_cwe_tipo

# Base de Conhecimento: recupera, por CHAVE EXATA (o CWE), o documento curado do erro.
# Usado na 2ª chamada ao LLM (geração de feedback) para aterrar a explicação.
from src.kb import recuperar_kb


def _chamar_llm(prompt, tentativa=1, temperatura=TEMPERATURA_CLASSIFICACAO):
    """
    Executa uma chamada ao Ollama e retorna o texto completo gerado.
    Retorna string vazia se o servidor não gerar nenhum token.

    'temperatura' é passada por CADA FASE: a classificação usa 0.0 (determinística) e o
    feedback usa uma um pouco mais alta (texto mais natural). O default é o da classificação.
    """
    resposta = requests.post(URL_LLM_LOCAL, json={
        "model": NOME_MODELO,
        "prompt": prompt,
        "stream": True,
        "format": "json",
        "keep_alive": LLM_KEEP_ALIVE,              # mantém o modelo carregado (evita cold start)
        "options": {"temperature": temperatura}   # definida pela fase que chamou
    }, stream=True, timeout=LLM_TIMEOUT_S)          # generoso: 1ª chamada carrega o modelo

    texto_completo = ""
    print(f"  -> [IA Analisando] (tentativa {tentativa}): \n", end="", flush=True)

    for linha in resposta.iter_lines():
        if linha:
            pedaco_json = json.loads(linha.decode('utf-8'))
            pedaco_texto = pedaco_json.get("response", "")
            print(pedaco_texto, end="", flush=True)
            texto_completo += pedaco_texto

    print("\n")
    return texto_completo


def _sanitizar(texto):
    """Remove blocos markdown e espaços extras que alguns modelos inserem."""
    return (
        texto.strip()
        .removeprefix("```json")
        .removeprefix("```")
        .removesuffix("```")
        .strip()
    )


# ══════════════════════════════════════════════════════════════════════════════
# ANOTAÇÃO INLINE DETERMINÍSTICA (inspirada no FLAME, §III-B)
# ══════════════════════════════════════════════════════════════════════════════
# Fundamentação: o FLAME mostra por ablação que anotar a linha do erro com um comentário no
# código (// @@ explicação) supera passar o NÚMERO da linha em texto (top-1 62,7% -> 15,8% com
# referência numérica), devido à limitação de "numerical understanding" das LLMs.
# Vantagem sobre o FLAME: lá é a própria LLM que anota e o marcador desalinha ao reformatar o
# código (daí o "fuzzy matching" por cosseno); aqui quem anota é o PIPELINE, ancorando na linha
# EXATA reportada pela ferramenta (ASan/Valgrind) — determinístico, dispensa o fuzzy matching.
# Sintoma vs causa: a linha onde o erro DISPARA (sintoma) raramente é onde NASCE (causa). O
# backtrace dá os dois pontos, então anota-se AMBOS, mas só quando a ferramenta os fornece.

# Regras de detecção de seção (SINTOMA/CAUSA/VAZAMENTO/ORIGEM) isoladas em src/regras_secao.py,
# único lugar que conhece o texto do ASan/Valgrind. Ajustes de classe de erro vão em REGRAS_SECAO.
from src.regras_secao import REGRAS_SECAO


def _extrair_pontos_anotacao(log, nome_arquivo):
    """
    Varre o log (idealmente o BRUTO) e extrai, de forma DETERMINÍSTICA, os pontos que a
    ferramenta reportou no código do aluno, associando cada um a um papel:

        SINTOMA   -> onde o erro se manifesta (o acesso/uso que dispara a falha)
        CAUSA     -> onde o erro nasce (o free do bloco, ou a criação do valor não inic.)
        VAZAMENTO -> a alocação cuja memória nunca é liberada (leaks)
        ORIGEM    -> onde o bloco foi alocado (extra, não anotada por padrão)

    Retorna dict {papel: (numero_da_linha, texto_do_comentario)}. Só inclui um papel quando a
    ferramenta forneceu aquela linha; nunca inventa.
    """
    if not nome_arquivo:
        return {}

    # REGEX 1 — "<arquivo>:<numero>" (ex.: "submissao_5.c:118") em qualquer frame. re.escape
    # torna o nome um literal seguro (o "." de ".c" vira ponto literal); "(\d+)" captura o número.
    padrao_linha = re.compile(re.escape(nome_arquivo) + r":(\d+)")
    # REGEX 2 — distingue frame do GDB do frame do Valgrind pelo formato do "at", para dar
    # prioridade ao relatório ESTRUTURADO (que separa sintoma/free/alloc) sobre o backtrace do GDB:
    #   GDB:      "... at ./caminho/submissao.c:23"           (arquivo logo após "at ")
    #   Valgrind: "... at 0x4001654: func (submissao.c:118)"  ("at 0x", com espaço depois)
    # "\S*<arquivo>" alcança o nome no caso do GDB, mas não no do Valgrind (onde \S* não atravessa
    # o "0x..." seguido de espaço).
    padrao_gdb = re.compile(r"\bat\s+\S*" + re.escape(nome_arquivo))

    pontos = {}         # papel -> (linha, rotulo)
    veio_do_gdb = {}    # papel -> bool: a linha guardada veio de um frame do GDB?
    papel_atual = None  # (papel, rotulo) da seção sendo lida no momento

    # ESTRATÉGIA: preferir frames ESTRUTURADOS e usar os do GDB só como FALLBACK — essencial para
    # o SIGSEGV puro (null-deref), em que o ASan não gera relatório e a linha só existe no
    # backtrace do GDB (antes esses frames eram descartados e o crash ficava sem anotação).
    for busca in log.split("\n"):
        linha = busca.strip()

        # Frame do GDB? Não descarta de imediato; só marca, para o estruturado ter prioridade.
        eh_gdb = bool(padrao_gdb.search(linha))

        # Detecta início/troca de SEÇÃO (primeira regra cujo regex casa).
        for papel, rotulo, rx in REGRAS_SECAO:
            if rx.search(linha):
                papel_atual = (papel, rotulo)
                break

        # Extrai a linha do aluno pertencente à seção atual.
        if papel_atual is not None:
            m = padrao_linha.search(linha)
            if m:
                papel = papel_atual[0]
                num = int(m.group(1))
                if papel not in pontos:
                    # 1ª linha desta seção (frame mais próximo do erro) — guarda.
                    pontos[papel] = (num, papel_atual[1])
                    veio_do_gdb[papel] = eh_gdb
                elif veio_do_gdb.get(papel) and not eh_gdb:
                    # Já havia só um frame do GDB, mas chegou um ESTRUTURADO — ele vence.
                    pontos[papel] = (num, papel_atual[1])
                    veio_do_gdb[papel] = False

    return pontos


def _anotar_codigo(codigo_fonte, pontos):
    """
    Injeta comentários `// @@ [PAPEL] explicação` no FIM das linhas exatas reportadas pela
    ferramenta. Anota apenas SINTOMA, CAUSA e VAZAMENTO (os pontos determinísticos). Como a linha
    vem da ferramenta, o marcador cai sempre no lugar certo.
    """
    if not codigo_fonte or not pontos:
        return codigo_fonte

    linhas = codigo_fonte.split("\n")
    for papel in ("SINTOMA", "CAUSA", "VAZAMENTO"):
        if papel not in pontos:
            continue
        num, rotulo = pontos[papel]
        numLinha = num - 1
        if 0 <= numLinha < len(linhas):
            comentario = f"  // @@ [{papel}] {rotulo}"
            # Linha já anotada (ex.: sintoma e causa na mesma linha): acrescenta em vez de sobrescrever.
            if "// @@" in linhas[numLinha]:
                linhas[numLinha] = linhas[numLinha].rstrip() + f"  | [{papel}] {rotulo}"
            else:
                linhas[numLinha] = linhas[numLinha].rstrip() + comentario
    return "\n".join(linhas)


# Regex de DECLARAÇÃO DE VARIÁVEL SEM INICIALIZADOR: "<tipo> <nome>;". Aceita tipos primitivos,
# ponteiros, typedefs iniciados por maiúscula (ex.: TAVL, Node) e nomes terminados em _t. Exige
# ";" logo após o nome (sem "= ..."), o que exclui declarações já inicializadas ("int res = 0;")
# e statements comuns ("return res;"). Deliberadamente conservador — na dúvida, não casa.
_TIPO_C = r"(?:const\s+)?(?:unsigned\s+|signed\s+)?(?:int|char|short|long|float|double|void|bool|[A-Z]\w*|\w+_t)\s*\**"
_DECL_SEM_INIT = re.compile(rf"^\s*{_TIPO_C}\s+(\w+)\s*;")


def _fim_da_funcao(linhas, linha_abertura):
    """
    Retorna o número (1-based) da linha do '}' que FECHA a função aberta em 'linha_abertura', por
    CASAMENTO DE CHAVES. Ignora chaves em strings "...", chars '...' e comentários (// e /* */),
    para não ser enganado por  char c = '}';  ou  /* } */.
    É o limite superior robusto da varredura (substitui a antiga janela fixa de 40 linhas): nunca
    cruza para a função seguinte. Se as chaves não fecharem, devolve a última linha (degradação segura).
    """
    profundidade = 0
    viu_abertura = False
    em_comentario_bloco = False
    i = linha_abertura - 1
    while i < len(linhas):
        linha = linhas[i]
        j = 0
        em_string = em_char = em_comentario_linha = False
        while j < len(linha):
            c = linha[j]
            prox = linha[j + 1] if j + 1 < len(linha) else ""
            if em_comentario_bloco:
                if c == "*" and prox == "/":
                    em_comentario_bloco = False; j += 2; continue
                j += 1; continue
            if em_comentario_linha:
                break  # o resto da linha é comentário
            if em_string:
                if c == "\\": j += 2; continue      # escape (ex.: \" ) — pula os dois
                if c == '"': em_string = False
                j += 1; continue
            if em_char:
                if c == "\\": j += 2; continue
                if c == "'": em_char = False
                j += 1; continue
            # fora de string/char/comentário:
            if c == "/" and prox == "/": em_comentario_linha = True; break
            if c == "/" and prox == "*": em_comentario_bloco = True; j += 2; continue
            if c == '"': em_string = True; j += 1; continue
            if c == "'": em_char = True; j += 1; continue
            if c == "{":
                profundidade += 1; viu_abertura = True
            elif c == "}":
                profundidade -= 1
                if viu_abertura and profundidade == 0:
                    return i + 1  # linha do '}' que fecha a função (1-based)
            j += 1
        i += 1
    return len(linhas)   # não fechou -> última linha (seguro)


def _refinar_causa_uninit(pontos, codigo_fonte):
    """
    Refina a linha de CAUSA nos erros de VALOR NÃO INICIALIZADO.

    Motivo: para um valor não inicializado vindo da pilha, o Valgrind reporta a origem na linha de
    ABERTURA DA FUNÇÃO (o frame é alocado de uma vez), não na declaração da variável. A marca da
    CAUSA é movida para a DECLARAÇÃO sem inicializador, o ponto pedagogicamente correto.

    Trava de segurança (nunca piora o existente): só refina se
      (a) a CAUSA é do tipo "não inicializado" (pelo rótulo);
      (b) a linha da CAUSA é mesmo uma ABERTURA DE FUNÇÃO (tem '(' e '{') — não uma origem de
          heap (malloc), que deve permanecer onde está;
      (c) existe EXATAMENTE UMA declaração sem inicializador entre a função e o uso.
    Se qualquer condição falhar, devolve os pontos inalterados (fica na linha da função).
    """
    if "CAUSA" not in pontos or not codigo_fonte:
        return pontos

    linha_causa, rotulo_causa = pontos["CAUSA"]
    # (a) só atua no caso de valor não inicializado (identificado pelo rótulo).
    if "inicializado" not in rotulo_causa.lower():
        return pontos

    linhas = codigo_fonte.split("\n")
    if not (1 <= linha_causa <= len(linhas)):
        return pontos

    # (b) a CAUSA precisa estar numa linha de ABERTURA DE FUNÇÃO (caso do frame de pilha).
    linha_da_causa_txt = linhas[linha_causa - 1]
    if "(" not in linha_da_causa_txt or "{" not in linha_da_causa_txt:
        return pontos   # provavelmente origem de heap (malloc) -> mantém

    # Intervalo a varrer: da abertura da função ao fim REAL dela (casamento de chaves), para nunca
    # cruzar para a função seguinte. Havendo SINTOMA (o uso), usa-se o MENOR entre ele e o fim da
    # função — janela mais justa (a declaração está sempre entre a abertura e o uso), evitando
    # declarações de outros ramos após o uso.
    inicio = linha_causa
    fim_funcao = _fim_da_funcao(linhas, linha_causa)
    fim = min(pontos["SINTOMA"][0], fim_funcao) if "SINTOMA" in pontos else fim_funcao
    if fim <= inicio:
        fim = fim_funcao

    # (c) procura declarações sem inicializador no intervalo (linhas são 1-based).
    achados = []
    for n in range(inicio, min(fim, len(linhas) + 1)):
        m = _DECL_SEM_INIT.match(linhas[n - 1])
        if m:
            achados.append((n, m.group(1)))   # (linha, nome_da_variável)

    # Só refina se for INEQUÍVOCO (exatamente uma). Caso contrário, mantém a linha da função.
    if len(achados) == 1:
        nova_linha, nome_var = achados[0]
        pontos["CAUSA"] = (
            nova_linha,
            f"variável '{nome_var}' declarada aqui SEM inicialização (origem do valor não inicializado)",
        )
    return pontos


def _evidencia_do_log(log):
    """
    Escolhe DETERMINISTICAMENTE uma linha REAL do relatório da ferramenta para servir de evidência
    (ex.: "==NNNN== ... definitely lost" ou "ERROR: AddressSanitizer: ...").

    Rede de segurança do campo 'evidencia_log': se a LLM copiar a anotação // @@ (rótulo do
    pipeline, não prova) ou deixar o campo vazio, ele é trocado por esta linha real.

    Estratégia: retorna a PRIMEIRA linha que casa uma regra de SINTOMA/VAZAMENTO (cabeçalho do
    erro). Sem nenhuma, cai na primeira linha não-vazia; no limite, "-".
    """
    linhas = [l.strip() for l in log.split("\n")]
    for linha in linhas:
        for papel, _rotulo, rx in REGRAS_SECAO:
            if papel in ("SINTOMA", "VAZAMENTO") and rx.search(linha):
                return linha
    for linha in linhas:
        if linha:
            return linha
    return "-"


# ══════════════════════════════════════════════════════════════════════════════
# CLASSIFICAÇÃO FORENSE (com anotação inline)
# ════════════════════════════
def classificar_erro(log_limpo, codigo_fonte="", nome_arquivo="", log_bruto=""):
    """
    CLASSIFICAÇÃO 100% DETERMINÍSTICA do erro — SEM LLM.

    Todos os campos vêm da FERRAMENTA (ASan/Valgrind) por regex/parsing — rápido, estável e
    auditável —, então o /analisar devolve um diagnóstico imediato. Os campos que só a LLM
    produzia (causa_raiz, descricao_curta, variaveis_envolvidas) foram removidos daqui: o detalhe
    fica para o passo de FEEDBACK (gerar_feedback / gerar_feedback_stream), que usa o LLM.

    Retorna dict determinístico: tipo_erro, cwe_id, cwe_nome, linha_sintoma, linha_causa,
    linha_ocorrencia, evidencia_log, codigo_anotado.
    """
    # 1) Pontos da ferramenta + código anotado inline (// @@). Prefere o log BRUTO (todas as
    #    seções) e cai no limpo se não vier.
    pontos = _extrair_pontos_anotacao(log_bruto or log_limpo, nome_arquivo)
    # Refina a CAUSA de valor não inicializado (da abertura da função para a DECLARAÇÃO, quando
    # inequívoca).
    pontos = _refinar_causa_uninit(pontos, codigo_fonte)
    codigo_anotado = _anotar_codigo(codigo_fonte, pontos)

    # 2) Linhas determinísticas (da ferramenta).
    linha_sintoma = str(pontos["SINTOMA"][0]) if "SINTOMA" in pontos else (
        str(pontos["VAZAMENTO"][0]) if "VAZAMENTO" in pontos else "-")
    linha_causa = str(pontos["CAUSA"][0]) if "CAUSA" in pontos else "-"

    # 3) CWE + nome + tipo_erro — determinísticos, da assinatura do log.
    cwe_id, cwe_nome, tipo_erro = classificar_cwe_tipo(log_bruto or log_limpo)

    # 4) Evidência: linha REAL do relatório (âncora anti-alucinação).
    evidencia_log = _evidencia_do_log(log_bruto or log_limpo)

    return {
        "tipo_erro":       tipo_erro,
        "cwe_id":          cwe_id,
        "cwe_nome":        cwe_nome,
        "linha_sintoma":   linha_sintoma,
        "linha_causa":     linha_causa,
        # Compatibilidade com quem lê "linha_ocorrencia" (= sintoma).
        "linha_ocorrencia": linha_sintoma,
        "evidencia_log":   evidencia_log,
        # Código com anotações inline (// @@), para o orquestrador salvar / o feedback usar.
        "codigo_anotado":  codigo_anotado,
    }



# ══════════════════════════════════════════════════════════════════════════════
# 2ª CHAMADA AO LLM — GERAÇÃO DE FEEDBACK PEDAGÓGICO FORMATIVO
# ══════════════════════════════════════════════════════════════════════════════

def montar_prompt_feedback(codigo, analise, saida="json"):
    """
    Monta o PROMPT do feedback formativo — FONTE ÚNICA das regras pedagógicas.

    Usada em dois caminhos, para as regras nunca divergirem:
      • gerar_feedback (offline/catálogo): saida="json" -> JSON {"feedback": ...}, validado/retentado.
      • gerar_feedback_stream (API/SSE):   saida="texto" -> TEXTO puro, para os tokens do Ollama
        irem direto ao aluno, sem envelope JSON no stream.
    Só a INSTRUÇÃO FINAL muda entre os dois; o corpo (regras + exemplos + diagnóstico) é idêntico.
    """
    # Recupera o documento curado do erro por CHAVE EXATA (o CWE apurado na 1ª fase). Sem documento,
    # doc_kb = "" e o prompt segue sem ele (degradação graciosa).
    cwe_id = analise.get("cwe_id", "-")
    doc_kb = recuperar_kb(cwe_id)

    # Campos da classificação que dão contexto ao feedback (todos determinísticos).
    tipo_erro     = analise.get("tipo_erro", "-")
    cwe_nome      = analise.get("cwe_nome", "-")
    linha_sintoma = analise.get("linha_sintoma", "-")
    linha_causa   = analise.get("linha_causa", "-")

    # A seção da KB só entra no prompt se houver documento (evita cabeçalho vazio).
    secao_kb = f"\n===== MATERIAL DE APOIO (sobre este tipo de erro) =====\n{doc_kb}\n" if doc_kb else ""

    # ── ABLAÇÃO (MODO_ANOTACAO): com a classificação já determinística, a ablação vive aqui, no
    #    único passo que ainda usa LLM. Controla COMO a localização do erro chega ao modelo
    #    (variável experimental estilo FLAME):
    #      inline   -> código com marcadores // @@ (localização embutida)
    #      numerica -> código original + as linhas do erro em TEXTO (o "FLAME_num")
    #      nenhuma  -> código original, sem dica de linha (baseline)
    #    'codigo' recebido é o ORIGINAL; o anotado vem de analise["codigo_anotado"].
    codigo_anotado = analise.get("codigo_anotado", "") or codigo
    if MODO_ANOTACAO == "numerica":
        cabecalho_codigo = "===== CÓDIGO DO ALUNO ====="
        corpo_codigo = codigo
        dica_linhas = f"\nA ferramenta localizou o erro nestas linhas — sintoma: {linha_sintoma}; causa: {linha_causa}.\n"
    elif MODO_ANOTACAO == "nenhuma":
        cabecalho_codigo = "===== CÓDIGO DO ALUNO ====="
        corpo_codigo = codigo
        dica_linhas = ""
    else:  # "inline" (padrão)
        cabecalho_codigo = "===== CÓDIGO DO ALUNO (JÁ ANOTADO PELA FERRAMENTA) ====="
        corpo_codigo = codigo_anotado
        dica_linhas = ""

    # --- CORPO DO PROMPT (idêntico nos dois caminhos) ---
    corpo = f"""
Você é um TUTOR de programação em C que dá FEEDBACK FORMATIVO a um ALUNO INICIANTE.

Um analisador já identificou o erro (seção DIAGNÓSTICO). Seu objetivo: fazer o aluno DESCOBRIR
a correção sozinho, nunca recebê-la pronta. Termine SEMPRE o texto com uma PERGUNTA que leve o 
aluno ao próximo passo, ou seja, uma pergunta que o faça pensar na correção, sem dizê-la.

REGRAS:
1. NÃO revele a correção, em código ou em palavras (ex.: não diga o que atribuir, o que trocar,
   onde inserir uma chamada). Conduza o raciocínio até lá.
2. Baseie-se SOMENTE no DIAGNÓSTICO. Cite a variável real e a(s) linha(s) reais informadas
   ({linha_sintoma}, {linha_causa}), nunca invente outra causa.
3. Texto corrido, 3 a 5 frases, linguagem simples. Sem código, sem markdown, sem listas.
4. Termine SEMPRE o texto com uma PERGUNTA que leve o aluno ao próximo passo, uma pergunta que o faça
   pensar na correção, sem dizê-la.
5. Sua resposta é sobre O CASO ATUAL. Os exemplos abaixo são de OUTROS problemas, com outras
   variáveis e outras linhas — servem só para mostrar o TOM. Não reaproveite nomes, números ou
   frases deles. Se sua resposta usar as mesmas palavras de um exemplo, ela está errada.

EXEMPLOS DE ESTILO (problemas diferentes do caso atual — não copiar):
Caso: variável usada sem inicialização.
  Ruim (entrega a resposta): "Inicialize a variável 'total' antes do laço."
  Bom (leva a pensar): "Note que 'total' é lida na linha 14 dentro do laço — antes disso, algum
  caminho do código garante que ela já teve um valor definido?"

EXEMPLOS DE ESTILO (problemas diferentes do caso atual — não copiar):
Caso: acesso a índice fora dos limites de um vetor.
  Ruim: "Troque o '<=' por '<' na condição do for."
  Bom: "Seu vetor tem tamanho N e o laço vai até o índice N — o que existe na posição N de um
  vetor de tamanho N?"

EXEMPLOS DE ESTILO (problemas diferentes do caso atual — não copiar):
Caso: vazamento de memória (bloco alocado que nunca é devolvido).
  Ruim: "Adicione free(buffer) antes do return na linha 40."
  Bom: "O bloco apontado por 'buffer' foi reservado na linha 22, mas o programa passa pelo
  return da linha 40 sem mais nenhuma referência a ele — o que acontece com essa memória
  a partir desse ponto, e quem mais consegue reaproveitá-la depois?"

{cabecalho_codigo}
```c
{corpo_codigo}
```
{dica_linhas}
===== DIAGNÓSTICO (fonte da localização) =====
Tipo do erro: {tipo_erro} ({cwe_id} — {cwe_nome})
Linha do sintoma: {linha_sintoma}
Linha da causa: {linha_causa}
Material de apoio: {secao_kb}

Antes de responder, confira mentalmente: a pergunta ao final do feedback foi gerada? Sua pergunta menciona a variável e a linha REAIS do
diagnóstico acima ? Se não, reescreva.
"""

    # --- INSTRUÇÃO FINAL (único trecho que difere entre JSON e TEXTO) ---
    if saida == "texto":
        instrucao = (
            "\nEscreva APENAS o texto do feedback ao aluno, em português, seguindo as regras "
            "acima. Sem JSON, sem markdown, sem aspas ao redor, sem rótulos — apenas o parágrafo.\n"
        )
    else:  # "json" (padrão): comportamento original preservado
        instrucao = (
            "\nRetorne APENAS um JSON válido (sem markdown, sem texto fora dele):\n"
            "{\n"
            '    "feedback": "texto do feedback ao aluno, em português, seguindo as regras acima"\n'
            "}\n"
        )

    return corpo + instrucao


def gerar_feedback(codigo, analise, max_tentativas=3):
    """
    Gera o FEEDBACK FORMATIVO ao aluno (2ª chamada ao LLM, separada da classificação).

    A 1ª chamada (classificar_erro) classifica o erro; esta conversa com o aluno: explica o erro e
    o guia a corrigir sozinho, sem entregar a solução pronta.

    Parâmetros (tudo vem pronto da 1ª fase, nada é recalculado):
        codigo:  o código do aluno a exibir (idealmente o já anotado com // @@).
        analise: o dict da classificação determinística (tipo_erro, cwe_id, linhas, codigo_anotado...).
                 É o mesmo objeto que classificar_erro retornou (ou a linha lida da planilha).

    Retorna dict {"feedback": "<texto>"} (ou um esqueleto de falha após os retries).
    """
    # Prompt do construtor único (regras pedagógicas centralizadas). saida="json" preserva o
    # comportamento original: Ollama em format=json e leitura via json.loads.
    prompt = montar_prompt_feedback(codigo, analise, saida="json")

    ultimo_erro = None
    for tentativa in range(1, max_tentativas + 1):
        try:
            print(f"  -> [IA Feedback] (tentativa {tentativa}):")
            # Feedback com temperatura mais alta (TEMPERATURA_FEEDBACK): texto mais natural. Ollama
            # em format=json garante saída JSON válida, então a leitura abaixo não quebra.
            texto = _chamar_llm(prompt, tentativa, temperatura=TEMPERATURA_FEEDBACK)
            if not texto.strip():
                raise ValueError("Ollama retornou resposta vazia (nenhum token gerado).")

            resultado = json.loads(_sanitizar(texto))
            # O resto do pipeline espera a chave "feedback"; se faltar, força um retry.
            if "feedback" not in resultado:
                raise ValueError("JSON de feedback sem o campo 'feedback'.")
            return resultado

        except (json.JSONDecodeError, ValueError) as e:
            ultimo_erro = e
            if tentativa < max_tentativas:
                espera = 2 ** (tentativa - 1)  # backoff exponencial: 1s, 2s, 4s
                print(f"  [Retry {tentativa}/{max_tentativas}] {str(e)} — aguardando {espera}s...")
                time.sleep(espera)
        except Exception as e:
            # Falha de rede/servidor offline/timeout de conexão.
            ultimo_erro = e
            if tentativa < max_tentativas:
                espera = 2 ** (tentativa - 1)
                print(f"  [Retry {tentativa}/{max_tentativas}] Erro de rede: {str(e)} — aguardando {espera}s...")
                time.sleep(espera)

    # Esgotou as tentativas — devolve um esqueleto com o mesmo formato (chave "feedback").
    print(f"\n[Aviso] Feedback falhou após {max_tentativas} tentativas. Último erro: {str(ultimo_erro)}")
    return {"feedback": f"[falha ao gerar feedback após {max_tentativas} tentativas: {str(ultimo_erro)}]"}


def gerar_feedback_stream(codigo, analise):
    """
    Versão STREAMING do feedback: um gerador que entrega o texto TOKEN A TOKEN.

    Usada pela API (endpoint /feedback via SSE). Diferenças em relação ao gerar_feedback:
      • prompt com saida="texto" (sem envelope JSON) -> o texto que chega já é o feedback;
      • Ollama SEM "format": "json" -> saída em texto natural, não objeto;
      • em vez de acumular e retornar, faz `yield` de cada pedaço conforme o Ollama envia.

    Como a saída é texto puro em stream, a validação/retentativa por JSON e o filtro
    anti-vazamento pós-JSON do gerar_feedback não se aplicam aqui. A proibição anti-vazamento
    continua NO PROMPT (REGRA 1); um filtro determinístico sobre o texto streamado pode ser
    somado depois, como etapa à parte.
    """
    prompt = montar_prompt_feedback(codigo, analise, saida="texto")

    # stream=True (requests) -> lê a resposta em pedaços; "stream": True (Ollama) -> o
    # modelo emite token a token. SEM "format": "json" para o texto sair natural.
    resposta = requests.post(URL_LLM_LOCAL, json={
        "model": NOME_MODELO,
        "prompt": prompt,
        "stream": True,
        "keep_alive": LLM_KEEP_ALIVE,              # mantém o modelo carregado (evita cold start)
        "options": {"temperature": TEMPERATURA_FEEDBACK},
    }, stream=True, timeout=LLM_TIMEOUT_S)          # generoso: 1ª chamada carrega o modelo

    for linha in resposta.iter_lines():
        if not linha:
            continue
        try:
            pedaco = json.loads(linha.decode("utf-8")).get("response", "")
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue  # linha keep-alive/incompleta: ignora e segue
        if pedaco:
            yield pedaco   # <-- cada token vai direto para o SSE (efeito "digitando")
