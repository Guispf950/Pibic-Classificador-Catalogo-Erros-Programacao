import requests  # Biblioteca para fazer requisições HTTP (chamar a API do LLM)
import json      # Para serializar/desserializar dados no formato JSON
import re        # Para extrair as linhas do log e ancorar as anotações inline
import sys       # Importado para uso futuro (ex: sys.exit em erros fatais)
import time      # Para backoff entre tentativas de retry

# Configuração central: endereço/modelo/temperatura do LLM e o modo de anotação
# (a variável dos experimentos de ablação). Ver src/config.py.
from src.config import URL_LLM_LOCAL, NOME_MODELO, TEMPERATURA_LLM, MODO_ANOTACAO

# Classificação DETERMINÍSTICA do erro para CWE (a partir do log da ferramenta).
from src.cwe import classificar_cwe


def _chamar_llm(prompt, tentativa=1):
    """
    Executa uma chamada ao Ollama e retorna o texto completo gerado.
    Retorna string vazia se o servidor não gerar nenhum token.
    """
    resposta = requests.post(URL_LLM_LOCAL, json={
        "model": NOME_MODELO,
        "prompt": prompt,
        "stream": True,
        "format": "json",
        "options": {"temperature": TEMPERATURA_LLM}   # vem do config central
    }, stream=True, timeout=120)

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
#
# POR QUÊ (fundamentação):
#   O FLAME mostra, por ablação, que ANOTAR a linha do erro com um comentário no
#   código (// @@ explicação) supera de longe passar o NÚMERO da linha em texto:
#   no dataset deles o top-1 cai de 62,7% -> 15,8% quando se usa referência numérica.
#   A razão é a limitação inerente de "numerical understanding" das LLMs.
#
# NOSSA VANTAGEM SOBRE O FLAME:
#   No FLAME é a própria LLM que anota, e ao reformatar o código o marcador // @@
#   desalinha — por isso eles precisam de "fuzzy matching" (similaridade de cosseno).
#   Aqui, quem anota é o PIPELINE, ancorando o comentário na LINHA EXATA que a
#   ferramenta (ASan/Valgrind) reportou. Isso é DETERMINÍSTICO e dispensa o fuzzy
#   matching inteiro — mais simples e mais confiável.
#
# SINTOMA vs CAUSA (FCS/Lancet):
#   A linha onde o erro DISPARA (sintoma) raramente é onde ele NASCE (causa). Como o
#   backtrace do ASan/Valgrind dá os dois pontos (o free/creation e o uso), anotamos
#   AMBOS — mas SÓ quando a ferramenta os fornece deterministicamente. Nada é inferido.

# As regras de detecção de seção (SINTOMA/CAUSA/VAZAMENTO/ORIGEM) foram extraídas para
# um módulo próprio (src/regras_secao.py) — o único lugar que conhece o texto do ASan/
# Valgrind. Para adicionar ou ajustar uma classe de erro, edite REGRAS_SECAO lá.
from src.regras_secao import REGRAS_SECAO


def _extrair_pontos_anotacao(log, nome_arquivo):
    """
    Varre o log (idealmente o BRUTO, para não depender do que o parser manteve) e extrai,
    de forma DETERMINÍSTICA, os pontos que a ferramenta
    reportou no código do aluno, associando cada um a um papel:

        SINTOMA   -> onde o erro se manifesta (o acesso/uso que dispara a falha)
        CAUSA     -> onde o erro nasce (o free do bloco, ou a criação do valor não inic.)
        VAZAMENTO -> a alocação cuja memória nunca é liberada (para leaks)
        ORIGEM    -> onde o bloco foi alocado (informação extra, não anotada por padrão)

    Retorna um dict {papel: (numero_da_linha, texto_do_comentario)}. Só inclui um papel
    quando a ferramenta de fato forneceu aquela linha, nunca inventa.
    """
    if not nome_arquivo:
        return {}

    # REGEX 1 — acha "<arquivo>:<numero>" (ex.: "submissao_5.c:118") em qualquer frame.
    #   re.escape(nome_arquivo) -> transforma o nome num literal SEGURO: o "." de ".c" é
    #       um metacaractere (casaria qualquer char); escapado vira "\." (ponto literal).
    #   ":(\d+)" -> dois-pontos literal, e "(\d+)" captura UM OU MAIS dígitos (\d=dígito,
    #       +=um ou mais). Os parênteses formam o grupo 1, recuperado depois com m.group(1).
    padrao_linha = re.compile(re.escape(nome_arquivo) + r":(\d+)")
    # REGEX 2 — distingue frame do GDB de frame do Valgrind, para IGNORAR os do GDB.
    #   As linhas devem vir do relatório ESTRUTURADO (que separa sintoma/free/alloc em
    #   seções), não do backtrace linear do GDB. O truque está no formato do "at":
    #     GDB:      "... at ./caminho/submissao.c:23"   (arquivo logo após "at ")
    #     Valgrind: "... at 0x4001654: func (submissao.c:118)"  ("at 0x", com espaço depois)
    #   \b = fronteira de palavra (o "at" isolado, não o "at" de "altura");
    #   \s+ = um ou mais espaços;  \S* = qualquer sequência SEM espaço (o caminho).
    #   Logo, "\S*<arquivo>" alcança o nome no caso do GDB, mas NÃO no do Valgrind (onde
    #   depois de "at " vem "0x..." e um espaço, que \S* não atravessa).
    padrao_gdb = re.compile(r"\bat\s+\S*" + re.escape(nome_arquivo))

    pontos = {}         # papel -> (linha, rotulo)
    veio_do_gdb = {}    # papel -> bool: a linha guardada veio de um frame do GDB?
    papel_atual = None  # (papel, rotulo) da seção sendo lida no momento

    # ESTRATÉGIA: preferir frames ESTRUTURADOS (relatório do ASan/Valgrind, que separa
    # sintoma/free/alloc) e usar os frames do GDB apenas como FALLBACK — quando são a única
    # fonte. Isso é essencial para o SIGSEGV puro (null-deref), em que o ASan NÃO gera
    # relatório e a linha só existe no backtrace do GDB. Antes esses frames eram descartados
    # e o crash ficava sem anotação.
    for busca in log.split("\n"):
        linha = busca.strip()

        # Este frame é do GDB? ("... at <caminho>/<arquivo>"). Não descartamos mais de cara;
        # apenas marcamos, para o estruturado ter prioridade sobre ele.
        eh_gdb = bool(padrao_gdb.search(linha))

        # --- Detecta início/troca de SEÇÃO (primeira regra cujo regex casa) ---
        for papel, rotulo, rx in REGRAS_SECAO:
            if rx.search(linha):
                papel_atual = (papel, rotulo)
                break

        # --- Extrai a linha do aluno pertencente à seção atual ---
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
                    # Já tínhamos só um frame do GDB, mas chegou um ESTRUTURADO — ele vence.
                    pontos[papel] = (num, papel_atual[1])
                    veio_do_gdb[papel] = False

    return pontos


def _anotar_codigo(codigo_fonte, pontos):
    """
    Injeta comentários `// @@ [PAPEL] explicação` no FIM das linhas exatas reportadas
    pela ferramenta. Por decisão de projeto, anotamos apenas SINTOMA, CAUSA e VAZAMENTO
    (os pontos que a ferramenta fornece deterministicamente).

    Ancoragem determinística: como a linha vem da ferramenta, o marcador cai sempre no
    lugar certo.
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
            # Se a linha já tiver uma anotação (ex.: sintoma e causa na mesma linha),
            # acrescenta a segunda em vez de sobrescrever.
            if "// @@" in linhas[numLinha]:
                linhas[numLinha] = linhas[numLinha].rstrip() + f"  | [{papel}] {rotulo}"
            else:
                linhas[numLinha] = linhas[numLinha].rstrip() + comentario
    return "\n".join(linhas)


# Regex de uma DECLARAÇÃO DE VARIÁVEL SEM INICIALIZADOR: "<tipo> <nome>;".
# Aceita tipos primitivos, ponteiros, typedefs iniciados por maiúscula (ex.: TAVL, Node)
# e nomes terminados em _t (ex.: size_t). Exige ";" logo após o nome (sem "= ..."), o que
# EXCLUI declarações já inicializadas ("int res = 0;") e statements comuns ("return res;",
# que não começa com um tipo). É deliberadamente conservador — na dúvida, não casa.
_TIPO_C = r"(?:const\s+)?(?:unsigned\s+|signed\s+)?(?:int|char|short|long|float|double|void|bool|[A-Z]\w*|\w+_t)\s*\**"
_DECL_SEM_INIT = re.compile(rf"^\s*{_TIPO_C}\s+(\w+)\s*;")


def _fim_da_funcao(linhas, linha_abertura):
    """
    Retorna o número (1-based) da linha do '}' que FECHA a função aberta em 'linha_abertura',
    por CASAMENTO DE CHAVES. Ignora chaves dentro de strings "...", chars '...' e comentários
    (// e /* */), para não ser enganado por coisas como  char c = '}';  ou  /* } */.

    É o limite superior ROBUSTO da varredura (substitui a antiga janela fixa de 40 linhas):
    garante que nunca cruzamos para a função seguinte. Se as chaves não fecharem, devolve a
    última linha do arquivo (degradação segura).
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

    POR QUÊ: o Valgrind, para um valor não inicializado vindo da pilha, reporta a origem na
    linha de ABERTURA DA FUNÇÃO (o frame inteiro é alocado de uma vez) — não na declaração
    da variável. Aqui movemos a marca da CAUSA para a DECLARAÇÃO sem inicializador, que é o
    ponto pedagogicamente correto ("você declarou X sem dar um valor").

    TRAVA DE SEGURANÇA (nunca piora o que já existe): só refina se
      (a) a CAUSA é do tipo "não inicializado" (pelo rótulo);
      (b) a linha da CAUSA é mesmo uma ABERTURA DE FUNÇÃO (tem '(' e '{'), i.e., o caso do
          frame — não uma origem de heap (malloc), que deve permanecer onde está;
      (c) existe EXATAMENTE UMA declaração sem inicializador entre a função e o uso.
    Se qualquer condição falhar, devolve os pontos INALTERADOS (fica na linha da função).
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

    # Intervalo a varrer: da abertura da função até o fim REAL dela (casamento de chaves),
    # de modo que a varredura NUNCA cruze para a função seguinte. Se houver SINTOMA (o uso),
    # usamos o MENOR entre ele e o fim da função — janela ainda mais justa (a declaração
    # está sempre entre a abertura e o uso), evitando declarações de outros ramos após o uso.
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
    Escolhe DETERMINISTICAMENTE uma linha REAL do relatório da ferramenta para servir de
    evidência (ex.: "==NNNN== ... definitely lost" ou "ERROR: AddressSanitizer: ...").

    É a rede de segurança do campo 'evidencia_log': se a LLM copiar a anotação // @@
    (que é rótulo NOSSO, não prova) ou deixar o campo vazio, trocamos por esta linha real.

    Estratégia: retorna a PRIMEIRA linha que casa uma regra de SINTOMA/VAZAMENTO (o
    cabeçalho do erro). Se nenhuma casar, cai na primeira linha não-vazia; no limite, "-".
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
def classificar_erro(log_limpo, codigo_fonte="", nome_arquivo="", log_bruto="", max_tentativas=3):
    """
    Anota o código-fonte com os pontos que a ferramenta reportou (inline, // @@) e
    envia esse CÓDIGO ANOTADO para o LLM local, que EXPLICA e CLASSIFICA o erro.

    Diferença central em relação à versão anterior: a LLM NÃO recebe mais números de
    linha em texto (veneno para o modelo, per FLAME) nem precisa devolvê-los — a
    localização já está marcada no código e é preenchida deterministicamente no resultado.

    Retorna um dict com a classificação (campos da IA + linhas determinísticas).
    """
    # 1) Extrai os pontos da ferramenta e monta o código anotado (determinístico).
    #    Prefere o log BRUTO (todas as seções presentes) e cai no limpo se não vier.
    pontos = _extrair_pontos_anotacao(log_bruto or log_limpo, nome_arquivo)
    # Refina a CAUSA de valor não inicializado: da abertura da função (o que o Valgrind
    # dá) para a DECLARAÇÃO da variável, quando ela é inequívoca. Determinístico, no fonte.
    pontos = _refinar_causa_uninit(pontos, codigo_fonte)
    codigo_anotado = _anotar_codigo(codigo_fonte, pontos)

    # Linhas determinísticas (vêm da ferramenta, não da LLM):
    linha_sintoma = str(pontos["SINTOMA"][0]) if "SINTOMA" in pontos else (
        str(pontos["VAZAMENTO"][0]) if "VAZAMENTO" in pontos else "-")
    linha_causa = str(pontos["CAUSA"][0]) if "CAUSA" in pontos else "-"

    # CWE DETERMINÍSTICO — vem do log da FERRAMENTA (não do LLM). Serve de rótulo padrão
    # e de checagem de consistência contra o `tipo_erro` que o modelo devolver.
    cwe_id, cwe_nome = classificar_cwe(log_bruto or log_limpo)

    # 2) Monta o prompt conforme o MODO de anotação (ablação estilo FLAME).
    #    O que MUDA entre os modos é SÓ como a localização do erro chega à LLM; o resto
    #    (veredito, esquema JSON, regras 1–3) é idêntico, para isolar essa variável.
    print(f"  -> [modo anotação] {MODO_ANOTACAO}")
    if MODO_ANOTACAO == "inline":
        intro = (
            "O CÓDIGO abaixo já foi ANOTADO deterministicamente pela ferramenta (ASan/Valgrind).\n"
            "Comentários `// @@` marcam os pontos: [SINTOMA] onde o erro se manifesta; "
            "[CAUSA] onde ele nasce; [VAZAMENTO] a alocação vazada.\n"
            "Confie nessas anotações: elas já marcam os pontos EXATOS."
        )
        cabecalho_codigo = "===== CÓDIGO DO ALUNO (JÁ ANOTADO PELA FERRAMENTA) ====="
        corpo_codigo = codigo_anotado
        regra_extra = ('4. As anotações `// @@` são RÓTULOS nossos. NÃO as use como evidência: o campo\n'
                       '   "evidencia_log" deve conter uma linha REAL do VEREDITO abaixo.\n')
    elif MODO_ANOTACAO == "numerica":
        _dicas = []
        if linha_sintoma != "-":
            _dicas.append(f"SINTOMA na linha {linha_sintoma}")
        if linha_causa != "-":
            _dicas.append(f"CAUSA na linha {linha_causa}")
        _dica_txt = "; ".join(_dicas) if _dicas else "linha não fornecida"
        intro = (
            "O CÓDIGO abaixo é o do aluno (SEM anotações). A ferramenta (ASan/Valgrind) LOCALIZOU o\n"
            f"erro nestas linhas: {_dica_txt}. Use esses NÚMEROS para achar o ponto no código."
        )
        cabecalho_codigo = "===== CÓDIGO DO ALUNO ====="
        corpo_codigo = codigo_fonte
        regra_extra = ""
    else:  # "nenhuma" (baseline)
        intro = (
            "O CÓDIGO abaixo é o do aluno. A ferramenta detectou um erro (veja o VEREDITO).\n"
            "Identifique no código onde o erro ocorre e classifique-o."
        )
        cabecalho_codigo = "===== CÓDIGO DO ALUNO ====="
        corpo_codigo = codigo_fonte
        regra_extra = ""

    secao_codigo = f"\n{cabecalho_codigo}\n```c\n{corpo_codigo}\n```\n" if corpo_codigo else ""

    prompt = f"""
Você é um analisador forense de erros em C.

{intro}

REGRAS (obrigatórias):
1. Baseie-se APENAS no material fornecido (código + veredito); não invente erros não indicados.
2. NÃO cite funções, variáveis ou linhas que não apareçam no material.
3. Se algo não estiver claro, escreva "indeterminado" em vez de supor.
{regra_extra}{secao_codigo}
===== VEREDITO DA FERRAMENTA (apoio) =====
{log_limpo}
===== FIM DO VEREDITO =====

Retorne APENAS um objeto JSON válido (sem markdown, sem texto fora do JSON):
{{
    "tipo_erro": "nome técnico (ex.: 'heap-use-after-free', 'use-after-scope', 'uninitialized-value', 'memory-leak', 'double-free', 'invalid-free', 'null-pointer-dereference')",
    "variaveis_envolvidas": "variáveis citadas no material e seus valores, se houver (ex.: res=-132143025). Ponteiros como nome* (ex.: raiz*). Só o que aparece explicitamente.",
    "causa_raiz": "explique POR QUE o erro ocorre (o encadeamento entre onde ele nasce e onde se manifesta)",
    "descricao_curta": "1 frase explicando o erro de forma técnica e objetiva",
    "evidencia_log": "cópia LITERAL de uma linha do VEREDITO DA FERRAMENTA (ex.: uma linha com '==NNNN==' ou '#N ... arquivo.c:linha'). NUNCA invente nem copie uma anotação // @@."
}}
"""

    ultimo_erro = None

    for tentativa in range(1, max_tentativas + 1):
        try:
            texto_completo = _chamar_llm(prompt, tentativa)

            # Resposta vazia: Ollama não gerou nenhum token (sobrecarga/timeout interno)
            if not texto_completo.strip():
                raise ValueError("Ollama retornou resposta vazia (nenhum token gerado).")

            resultado = json.loads(_sanitizar(texto_completo))

            # 3) Injeta as linhas DETERMINÍSTICAS (da ferramenta), não confiando na LLM para isso.
            resultado["linha_sintoma"] = linha_sintoma
            resultado["linha_causa"] = linha_causa
            # Compatibilidade com o catálogo existente (coluna "Linha" = sintoma).
            resultado["linha_ocorrencia"] = linha_sintoma
            # Código com as anotações inline (// @@), para o orquestrador salvar como arquivo.
            resultado["codigo_anotado"] = codigo_anotado
            # CWE determinístico (da ferramenta) — não confia na LLM para isso.
            resultado["cwe_id"] = cwe_id
            resultado["cwe_nome"] = cwe_nome

            # SALVAGUARDA do 'evidencia_log': ele deve ser uma linha REAL do relatório, não o
            # rótulo // @@ (que é padrão nosso). Se a LLM copiou a anotação, ou deixou vazio,
            # substituímos deterministicamente por uma linha de verdade do log da ferramenta.
            ev = str(resultado.get("evidencia_log", "")).strip()
            if (not ev) or ev in ("-", "'-'") or "@@" in ev:
                resultado["evidencia_log"] = _evidencia_do_log(log_bruto or log_limpo)
            return resultado

        except (json.JSONDecodeError, ValueError) as e:
            ultimo_erro = e
            if tentativa < max_tentativas:
                espera = 2 ** (tentativa - 1)  # backoff: 1s, 2s, 4s
                print(f"  [Retry {tentativa}/{max_tentativas}] {str(e)} — aguardando {espera}s...")
                time.sleep(espera)

        except Exception as e:
            # Falha de rede, timeout de conexão, servidor offline, etc.
            ultimo_erro = e
            if tentativa < max_tentativas:
                espera = 2 ** (tentativa - 1)
                print(f"  [Retry {tentativa}/{max_tentativas}] Erro de rede: {str(e)} — aguardando {espera}s...")
                time.sleep(espera)

    # Todas as tentativas esgotadas — devolve o esqueleto com as linhas determinísticas.
    print(f"\n[Aviso] IA falhou após {max_tentativas} tentativas. Último erro: {str(ultimo_erro)}")
    return {
        "tipo_erro": "Falha no Pipeline",
        "linha_sintoma": linha_sintoma,
        "linha_causa": linha_causa,
        "linha_ocorrencia": linha_sintoma,
        "variaveis_envolvidas": "-",
        "causa_raiz": "-",
        "descricao_curta": f"LLM não respondeu após {max_tentativas} tentativas: {str(ultimo_erro)}",
        "evidencia_log": "-",
        "codigo_anotado": codigo_anotado,
        "cwe_id": cwe_id,
        "cwe_nome": cwe_nome
    }
