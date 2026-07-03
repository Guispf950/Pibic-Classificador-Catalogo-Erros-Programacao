"""
Detecção de parâmetro de escala e geração de stdin automático.

Este módulo é COMPARTILHADO pela Malha 1 (ASan+GDB) e pela Malha 2 (Valgrind+vgdb).
Seu objetivo é evitar que programas que leem dados via scanf travem os subprocessos
de análise (GDB/Valgrind) aguardando input do terminal.

Historicamente essas funções viviam dentro do perfilador de desempenho (Malha 3).
Com a remoção da Malha 3 do pipeline, elas foram extraídas para cá — são a única
parte daquele módulo de que as malhas de memória ainda dependem.
"""

import re


# ══════════════════════════════════════════════════════════════════════════════
# DETECÇÃO DO PARÂMETRO DE ESCALA
# ══════════════════════════════════════════════════════════════════════════════

def detectar_parametro_escala(codigo_fonte):
    """
    Lê o código C do aluno e determina se ele possui um parâmetro de tamanho N
    controlável via stdin (Cenário A) ou não (Cenário B).

    A detecção funciona em duas etapas:
      1. Encontra um scanf que lê EXATAMENTE um inteiro: scanf("%d", &var)
         (exclui formatos compostos como "%d %d" que indicam entradas fixas)
      2. Confirma que essa variável controla um laço ou uma alocação dinâmica,
         ou seja, que ela realmente representa o "tamanho" do problema.

    Retorna o nome da variável de escala (ex: "n", "k") ou None se for Cenário B.
    """

    # Remove comentários de linha (//) e de bloco (/* */) antes de analisar.
    # Sem isso, um scanf comentado poderia ser detectado como parâmetro de escala.
    codigo = re.sub(r'//.*', '', codigo_fonte)
    codigo = re.sub(r'/\*.*?\*/', '', codigo, flags=re.DOTALL)

    # Busca scanf que lê EXATAMENTE um inteiro ("%d"), sem outros especificadores.
    # O grupo(2) captura o nome da variável (ex: "k" em scanf("%d", &k)).
    # Exemplos aceitos: scanf("%d", &n)  → detectado
    # Exemplos rejeitados: scanf("%d %d", &a, &b)  → ignorado (entrada composta)
    matches = list(re.finditer(
        r'scanf\s*\(\s*"(%d)"\s*,\s*&\s*(\w+)\s*\)',
        codigo
    ))

    for m in matches:
        var = m.group(2)  # nome da variável lida pelo scanf (ex: "n", "k", "tam")

        # Verifica se a variável realmente representa o "tamanho" do problema,
        # checando se ela aparece como limite de laço ou tamanho de alocação.
        usada_como_tamanho = (
            # for(int i = 0; i < var; ...) — var como limite superior de for
            re.search(rf'for\s*\([^;]*;\s*[^;]*{re.escape(var)}[^;]*;', codigo)
            # while(i < var) ou while(var > 0) — var como condição de parada
            or re.search(rf'while\s*\([^)]*{re.escape(var)}', codigo)
            # malloc(var * sizeof(...)) — var como quantidade de elementos alocados
            or re.search(rf'malloc\s*\([^)]*{re.escape(var)}', codigo)
            # calloc(var, sizeof(...)) — mesmo caso acima com calloc
            or re.search(rf'calloc\s*\([^)]*{re.escape(var)}', codigo)
            # int arr[var] — VLA (Vetor de Tamanho Variável) usando var como tamanho
            or re.search(rf'\[\s*{re.escape(var)}\s*\]', codigo)
        )

        # Se a variável controla tamanho, este é o parâmetro de escala do Cenário A
        if usada_como_tamanho:
            return var

    # Nenhuma variável de escala encontrada → Cenário B (entrada fixa)
    return None


# ══════════════════════════════════════════════════════════════════════════════
# GERAÇÃO DE ENTRADA
# ══════════════════════════════════════════════════════════════════════════════

def gerar_entrada_para_n(N, formato="N_ESPACO_VALORES"):
    """
    Gera a string enviada pelo stdin do programa para um dado N.

    Padrão CodeBench mais comum:
        Linha 1 → o número N (tamanho da entrada)
        Linha 2 → N inteiros separados por espaço (os dados a processar)

    Compatível com scanf("%d", &arr[i]) tanto em loop (lê um por chamada)
    quanto em linha única — o scanf com %d ignora whitespace automaticamente.
    """
    if formato == "N_ESPACO_VALORES":
        # Gera N inteiros sequenciais (1, 2, 3, ..., N) separados por espaço.
        # Valores crescentes (em vez de constantes) evitam que o branch predictor
        # da CPU distorça a execução do código do aluno.
        valores = " ".join(str(i + 1) for i in range(N))
        return f"{N}\n{valores}\n"  # ex: "5\n1 2 3 4 5\n"

    elif formato == "N_LINHA_POR_LINHA":
        # Variante onde cada valor ocupa uma linha separada (alguns exercícios pedem isso)
        valores = "\n".join(str(i + 1) for i in range(N))
        return f"{N}\n{valores}\n"  # ex: "5\n1\n2\n3\n4\n5\n"

    # Fallback: envia apenas N, sem dados adicionais (para quem só lê o tamanho)
    return f"{N}\n"


# ══════════════════════════════════════════════════════════════════════════════
# STDIN AUTOMÁTICO PARA AS MALHAS DE MEMÓRIA
# ══════════════════════════════════════════════════════════════════════════════

def stdin_para_analise(caminho_codigo):
    """
    Gera um stdin mínimo para exercitar o código durante a análise de memória
    (Malha 1 e 2), evitando que o processo trave aguardando input do terminal.

    Lógica:
        Se o código lê um inteiro N via scanf e o usa como tamanho de array/laço,
        gera a string "5\\n1 2 3 4 5\\n" — suficiente para exercitar o algoritmo
        (malloc/free, acessos a vetor) sem sobrecarregar a análise.

        Se o código não tem parâmetro de escala (entrada fixa, ex: "some 3 números"),
        retorna None → o processo herda o stdin do terminal normalmente.

    Por que N=5 e não N=100?
        As malhas 1/2 testam CORREÇÃO de memória, não desempenho. N=5 já exercita
        malloc/free e detecta buffer overflow sem aumentar o tempo do Valgrind.

    Limitações conhecidas (assumidas):
        - Cobre apenas o padrão scanf("%d", &var) com um único %d controlando escala.
        - Entradas compostas (ex: "%d %d") ou formatos não-canônicos não são cobertos;
          nesses casos retorna None e o processo herda o stdin do ambiente.
    """
    try:
        with open(caminho_codigo, 'r', encoding='utf-8', errors='replace') as f:
            codigo = f.read()
        if detectar_parametro_escala(codigo):
            return gerar_entrada_para_n(5)   # "5\n1 2 3 4 5\n"
    except Exception:
        pass
    return None  # sem stdin automático — herda do ambiente
