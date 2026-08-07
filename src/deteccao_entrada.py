"""
Detecção de parâmetro de escala e geração de stdin para as malhas de memória.

Este módulo é COMPARTILHADO pela Malha 1 (ASan+GDB) e pela Malha 2 (Valgrind+vgdb).
Seu objetivo é fornecer o stdin que exercita o código durante a análise de memória,
evitando que os subprocessos (GDB/Valgrind) travem aguardando input do terminal.

Fonte de entrada, em ordem de prioridade:
  1. Caso de teste REAL por arquivo (<nome>.in ao lado do <nome>.c).
  2. Caso de teste REAL compartilhado pela pasta (_entrada.in no mesmo diretório) —
     útil quando a pasta contém várias submissões do MESMO exercício (que, por serem
     o mesmo problema, compartilham exatamente a mesma entrada).
  3. Heurística de escala (fallback): reconhece scanf("%d", &var) e sintetiza uma
     entrada mínima.
  4. Nenhuma: entrada fixa não reconhecida — herda o stdin do ambiente.

O texto do .in é a entrada REAL do exercício (o mesmo que o CodeBench já armazena por
questão), o que elimina a adivinhação do stdin e cobre qualquer formato de entrada.
"""

import os
import re


# Nome convencional do arquivo de entrada COMPARTILHADO por uma pasta de submissões
# do mesmo exercício. Quando não há um <nome>.in específico, este é usado por todos
# os .c do diretório.
NOME_ENTRADA_COMPARTILHADA = "_entrada.in"


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
# GERAÇÃO DE ENTRADA (fallback heurístico)
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
# CASO DE TESTE REAL (arquivo .in)
# ══════════════════════════════════════════════════════════════════════════════

def caminho_caso_de_teste(caminho_codigo):
    """
    Devolve o caminho do arquivo de entrada real (.in) associado ao .c, ou None.

    Procura em duas convenções, nesta ordem:
      1. POR ARQUIVO — mesmo nome-base do .c, no mesmo diretório:
            data/teste_avl.c  ->  data/teste_avl.in
      2. COMPARTILHADO POR PASTA — um único "_entrada.in" no mesmo diretório, usado
         por TODOS os .c da pasta:
            .../submissoes/submissao_1.c ─┐
            .../submissoes/submissao_2.c ─┼─►  .../submissoes/_entrada.in
            .../submissoes/submissao_3.c ─┘
         Ideal para pastas que contêm várias submissões do MESMO exercício: como o
         problema é o mesmo, a entrada é a mesma — evita duplicar um .in por arquivo.

    O .in por arquivo tem prioridade sobre o compartilhado (permite exceções pontuais).
    """
    # 1) por arquivo: <nome>.in
    caminho_in = os.path.splitext(caminho_codigo)[0] + ".in"
    if os.path.isfile(caminho_in):
        return caminho_in

    # 2) compartilhado por pasta: _entrada.in no mesmo diretório
    pasta = os.path.dirname(os.path.abspath(caminho_codigo))
    compartilhado = os.path.join(pasta, NOME_ENTRADA_COMPARTILHADA)
    if os.path.isfile(compartilhado):
        return compartilhado

    return None


def _ler_caso_de_teste(caminho_codigo):
    """
    Lê o conteúdo do .in associado (por arquivo ou compartilhado) e o retorna como
    string. Retorna None quando não há caso de teste cadastrado ou o arquivo é vazio.
    """
    caminho_in = caminho_caso_de_teste(caminho_codigo)
    if caminho_in is None:
        return None
    try:
        with open(caminho_in, 'r', encoding='utf-8', errors='replace') as f:
            conteudo = f.read()
    except Exception:
        return None

    # .in vazio/whitespace não serve como entrada — trata como ausente
    if conteudo.strip() == "":
        return None

    # Garante uma quebra de linha final (o scanf espera terminadores previsíveis)
    if not conteudo.endswith("\n"):
        conteudo = conteudo + "\n"

    return conteudo


# ══════════════════════════════════════════════════════════════════════════════
# STDIN PARA AS MALHAS DE MEMÓRIA
# ══════════════════════════════════════════════════════════════════════════════

def stdin_para_analise(caminho_codigo):
    """
    Escolhe o stdin que exercita o código durante a análise de memória (Malha 1 e 2),
    evitando que o processo trave aguardando input do terminal.

    ORDEM DE PRIORIDADE:
      1. CASO DE TESTE REAL (.in por arquivo ou _entrada.in da pasta): usa o texto real
         do exercício (o que o CodeBench já cadastra). Fonte preferida.
      2. HEURÍSTICA (fallback): sem .in, tenta detectar um parâmetro de escala
         (scanf("%d", &var) com um único %d) e sintetiza "5\\n1 2 3 4 5\\n".
      3. NENHUMA: entrada fixa não reconhecida → None (o processo herda o stdin do ambiente).

    Por que o .in vem primeiro?
        A adivinhação por regex é frágil (só pega o padrão canônico). O ".in" real
        elimina a adivinhação: cobre listas, matrizes e formatos
        compostos que a heurística nunca cobriria — antecipando a integração com os
        casos de teste que o CodeBench já armazena por questão.
    """
    # 1) Caso de teste real (.in por arquivo ou compartilhado da pasta) — fonte preferida
    caso = _ler_caso_de_teste(caminho_codigo)
    if caso is not None:
        nome_in = os.path.basename(caminho_caso_de_teste(caminho_codigo))
        print(f"  -> [entrada] usando caso de teste real: {nome_in}")
        return caso

    # 2) Heurística de escala (fallback), só quando não há .in cadastrado
    try:
        with open(caminho_codigo, 'r', encoding='utf-8', errors='replace') as f:
            codigo = f.read()
        if detectar_parametro_escala(codigo):
            print("  -> [entrada] sem .in; usando heurística de escala (N=5)")
            return gerar_entrada_para_n(5)   # "5\n1 2 3 4 5\n"
    except Exception:
        pass

    # 3) Sem entrada automática — herda do ambiente
    return None
