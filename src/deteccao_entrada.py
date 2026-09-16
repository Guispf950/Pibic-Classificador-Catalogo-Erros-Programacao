"""
Detecção de parâmetro de escala e geração de stdin para as malhas de memória.

Compartilhado pela Malha 1 (ASan+GDB) e pela Malha 2 (Valgrind+vgdb). Fornece o stdin que
exercita o código durante a análise, evitando que GDB/Valgrind travem aguardando input.

Fonte de entrada, em ordem de prioridade:
  1. Caso de teste REAL por arquivo (<nome>.in ao lado do <nome>.c).
  2. Caso de teste REAL compartilhado pela pasta (_entrada.in no mesmo diretório) — útil
     quando a pasta reúne várias submissões do MESMO exercício (mesma entrada).
  3. Heurística de escala (fallback): reconhece scanf("%d", &var) e sintetiza entrada mínima.
  4. Nenhuma: entrada fixa não reconhecida — herda o stdin do ambiente.

O texto do .in é a entrada real do exercício (a mesma que o CodeBench já armazena por questão),
o que elimina a adivinhação do stdin e cobre qualquer formato de entrada.
"""

import os
import re


# Nome convencional do arquivo de entrada COMPARTILHADO por uma pasta de submissões do mesmo
# exercício. Sem um <nome>.in específico, este é usado por todos os .c do diretório.
NOME_ENTRADA_COMPARTILHADA = "_entrada.in"


# ══════════════════════════════════════════════════════════════════════════════
# DETECÇÃO DO PARÂMETRO DE ESCALA
# ══════════════════════════════════════════════════════════════════════════════

def detectar_parametro_escala(codigo_fonte):
    """
    Determina se o código tem um parâmetro de tamanho N controlável via stdin (Cenário A)
    ou não (Cenário B). Retorna o nome da variável de escala (ex.: "n", "k") ou None.

    Duas etapas: (1) encontra um scanf que lê EXATAMENTE um inteiro — scanf("%d", &var),
    excluindo formatos compostos como "%d %d"; (2) confirma que a variável controla um laço
    ou uma alocação dinâmica, ou seja, representa de fato o "tamanho" do problema.
    """

    # Remove comentários (// e /* */) antes de analisar, para não detectar um scanf comentado.
    codigo = re.sub(r'//.*', '', codigo_fonte)
    codigo = re.sub(r'/\*.*?\*/', '', codigo, flags=re.DOTALL)

    # scanf que lê EXATAMENTE um inteiro ("%d"); group(2) captura o nome da variável.
    # Aceita scanf("%d", &n); rejeita scanf("%d %d", &a, &b) (entrada composta).
    matches = list(re.finditer(
        r'scanf\s*\(\s*"(%d)"\s*,\s*&\s*(\w+)\s*\)',
        codigo
    ))

    for m in matches:
        var = m.group(2)  # nome da variável lida pelo scanf

        # Confirma que a variável representa o "tamanho": aparece como limite de laço ou
        # tamanho de alocação.
        usada_como_tamanho = (
            re.search(rf'for\s*\([^;]*;\s*[^;]*{re.escape(var)}[^;]*;', codigo)  # limite de for
            or re.search(rf'while\s*\([^)]*{re.escape(var)}', codigo)            # condição de while
            or re.search(rf'malloc\s*\([^)]*{re.escape(var)}', codigo)           # qtd em malloc
            or re.search(rf'calloc\s*\([^)]*{re.escape(var)}', codigo)           # qtd em calloc
            or re.search(rf'\[\s*{re.escape(var)}\s*\]', codigo)                 # VLA int arr[var]
        )

        if usada_como_tamanho:
            return var

    return None   # Cenário B (entrada fixa)


# ══════════════════════════════════════════════════════════════════════════════
# GERAÇÃO DE ENTRADA (fallback heurístico)
# ══════════════════════════════════════════════════════════════════════════════

def gerar_entrada_para_n(N, formato="N_ESPACO_VALORES"):
    """
    Gera a string enviada pelo stdin para um dado N.
    Padrão CodeBench mais comum: linha 1 com N, linha 2 com N inteiros separados por espaço.
    Compatível com scanf("%d", &arr[i]) em loop ou em linha única (o %d ignora whitespace).
    """
    if formato == "N_ESPACO_VALORES":
        # N inteiros crescentes (1..N): valores crescentes evitam que o branch predictor da
        # CPU distorça a execução do código.
        valores = " ".join(str(i + 1) for i in range(N))
        return f"{N}\n{valores}\n"  # ex.: "5\n1 2 3 4 5\n"

    elif formato == "N_LINHA_POR_LINHA":
        # Variante com cada valor em uma linha (alguns exercícios pedem isso).
        valores = "\n".join(str(i + 1) for i in range(N))
        return f"{N}\n{valores}\n"  # ex.: "5\n1\n2\n3\n4\n5\n"

    # Fallback: apenas N, sem dados adicionais.
    return f"{N}\n"


# ══════════════════════════════════════════════════════════════════════════════
# CASO DE TESTE REAL (arquivo .in)
# ══════════════════════════════════════════════════════════════════════════════

def caminho_caso_de_teste(caminho_codigo):
    """
    Devolve o caminho do .in associado ao .c, ou None. Procura, nesta ordem:
      1. POR ARQUIVO — mesmo nome-base do .c (data/teste_avl.c -> data/teste_avl.in);
      2. COMPARTILHADO POR PASTA — um único "_entrada.in" no diretório, usado por todos os .c
         (ideal para pastas com várias submissões do mesmo exercício: mesma entrada).
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
    Lê o conteúdo do .in associado (por arquivo ou compartilhado) como string.
    Retorna None quando não há caso de teste cadastrado ou o arquivo é vazio.
    """
    caminho_in = caminho_caso_de_teste(caminho_codigo)
    if caminho_in is None:
        return None
    try:
        with open(caminho_in, 'r', encoding='utf-8', errors='replace') as f:
            conteudo = f.read()
    except Exception:
        return None

    # .in vazio/whitespace não serve como entrada — trata como ausente.
    if conteudo.strip() == "":
        return None

    # Garante quebra de linha final (o scanf espera terminadores previsíveis).
    if not conteudo.endswith("\n"):
        conteudo = conteudo + "\n"

    return conteudo


# ══════════════════════════════════════════════════════════════════════════════
# STDIN PARA AS MALHAS DE MEMÓRIA
# ══════════════════════════════════════════════════════════════════════════════

def stdin_para_analise(caminho_codigo):
    """
    Escolhe o stdin que exercita o código durante a análise (Malha 1 e 2), evitando travar
    aguardando input. Ordem de prioridade:
      1. CASO DE TESTE REAL (.in por arquivo ou _entrada.in): entrada real do exercício. Preferida.
      2. HEURÍSTICA (fallback): sem .in, detecta parâmetro de escala e sintetiza "5\\n1 2 3 4 5\\n".
      3. NENHUMA: entrada fixa não reconhecida -> None (herda o stdin do ambiente).

    O .in vem primeiro porque a adivinhação por regex é frágil (só pega o padrão canônico); o
    .in real cobre listas, matrizes e formatos compostos que a heurística nunca cobriria.
    """
    # 1) Caso de teste real — fonte preferida
    caso = _ler_caso_de_teste(caminho_codigo)
    if caso is not None:
        nome_in = os.path.basename(caminho_caso_de_teste(caminho_codigo))
        print(f"  -> [entrada] usando caso de teste real: {nome_in}")
        return caso

    # 2) Heurística de escala (fallback), só sem .in cadastrado
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
