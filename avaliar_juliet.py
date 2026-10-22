"""
Harness de validação do pipeline determinístico contra o Juliet Test Suite (NIST SARD).

Diferente do `orquestrador.py` (modo catálogo, com feedback via LLM), este script roda SÓ a
parte determinística — Malha 1 (ASan+GDB), Malha 2 (Valgrind+vgdb), Malha UBSan e `src/cwe.py`
— e nunca chama o Ollama. Para cada caso selecionado, compara o CWE devolvido pelo pipeline com o CWE
oficial do Juliet (lido do `manifest.xml`) e grava um CSV-resumo, igual em espírito ao catálogo
do `orquestrador.py`, mas com colunas de acerto/erro em vez de feedback ao aluno.

── Por que os casos do Juliet não compilam "de cutucada" no comando fixo das malhas ──
`src/malha1_asan.py` e `src/malha2_valgrind.py` compilam só o arquivo do caso, sem include path
extra e sem linkar outro .c — o que basta para a submissão de um aluno (arquivo único,
autossuficiente), mas não para o Juliet: os casos incluem `std_testcase.h` e chamam funções de
`testcasesupport/io.c`, e o `main()` só entra na compilação com `-DINCLUDEMAIN`. Por isso as duas
malhas ganharam o parâmetro opcional `flags_extra` (ver docstrings lá) — usado só por este
script; a chamada de produção (`orquestrador.py`) não passa esse argumento e continua idêntica.

── Como usar ──
    # baixe e extraia o Juliet primeiro (procedimento em data/juliet/README.md)
    python avaliar_juliet.py --cwes 121,122,124,126,127 --por-cwe 5
    python avaliar_juliet.py --cwes todos --por-cwe 3 --seed 7
    python avaliar_juliet.py --listar-candidatos --cwes 369   # só lista, não compila/roda

    # equivalente via variável de ambiente (útil pra automatizar/repetir sem digitar a linha
    # toda); flag de linha de comando tem prioridade sobre a variável quando os dois aparecem.
    JULIET_CWES=121,415,476 JULIET_POR_CWE=10 python avaliar_juliet.py

── Saídas ──
  - `output/avaliacao_juliet.csv`      : 1 linha por CASO da rodada atual (sobrescrito a cada run).
  - `output/juliet_historico.csv`      : 1 linha por RODADA (acumula) — pra comparar acurácia ao
                                          longo do tempo conforme o cwe.py muda.
  - `output/juliet_divergencias.csv`   : 1 linha por CASO que NÃO bateu o rótulo oficial em
                                          QUALQUER rodada já feita (acumula) — material pronto pra
                                          seção de limitações conhecidas.
  - Com `--versao good`, os mesmos arquivos com sufixo `_good` (alarmes falsos).

── Quatro números por rodada (lentes) ──
  L1 estrito | L2 + hierarquia/convenção | L3 = L2 sem os casos que a ferramenta não tinha como
  ver (causas A/B) | L4 = L3 contando C/D (a ferramenta reportou um defeito verdadeiro). A causa
  de cada divergência vem de regras determinísticas + decisões manuais versionadas em
  data/juliet_adjudicacao.csv (ver causa_da_divergencia).
"""

import argparse
import csv
import os
import random
import re
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from src.malha1_asan import executar_malha_1_asan
from src.malha2_valgrind import executar_malha_2_valgrind
from src.malha_ubsan import executar_malha_ubsan, deve_refinar
from src.cwe import _NOME as CWES_SUPORTADOS  # mesma tabela do classificador
from src.llm_client import classificar_erro  # mesma função 100% determinística da produção


# ══════════════════════════════════════════════════════════════════════════════
# Critérios de seleção (decididos e documentados em data/juliet/README.md)
# ══════════════════════════════════════════════════════════════════════════════

# "_rand_" no nome do arquivo = resultado não reprodutível entre execuções; fora da amostra.
_PADRAO_RAND = re.compile(r"_rand_", re.IGNORECASE)

# Variantes que dependem de socket de rede (ex.: "..._listen_socket_12.c", "..._connect_socket_09.c")
# ficam esperando conexão e estouram o timeout de 60s da Malha 1 sem produzir diagnóstico —
# medido ao rodar a amostra real (CWE127_..._CWE839_listen_socket_12.c). Fora do escopo
# documentado em data/juliet/README.md ("sem depender de socket/arquivo").
_PADRAO_SOCKET = re.compile(r"socket", re.IGNORECASE)

# CWE-369 com float não trava em C (divisão de ponto flutuante por zero dá inf/nan, não SIGFPE);
# o próprio cwe.py não tem como detectar isso, então esses casos são exclusão metodológica, não
# falha do classificador. Reconhecidos pelo nome do arquivo (convenção do Juliet).
_PADRAO_FLOAT_CWE369 = re.compile(r"_(float|double)_", re.IGNORECASE)

# Pares CWE-filho -> CWE-pai na hierarquia OFICIAL do MITRE (View-1000), restrito aos CWEs que o
# cwe.py pode devolver. Usado na métrica "com hierarquia" (ex.: rótulo 122, resposta 787 = acerto
# nessa métrica); a métrica estrita (==) é sempre reportada em paralelo.
_PAI_NA_HIERARQUIA = {
    "CWE-121": "CWE-787",  # Stack-based Buffer Overflow   -> Out-of-bounds Write
    "CWE-122": "CWE-787",  # Heap-based Buffer Overflow    -> Out-of-bounds Write
    "CWE-124": "CWE-787",  # Buffer Underwrite             -> Out-of-bounds Write
    "CWE-126": "CWE-125",  # Buffer Over-read              -> Out-of-bounds Read
    "CWE-127": "CWE-125",  # Buffer Under-read              -> Out-of-bounds Read
}

# Equivalências ADOTADAS PELO PROJETO — não são hierarquia oficial do MITRE (nenhum dos pares
# abaixo é literalmente ancestral um do outro na árvore do CWE), mas convenções de classificação
# justificadas caso a caso. Cada uma por um motivo DIFERENTE — não confundir:
#
# 1) CWE-758 ~ {CWE-824, CWE-457}: rotulagem genérica x específica.
#    CWE-758 ("Reliance on Undefined, Unspecified, or Implementation-Defined Behavior") é um
#    guarda-chuva abstrato do MITRE — não é sobre valor negativo nem absurdo, é sobre QUALQUER
#    comportamento que o padrão C não garante. Investigando o código-fonte dos 5 casos do Juliet
#    rotulados 758 na nossa amostra: todos seguem o MESMO padrão — um malloc() cujo conteúdo
#    nunca é inicializado é lido e usado DIRETO como ponteiro, o que é literalmente a definição
#    de CWE-824 (Access of Uninitialized Pointer). Quando a Malha 2 (Valgrind) pega o valor não
#    inicializado ANTES do ponteiro ser usado, vira CWE-457 pelo mesmo motivo de fundo. Ou seja:
#    o Juliet rotulou pelo guarda-chuva onde a ferramenta soube ser mais específica — nenhum dos
#    5 casos testados estava "errado" de fato. Decidido tratar como equivalente "por enquanto"
#    (15/10/2026) — revisar se a diferenciação 758 x 824/457 importar para a pesquisa depois.
#
# 2) CWE-195 ~ CWE-789 (bidirecional): "negativo" e "absurdo" são o MESMO número, por dois
#    caminhos. Um valor negativo (195) convertido implicitamente para size_t (sem sinal) num
#    malloc/memcpy/memset VIRA um número gigante (789) — é a mesma conversão de sinal que o
#    próprio nome do CWE-195 descreve ("Signed to Unsigned Conversion Error"), só que o tamanho
#    do número final decide qual das duas regras do cwe.py casa primeiro (negative-size-param,
#    específica para memcpy/memset, vs. allocation-size-too-big, do malloc/calloc). MEDIDO: um
#    CWE-195 cujo sink é malloc (não memcpy/memset) sai classificado CWE-789, pela mesma causa
#    raiz. Decidido tratar como equivalente nos dois sentidos (15/10/2026).
#
# 3) CWE-126/CWE-127 ~ CWE-457: mesmo padrão do item 1 (rótulo pela consequência x causa mais
#    próxima), mas por um mecanismo diferente do 758. No padrão "CWE170 Improper Null
#    Termination" do Juliet (ex.: strncpy() que não garante '\0' se a origem não cabe no limite
#    copiado), o byte seguinte ao que deveria ser o fim da string fica com LIXO da pilha — pode ou
#    não ser zero, por acaso. Se o %s/printLine for ler esse byte pra decidir se já chegou no fim
#    da string, dois caminhos são possíveis: (a) o lixo por acaso é zero -> a string "termina" ali,
#    sem overread de verdade nessa execução (não detectável, nem deveria ser); (b) o lixo não é
#    zero -> a leitura continua por memória adjacente, e AÍ sim vira um over/under-read de verdade.
#    O Valgrind, que rastreia inicialização byte a byte, flagra o acesso ao byte de lixo como "uso
#    de valor não inicializado" (CWE-457) no INSTANTE em que ele é lido — antes mesmo de saber se
#    o caminho (a) ou (b) vai acontecer. Ou seja, CWE-457 é a causa-raiz mais imediata e correta
#    do ponto de vista da ferramenta; CWE-126/127 é a consequência eventual, que nem sempre se
#    manifesta (explica também por que alguns desses casos "passam limpo"). MEDIDO: 2/10
#    divergências do CWE-126 e 4/6 do CWE-127 na amostra de 20/CWE eram exatamente esse padrão.
#    Decidido tratar como equivalente (15/10/2026).
#
# 4) CWE-121/122/124/126/127 ~ CWE-129: causa x consequência. O CWE-129 ("Improper Validation of
#    Array Index") é o índice que ninguém checou; o estouro (leitura/escrita, antes/depois) é o
#    que ele provoca. O UBSan reporta "index N out of bounds for type 'int [10]'" sem dizer se foi
#    leitura ou escrita, então devolve 129 — verdadeiro, só que menos específico. É o mesmo padrão
#    que o próprio Juliet usa no nome desses arquivos ("_CWE129_"). Decidido tratar como
#    equivalente (21/10/2026).
#
# NÃO incluído: CWE-121 x CWE-122 (ver investigação do padrão "_CWE806_"/"_src_" — a confusão ali
# é genuinamente pilha x heap, a mesma distinção que o resto do cwe.py foi construído pra acertar;
# equiparar esconderia erros reais de classificação em outros casos). Ver comentário na conversa
# de 15/10/2026 — fica documentado como limitação conhecida do rótulo do Juliet nesse subpadrão,
# não como equivalência de código.
_EQUIVALENCIA_PROJETO = {
    "CWE-758": {"CWE-824", "CWE-457"},
    "CWE-195": {"CWE-789"},
    "CWE-789": {"CWE-195"},
    "CWE-121": {"CWE-129"},
    "CWE-122": {"CWE-129"},
    "CWE-124": {"CWE-129"},
    "CWE-126": {"CWE-457", "CWE-129"},
    "CWE-127": {"CWE-457", "CWE-129"},
}

# ── Entrada sintética por CWE ──────────────────────────────────────────────────
# Muitos casos do Juliet só disparam o defeito com um valor específico vindo do stdin (fonte
# "fscanf"/"fgets" do template). Sem entrada, a variável fica no valor de inicialização "seguro"
# do template (normalmente -1) e o caso passa limpo — FALSO NEGATIVO por falta de estímulo, não
# por erro do classificador.
#
# IMPORTANTE: o nome do arquivo (ex.: "_fscanf_", "_fgets_") só diz DE ONDE vem o valor, não diz
# PRA QUE ele é usado — isso depende do CWE. Confirmado lendo código real: um CWE-369 por fscanf
# usa o valor como DIVISOR (precisa de "0"); um CWE-121 por fgets usa o mesmo tipo de leitura como
# ÍNDICE/TAMANHO (precisa de um número GRANDE; "0" não dispara nada ali). Por isso a entrada é
# escolhida pelo CWE esperado, não pelo nome do arquivo — e é aplicada a TODO caso daquele CWE,
# não só aos que usam fscanf/fgets: um caso "_declare_" (valor fixo no código, não lê stdin)
# simplesmente ignora essa entrada — sem efeito colateral, sem precisar detectar o tipo de fonte.
#
# Repete a linha ~25x: quando OMITGOOD não é usado (padrão), main() chama good() ANTES de bad(),
# e good() às vezes também lê do stdin — a repetição garante que sobre valor pro bad().
_REPETICOES_ENTRADA = 25
# NÃO usar INT_MAX aqui: MEDIDO que em variantes "_alloca_" o valor lido também vira o TAMANHO de
# uma alocação dinâmica na pilha (alloca), não só um índice — com INT_MAX isso tenta reservar ~GBs
# e trava a Malha 2 (Valgrind) até o timeout, igual ao problema do CWE-789 (ver comentário mais
# abaixo). 100000 já é muito maior que qualquer buffer fixo do Juliet (dezenas/centenas de
# elementos) para continuar estourando o limite, mas pequeno o bastante para nunca virar uma
# alocação perigosa (no máximo ~800 KB mesmo multiplicado pelo maior tipo usado, wchar_t/double).
_NUMERO_GRANDE = f"{100_000}\n" * _REPETICOES_ENTRADA       # índice/tamanho "grande" mas seguro
_NUMERO_NEGATIVO = f"{-(2**31)}\n" * _REPETICOES_ENTRADA    # vira size_t gigante em memcpy/memset
_ZERO = "0\n" * _REPETICOES_ENTRADA                          # divisor zero
# CWE-789 precisa de um valor BEM maior que _NUMERO_GRANDE (100.000 daria só ~400 KB — longe dos
# 500 MB do teto do ASan abaixo). INT_MAX aqui é seguro (não "trava" mais) porque o teto de
# memória (LIMITE_ALOCACAO_ASAN_MB / LIMITE_MEMORIA_VALGRIND_MB, mais abaixo) faz a alocação
# falhar rápido em vez de ser tentada de verdade.
_NUMERO_ALOCACAO_ABSURDA = f"{2**31 - 1}\n" * _REPETICOES_ENTRADA

_ENTRADA_SINTETICA_POR_CWE = {
    # Overflow de buffer (leitura ou escrita, antes ou depois do limite): o valor lido vira
    # índice ou tamanho de cópia — precisa ser grande o bastante para passar do limite do buffer.
    "CWE-121": _NUMERO_GRANDE, "CWE-122": _NUMERO_GRANDE, "CWE-124": _NUMERO_GRANDE,
    "CWE-126": _NUMERO_GRANDE, "CWE-127": _NUMERO_GRANDE, "CWE-787": _NUMERO_GRANDE,
    # Tamanho negativo: memcpy/memset recebe o size_t convertido (gigante), mas o interceptor do
    # ASan para "negative-size-param" valida isso ANTES de tocar na memória (checagem de
    # fronteira, não um memset de verdade) — rápido, sem risco de travar. MEDIDO: ok.
    "CWE-195": _NUMERO_NEGATIVO,
    # Divisão por zero: o valor vira o divisor. MEDIDO: 3/3, ~0.5s cada.
    "CWE-369": _ZERO,
    # Alocação absurda: um `int` de 32 bits (o tipo que o fscanf("%d", ...) desses casos lê) não
    # chega nem perto do teto padrão do ASan pra rejeitar alocação (~1 TB) — só uns 8 GB depois de
    # multiplicado pelo tamanho do elemento. SEM os tetos de memória abaixo
    # (LIMITE_ALOCACAO_ASAN_MB / LIMITE_MEMORIA_VALGRIND_MB), isso travava a Malha 2 por ~120s por
    # caso (MEDIDO). Com os tetos aplicados, a Malha 1 rejeita na hora (MEDIDO: 2s) — e mesmo nos
    # raros casos que escapam dela, a Malha 2 também está protegida (MEDIDO: malloc de 8GB falha
    # em <1s sob o teto de memória virtual, em vez de travar).
    "CWE-789": _NUMERO_ALOCACAO_ABSURDA,
    # Estouro de inteiro (Malha UBSan): o valor lido entra numa soma/produto/incremento. O MAIOR
    # int estoura para cima (190); o MENOR estoura para baixo (191). MEDIDO (amostra de 50, seed
    # fixa): o UBSan acusou 15/15 casos int/int64 com essas entradas; char/short/unsigned ficam
    # limpos com qualquer entrada — em C eles não são comportamento indefinido (causa B).
    "CWE-190": f"{2**31 - 1}\n" * _REPETICOES_ENTRADA,
    "CWE-191": f"{-(2**31)}\n" * _REPETICOES_ENTRADA,
}

# Exceção por PADRÃO DE DEFEITO (não por fonte): os sufixos "CWE129" e "CWE839" no nome do arquivo
# dizem exatamente pra que o valor lido serve — índice de um vetor de 10 elementos sem checagem de
# limite (CWE129: só o limite superior; CWE839: só o inferior). Aí 100000 é RUIM: o acesso cai
# longe do vetor, fora da "zona de alerta" do ASan, e vira SIGSEGV genérico (classificado 824/758)
# ou nem dispara (CWE839 precisa de negativo). MEDIDO em 30 casos (6 por CWE, seed 7, Docker):
# com 100000 acertou 0/30; com "10" (logo após o fim) / "-1" (logo antes do início) acertou 30/30.
_ENTRADA_POR_PADRAO = {
    "CWE129": "10\n" * _REPETICOES_ENTRADA,   # índice = tamanho do vetor -> 1 posição após o fim
    "CWE839": "-1\n" * _REPETICOES_ENTRADA,   # índice negativo -> 1 posição antes do início
}


# Estouro de int64_t: os extremos de 32 bits não estouram 64 bits (MEDIDO: 3 casos
# "int64_t_fscanf_sub" do CWE-191 passavam limpos com -2^31). Usa os extremos de 64 bits.
_ENTRADA_INT64 = {
    "CWE-190": f"{2**63 - 1}\n" * _REPETICOES_ENTRADA,
    "CWE-191": f"{-(2**63)}\n" * _REPETICOES_ENTRADA,
}


def _entrada_sintetica(caminho_fonte, cwe_esperado):
    """Entrada do stdin para o caso: padrão de defeito no nome do arquivo tem prioridade; senão, por CWE."""
    nome = os.path.basename(caminho_fonte)
    for padrao, entrada in _ENTRADA_POR_PADRAO.items():
        if f"_{padrao}_" in nome:
            return entrada
    if "_int64_t_" in nome and cwe_esperado in _ENTRADA_INT64:
        return _ENTRADA_INT64[cwe_esperado]
    return _ENTRADA_SINTETICA_POR_CWE.get(cwe_esperado)  # None = usa a heurística padrão
# Tetos de memória (ver docstrings em malha1_asan.executar_malha_1_asan e
# malha2_valgrind.executar_malha_2_valgrind): sem eles, uma alocação "absurda" mas ainda dentro do
# que a máquina consegue reservar (poucos GB) é tentada de verdade em vez de rejeitada na hora.
# Aplicados em TODO caso (não só CWE-789) como defesa extra — testado que não muda o resultado de
# casos normais (regressão com CWE-401 real: detecta o vazamento igual, com ou sem o teto).
LIMITE_ALOCACAO_ASAN_MB = 500      # Malha 1: acima disso, o ASan recusa a alocação na hora.
LIMITE_MEMORIA_VALGRIND_MB = 1024  # Malha 2: teto de memória virtual do processo (e do Valgrind
                                    # em si — 1 GB já é generoso para o próprio Valgrind iniciar).

# Os demais CWEs suportados (401, 415, 416, 457, 475, 476, 562, 590, 674, 758, 762, 824, 825)
# ficam de fora do mapa: nas rodadas já feitas, os casos "_declare_"/hardcoded desses CWEs já
# acertaram quase 100% sem entrada nenhuma — adicionar uma entrada sintética "chute" (sem saber
# o que ela precisaria representar ali) arriscaria mudar o comportamento à toa.


# ══════════════════════════════════════════════════════════════════════════════
# Leitura do manifest.xml
# ══════════════════════════════════════════════════════════════════════════════

def _cwe_do_atributo_name(nome_flaw):
    """Extrai 'CWE-121' de algo como 'CWE121: Stack-based Buffer Overflow'. None se não achar."""
    m = re.search(r"CWE-?(\d+)", nome_flaw or "")
    return f"CWE-{m.group(1)}" if m else None


def _indexar_testcases(pasta_testcases):
    """
    O `path` de cada <file> no manifest.xml é só o NOME do arquivo (sem diretório) — os arquivos
    de verdade ficam espalhados em testcases/<categoria>/[subpasta]/arquivo.c. Monta um índice
    nome -> caminho absoluto varrendo a árvore uma única vez (muito mais rápido que procurar
    arquivo por arquivo). Em caso de nome duplicado (não visto no dataset, mas por segurança),
    fica o primeiro encontrado e os demais são ignorados.
    """
    indice = {}
    for raiz, _dirs, arquivos in os.walk(pasta_testcases):
        for nome in arquivos:
            indice.setdefault(nome, os.path.join(raiz, nome))
    return indice


def carregar_candidatos(juliet_dir):
    """
    Lê C/manifest.xml e devolve {cwe: [(caminho_absoluto, linha_do_defeito, nome_arquivo), ...]},
    já filtrado para: linguagem C (pela EXTENSÃO do arquivo — o manifest não tem atributo
    `language`), testcase de ARQUIVO ÚNICO (sem dependências multi-arquivo complexas), sem
    variantes "_rand_".
    """
    manifest_path = os.path.join(juliet_dir, "manifest.xml")
    if not os.path.isfile(manifest_path):
        sys.exit(
            f"[Erro] Não achei '{manifest_path}'.\n"
            f"Baixe e extraia o Juliet primeiro (procedimento em data/juliet/README.md) e "
            f"aponte --juliet-dir para a pasta que contém manifest.xml (normalmente 'C/')."
        )

    indice_arquivos = _indexar_testcases(os.path.join(juliet_dir, "testcases"))

    raiz = ET.parse(manifest_path).getroot()
    candidatos = {}

    for testcase in raiz.findall(".//testcase"):
        arquivos = testcase.findall("file")
        if len(arquivos) != 1:
            continue  # caso multi-arquivo: fora do escopo (o pipeline compila 1 arquivo)

        arquivo_el = arquivos[0]
        caminho_rel = arquivo_el.get("path") or ""
        nome_arquivo = os.path.basename(caminho_rel)
        if not nome_arquivo.lower().endswith(".c"):
            continue  # .cpp ou .h: fora do escopo (o pipeline compila C)
        if _PADRAO_RAND.search(nome_arquivo):
            continue
        if _PADRAO_SOCKET.search(nome_arquivo):
            continue  # precisa de conexão de rede; trava até o timeout sem produzir log útil

        flaws = arquivo_el.findall("flaw") + arquivo_el.findall("mixed")
        if not flaws:
            continue  # arquivo sem flaw anotado (ex.: variante "good-only") não serve de rótulo
        cwe = _cwe_do_atributo_name(flaws[0].get("name"))
        if cwe is None or cwe not in CWES_SUPORTADOS:
            continue  # fora dos 24 CWEs que o cwe.py sabe devolver
        if cwe == "CWE-369" and _PADRAO_FLOAT_CWE369.search(nome_arquivo):
            continue  # exclusão metodológica documentada (ver _PADRAO_FLOAT_CWE369)

        linha = flaws[0].get("line", "?")

        caminho_abs = indice_arquivos.get(nome_arquivo)
        if not caminho_abs:
            continue  # arquivo listado no manifest mas ausente no disco: ignora

        candidatos.setdefault(cwe, []).append((caminho_abs, linha, nome_arquivo))

    return candidatos


# ══════════════════════════════════════════════════════════════════════════════
# Execução de um caso pelo pipeline determinístico (Malha 1 -> Malha 2 -> cwe.py)
# ══════════════════════════════════════════════════════════════════════════════

def avaliar_caso(caminho_fonte, pasta_testcasesupport, pasta_bin, cwe_esperado, versao="bad"):
    """
    Roda a cascata determinística sobre um único arquivo do Juliet.
    `versao="good"` compila com -DOMITBAD: só as funções CORRIGIDAS do caso rodam, e qualquer
    detecção é ALARME FALSO (métrica de falsos positivos, como na literatura de sanitizers).
    Devolve (cwe_obtido, cwe_nome, ferramenta, status, linha_sintoma, linha_causa).
    `status`: "detectado" | "passou_limpo" | "erro_compilacao".
    `linha_sintoma`/`linha_causa`: linhas que a FERRAMENTA (ASan/Valgrind) reportou — vêm do
    mesmo extrator usado em produção (llm_client._extrair_pontos_anotacao, via classificar_erro).
    Dá pra comparar direto com a "Linha do Defeito (manifest)" do gabarito do Juliet.
    """
    flags_extra = [
        "-DINCLUDEMAIN",
        "-I", pasta_testcasesupport,
        os.path.join(pasta_testcasesupport, "io.c"),
    ]
    if versao == "good":
        flags_extra.append("-DOMITBAD")
    base = re.sub(r"[^A-Za-z0-9_.-]", "_", os.path.splitext(os.path.basename(caminho_fonte))[0])
    entrada = _entrada_sintetica(caminho_fonte, cwe_esperado)

    resultado = executar_malha_1_asan(
        caminho_fonte,
        binario_saida=os.path.join(pasta_bin, f"{base}_asan"),
        entrada=entrada,
        flags_extra=flags_extra,
        limite_alocacao_mb=LIMITE_ALOCACAO_ASAN_MB,
    )
    ferramenta = "ASan+GDB"

    if resultado and resultado.get("tipo") == "compilacao":
        return "-", "-", "Compilador (gcc)", "erro_compilacao", "-", "-"

    # Mesmas regras da produção (api/runner_analise.py): crash genérico -> tenta refinar pelo
    # UBSan (só índice fora do vetor); Malhas 1 e 2 limpas -> Malha UBSan completa.
    if deve_refinar(resultado):
        refinado = executar_malha_ubsan(
            caminho_fonte, binario_saida=os.path.join(pasta_bin, f"{base}_ubsan"),
            entrada=entrada, flags_extra=flags_extra, somente_indice=True)
        if refinado:
            resultado, ferramenta = refinado, "UBSan (refinando crash)"

    if not resultado:
        resultado = executar_malha_2_valgrind(
            caminho_fonte,
            binario_saida=os.path.join(pasta_bin, f"{base}_valgrind"),
            entrada=entrada,
            flags_extra=flags_extra,
            limite_memoria_mb=LIMITE_MEMORIA_VALGRIND_MB,
        )
        ferramenta = "Valgrind+vgdb"
        if resultado and resultado.get("tipo") == "compilacao":
            return "-", "-", "Compilador (gcc)", "erro_compilacao", "-", "-"

    if not resultado:
        resultado = executar_malha_ubsan(
            caminho_fonte, binario_saida=os.path.join(pasta_bin, f"{base}_ubsan"),
            entrada=entrada, flags_extra=flags_extra)
        ferramenta = "UBSan"

    if not resultado:
        return "-", "-", "Nenhuma", "passou_limpo", "-", "-"

    # BUG CORRIGIDO (15/10/2026): classificava em cima do log LIMPO (limpar_log_gdb), que existe
    # só para cortar ruído do backtrace ANTES de mostrar ao aluno ("preservando apenas as linhas
    # relevantes para o feedback", ver parser_logs.py) — não tem relação com o que o cwe.py
    # precisa. O próprio pipeline de produção (llm_client.classificar_erro, linha ~337) usa
    # `log_bruto or log_limpo`, ou seja, PREFERE o bruto. Rodar em cima do limpo cortava
    # justamente a seção do mapa de memória-sombra ("=>0x...: ca ca ca[ca]...") que a heurística
    # de alloca/VLA em cwe.py precisa ler — e como o regex de fallback não achava mais nenhuma
    # pista de posição, toda escrita de alloca caía no último recurso (nome do erro = "overflow"
    # -> sempre "depois"/121, nunca "antes"/124). MEDIDO: 9 de 9 casos `_alloca_` do CWE-124 na
    # amostra saíam 121 por esse motivo. Corrigido para classificar sobre o log bruto, igual à
    # produção.
    #
    # Usa classificar_erro (não só classificar_cwe) pra reaproveitar o MESMO extrator de linha
    # que a produção usa — assim o CSV também traz a linha que a FERRAMENTA apontou como sintoma
    # e causa, pra comparar com a "Linha do Defeito" do gabarito do manifest.xml. Continua 100%
    # determinístico: classificar_erro não chama o LLM (só gerar_feedback chama).
    with open(caminho_fonte, "r", encoding="utf-8", errors="replace") as f:
        codigo_fonte = f.read()
    analise = classificar_erro(resultado["log"], codigo_fonte, os.path.basename(caminho_fonte),
                                log_bruto=resultado["log"])
    return (analise["cwe_id"], analise["cwe_nome"], ferramenta, "detectado",
            analise["linha_sintoma"], analise["linha_causa"])


# ══════════════════════════════════════════════════════════════════════════════
# Causa de cada divergência (determinística)
# ══════════════════════════════════════════════════════════════════════════════
# Como as malhas são determinísticas, todo caso que não bate o rótulo cai numa destas causas.
# Só a E é defeito do classificador; A e B dizem até onde a análise dinâmica alcança; C e D são
# divergências em que a ferramenta reportou algo VERDADEIRO.
CAUSA_A = "A - não estimulado"                      # entrada/fluxo não fez o defeito acontecer
CAUSA_B = "B - fora do alcance da ferramenta"       # nenhuma das ferramentas vê esse defeito
CAUSA_C = "C - ordem de execução"                   # um defeito real ANTERIOR foi reportado
CAUSA_D = "D - rótulo impreciso"                    # o rótulo do Juliet não descreve o que acontece
CAUSA_E = "E - regra nossa"                         # o cwe.py/malhas erraram
CAUSA_REVISAR = "a revisar"                         # nenhuma regra cobre: revisão manual
CAUSAS_VALIDAS = {CAUSA_A, CAUSA_B, CAUSA_C, CAUSA_D, CAUSA_E}

# Decisões MANUAIS (arquivo -> causa + justificativa), versionadas no repositório. Têm prioridade
# sobre as regras abaixo; assim a mesma rodada sempre gera a mesma coluna (determinístico).
ARQUIVO_ADJUDICACAO = "./data/juliet_adjudicacao.csv"

# Destino da cópia declarado como vetor LOCAL (pilha) — ver regra D abaixo.
_RX_DESTINO_NA_PILHA = re.compile(r"^\s*(?:char|wchar_t)\s+dest\[\d+\]", re.M)
# Tipos em que o estouro NÃO é comportamento indefinido em C (promoção para int / unsigned dá a
# volta por definição): o UBSan não acusa — regra B abaixo. MEDIDO: 0/35 na amostra.
_RX_TIPO_SEM_UB = re.compile(r"__(?:char|short|unsigned_int|unsigned_char)_")


def carregar_adjudicacao(caminho=ARQUIVO_ADJUDICACAO):
    """{arquivo: causa} das decisões manuais (vazio se o arquivo não existe)."""
    if not os.path.isfile(caminho):
        return {}
    with open(caminho, encoding="utf-8") as f:
        decisoes = {l["Arquivo"]: l["Causa"] for l in csv.DictReader(f)}
    invalidas = {c for c in decisoes.values() if c not in CAUSAS_VALIDAS}
    if invalidas:
        sys.exit(f"[Erro] Causa(s) inválida(s) em {caminho}: {invalidas}")
    return decisoes


def causa_da_divergencia(nome_arquivo, codigo_fonte, esperado, obtido, status, adjudicacao):
    """
    Causa de um caso que NÃO bateu o rótulo estrito. Ordem: decisão manual -> regras de família
    (cada uma conferida no código-fonte do Juliet) -> "a revisar".
    """
    if nome_arquivo in adjudicacao:
        return adjudicacao[nome_arquivo]
    # D: "c_src"/"c_CWE806" do CWE-122 — a ORIGEM vem do malloc, mas o vetor que estoura é
    # `dest[50]`, local (pilha). A ferramenta diz 121 e está certa. MEDIDO: 608/896 arquivos da
    # família têm o destino na pilha; a regra exige isso no próprio arquivo.
    if esperado == "CWE-122" and obtido == "CWE-121" and _RX_DESTINO_NA_PILHA.search(codigo_fonte):
        return CAUSA_D
    # C: CWE-590 "_declare_" — o buffer é usado (impresso) depois que o bloco onde foi declarado
    # terminou, ANTES do free indevido: o use-after-scope (825) é um defeito real e anterior.
    if esperado == "CWE-590" and obtido == "CWE-825":
        return CAUSA_C
    # A: variante de fluxo 12 — o caminho bom/ruim é sorteado (globalReturnsTrueOrFalse); se o
    # sorteio pulou o defeito, só sobra o que mais o programa fizer (ex.: um vazamento).
    if nome_arquivo.endswith("_12.c") and (status == "passou_limpo" or obtido == "CWE-401"):
        return CAUSA_A
    # B: funções de wchar_t (wcscpy, wcsncpy...) não são interceptadas pelo ASan — limitação
    # conhecida (também relatada no Tech-ASan, 56 casos de wcscpy).
    if "wchar_t" in nome_arquivo:
        return CAUSA_B
    # B: estouro de char/short/unsigned não é comportamento indefinido em C.
    if esperado in ("CWE-190", "CWE-191") and status == "passou_limpo" and _RX_TIPO_SEM_UB.search(nome_arquivo):
        return CAUSA_B
    # B: "null_check_after_deref" — o ponteiro nunca é NULL na execução; o defeito (checar depois
    # de usar) só existe no texto do programa, não no comportamento.
    if esperado == "CWE-476" and "null_check_after_deref" in nome_arquivo:
        return CAUSA_B
    # B: "type_overrun" — a cópia estoura DENTRO da struct (charFirst invade voidSecond, o campo
    # vizinho): é memória válida do mesmo bloco, e o ASan/Valgrind não veem estouro intra-objeto.
    # O que aparece depois (uso do ponteiro corrompido, 824) é consequência verdadeira.
    if "type_overrun" in nome_arquivo:
        return CAUSA_B
    # B: "sizeof_struct" — malloc(sizeof(ponteiro)) no lugar de sizeof(struct): em 64 bits os dois
    # têm 8 bytes (twoIntsStruct = 2 ints), então o defeito não acontece. É a família "só em 32
    # bits" que o Tech-ASan também excluiu.
    if "sizeof_struct" in nome_arquivo:
        return CAUSA_B
    # A: CWE-401 "_realloc_" — o vazamento só acontece SE o realloc falhar (o bloco original fica
    # perdido); na execução o realloc dá certo e tudo é liberado.
    if esperado == "CWE-401" and "_realloc_" in nome_arquivo and status == "passou_limpo":
        return CAUSA_A
    # B: CWE-562 "return_buf" — o GCC troca o endereço do vetor local devolvido por NULL (com
    # aviso -Wreturn-local-addr), e o printLine do Juliet ignora NULL: o defeito some. MEDIDO.
    if esperado == "CWE-562" and "return_buf" in nome_arquivo:
        return CAUSA_B
    return CAUSA_REVISAR


# Versão corrigida (good): nem toda detecção é alarme falso. Muitas funções "good" do Juliet
# alocam memória e nunca liberam — o próprio Juliet às vezes marca isso ("POTENTIAL INCIDENTAL -
# Possible memory leak", "INCIDENTAL CWE-401"). MEDIDO: todos os alarmes CWE-401 da rodada de
# 21/10/2026 eram desse tipo. Regra objetiva: no código que roda na versão corrigida (o arquivo
# SEM o bloco "#ifndef OMITBAD ... #endif /* OMITBAD */" e SEM comentários) há mais chamadas de
# alocação do que de free. Comentários saem porque o Juliet às vezes deixa o free comentado de
# propósito ("/* free(reversedString); This call to free() was removed..." — CWE416
# ..._return_freed_ptr_08); helpers ficam porque a alocação pode estar neles (helperGood).
_RX_ALOCA = re.compile(r"\b(?:malloc|calloc|realloc)\s*\(")
_RX_LIBERA = re.compile(r"\bfree\s*\(")
_RX_BLOCO_BAD = re.compile(r"#ifndef OMITBAD.*?#endif /\* OMITBAD \*/", re.S)
_RX_COMENTARIO = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)
NATUREZA_ALARME_FALSO = "alarme falso"
NATUREZA_VAZAMENTO_REAL = "vazamento real no código corrigido"


def natureza_do_alarme(codigo_fonte, cwe_obtido):
    """Classifica uma detecção na versão good: vazamento real (alocação sem free) ou alarme falso."""
    roda_no_good = _RX_COMENTARIO.sub("", _RX_BLOCO_BAD.sub("", codigo_fonte))
    if cwe_obtido == "CWE-401" and len(_RX_ALOCA.findall(roda_no_good)) > len(_RX_LIBERA.findall(roda_no_good)):
        return NATUREZA_VAZAMENTO_REAL
    return NATUREZA_ALARME_FALSO


def resumo_por_lentes(linhas):
    """
    Uma rodada, quatro números (todos sobre os casos que compilaram):
      L1 estrito; L2 com hierarquia/convenção; L3 = L2 sem os casos que a ferramenta não tinha
      como ver (causas A e B); L4 = L3 contando C e D como acerto (a ferramenta reportou um defeito
      verdadeiro). Devolve dict com (acertos, total) de cada lente.
    """
    validos = [l for l in linhas if l["Status"] != "erro_compilacao"]
    l1 = sum(l["Acerto Estrito"] == "sim" for l in validos)
    l2 = sum(l["Acerto com Hierarquia/Convenção"] == "sim" for l in validos)
    escopo = [l for l in validos if l["Causa"] not in (CAUSA_A, CAUSA_B)]
    l3 = sum(l["Acerto com Hierarquia/Convenção"] == "sim" for l in escopo)
    l4 = l3 + sum(l["Causa"] in (CAUSA_C, CAUSA_D) for l in escopo)
    return {"L1": (l1, len(validos)), "L2": (l2, len(validos)),
            "L3": (l3, len(escopo)), "L4": (l4, len(escopo))}


# ══════════════════════════════════════════════════════════════════════════════
# Histórico (1 linha por rodada) e divergências (1 linha por caso errado, acumulado)
# ══════════════════════════════════════════════════════════════════════════════

def _commit_atual():
    """Hash curto do commit atual do repo, para amarrar um % de acerto a uma versão do cwe.py."""
    try:
        r = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, timeout=5)
        return r.stdout.strip() if r.returncode == 0 else "-"
    except Exception:
        return "-"


def _preparar_acumulado(caminho, campos):
    """
    True se `caminho` já existe com o MESMO cabeçalho (é só acrescentar). Se o cabeçalho mudou
    (o script ganhou colunas), o arquivo antigo é renomeado — preservado — e um novo começa, em vez
    de misturar colunas.
    """
    if not os.path.isfile(caminho):
        return False
    with open(caminho, encoding="utf-8", newline="") as f:
        cabecalho = next(csv.reader(f), [])
    if cabecalho == campos:
        return True
    os.replace(caminho, caminho.replace(".csv", f"_ate_{datetime.now().strftime('%Y%m%d%H%M%S')}.csv"))
    return False


def _registrar_historico(caminho_historico, args, cwes_pedidos, linhas_csv):
    """Acrescenta (não sobrescreve) uma linha-resumo desta rodada em output/juliet_historico.csv."""
    total = len(linhas_csv)
    compilacao_falhou = sum(1 for l in linhas_csv if l["Status"] == "erro_compilacao")

    linha = {
        "Data/Hora (UTC)": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "Commit cwe.py": _commit_atual(),
        "Versão": args.versao,
        "CWEs Testados": ",".join(cwes_pedidos),
        "Por CWE": args.por_cwe,
        "Seed": args.seed,
        "Total de Casos": total,
        "Falhas de Compilação": compilacao_falhou,
    }
    if args.versao == "good":
        alarmes = sum(1 for l in linhas_csv if l["Natureza da Detecção"] == NATUREZA_ALARME_FALSO)
        vazamentos = sum(1 for l in linhas_csv if l["Natureza da Detecção"] == NATUREZA_VAZAMENTO_REAL)
        linha["Alarmes Falsos"] = alarmes
        linha["Alarmes Falsos (%)"] = round(100 * alarmes / total, 1) if total else 0
        linha["Vazamentos Reais no Código Corrigido"] = vazamentos
    else:
        for lente, (acertos, n) in resumo_por_lentes(linhas_csv).items():
            linha[f"{lente} acertos"] = acertos
            linha[f"{lente} casos"] = n
            linha[f"{lente} (%)"] = round(100 * acertos / n, 1) if n else 0

    existe = _preparar_acumulado(caminho_historico, list(linha.keys()))
    with open(caminho_historico, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=linha.keys())
        if not existe:
            writer.writeheader()
        writer.writerow(linha)


def _registrar_divergencias(caminho_divergencias, linhas_csv):
    """
    Acrescenta (não sobrescreve) uma linha para cada caso que NÃO bateve o rótulo estrito nesta
    rodada — histórico cumulativo de "casos problemáticos" pronto para virar a seção de
    limitações conhecidas da apresentação. O mesmo arquivo pode ganhar o mesmo caso mais de uma
    vez, em rodadas diferentes (com timestamp), de propósito: dá para ver se uma divergência é
    recorrente ou foi pontual.
    """
    divergentes = [l for l in linhas_csv if l["Acerto Estrito"] == "não"]
    if not divergentes:
        return
    agora = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    campos = ["Data/Hora (UTC)"] + list(divergentes[0].keys())
    existe = _preparar_acumulado(caminho_divergencias, campos)
    with open(caminho_divergencias, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=campos)
        if not existe:
            writer.writeheader()
        for l in divergentes:
            writer.writerow({"Data/Hora (UTC)": agora, **l})


# ══════════════════════════════════════════════════════════════════════════════
# Programa principal
# ══════════════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cwes", default=os.environ.get("JULIET_CWES", "todos"),
                    help="Lista separada por vírgula, ex.: '121,122,127', ou 'todos' (os 24 suportados). "
                         "Default via env JULIET_CWES.")
    ap.add_argument("--por-cwe", type=int, default=int(os.environ.get("JULIET_POR_CWE", "5")),
                    help="Quantos casos sortear POR CWE (padrão: 5). Default via env JULIET_POR_CWE.")
    ap.add_argument("--juliet-dir", default=os.environ.get("JULIET_DIR", "./data/juliet/C"),
                    help="Pasta que contém manifest.xml, testcases/ e testcasesupport/ (padrão: ./data/juliet/C). "
                         "Default via env JULIET_DIR.")
    ap.add_argument("--saida", default=os.environ.get("JULIET_SAIDA", "./output/avaliacao_juliet.csv"),
                    help="CSV de resultado da rodada atual. Default via env JULIET_SAIDA.")
    ap.add_argument("--seed", type=int, default=int(os.environ.get("JULIET_SEED", "42")),
                    help="Semente da amostragem (reprodutibilidade). Default via env JULIET_SEED.")
    ap.add_argument("--historico", default=os.environ.get("JULIET_HISTORICO", "./output/juliet_historico.csv"),
                    help="CSV cumulativo (1 linha por rodada). Default via env JULIET_HISTORICO.")
    ap.add_argument("--divergencias", default=os.environ.get("JULIET_DIVERGENCIAS", "./output/juliet_divergencias.csv"),
                    help="CSV cumulativo dos casos que não bateram o rótulo oficial. Default via env JULIET_DIVERGENCIAS.")
    ap.add_argument("--listar-candidatos", action="store_true",
                    help="Só mostra quantos casos elegíveis existem por CWE e sai, sem compilar/rodar nada.")
    ap.add_argument("--versao", choices=("bad", "good"), default=os.environ.get("JULIET_VERSAO", "bad"),
                    help="'bad' (padrão): mede acerto do CWE. 'good': compila com -DOMITBAD (só as "
                         "funções corrigidas) e mede ALARMES FALSOS. Default via env JULIET_VERSAO.")
    args = ap.parse_args()
    if args.versao == "good":
        # Saídas separadas: os campos da rodada "good" são outros (alarmes, não acertos).
        for campo in ("saida", "historico", "divergencias"):
            caminho = getattr(args, campo)
            if not caminho.endswith("_good.csv"):
                setattr(args, campo, caminho.replace(".csv", "_good.csv"))

    pasta_testcasesupport = os.path.join(args.juliet_dir, "testcasesupport")
    if not args.listar_candidatos and not os.path.isdir(pasta_testcasesupport):
        sys.exit(f"[Erro] Não achei '{pasta_testcasesupport}' (esperado dentro de --juliet-dir).")

    print(f"[Info] Lendo manifest em {args.juliet_dir} ...")
    candidatos = carregar_candidatos(args.juliet_dir)

    if args.cwes.strip().lower() == "todos":
        cwes_pedidos = sorted(candidatos.keys())
    else:
        cwes_pedidos = [c.strip() if c.strip().upper().startswith("CWE-") else f"CWE-{c.strip()}"
                        for c in args.cwes.split(",") if c.strip()]

    print(f"\n{'CWE':<10}{'candidatos elegíveis':>22}")
    for cwe in cwes_pedidos:
        print(f"{cwe:<10}{len(candidatos.get(cwe, [])):>22}")

    if args.listar_candidatos:
        return

    rng = random.Random(args.seed)
    selecionados = []  # (cwe_esperado, caminho, linha, nome_arquivo)
    for cwe in cwes_pedidos:
        disponiveis = candidatos.get(cwe, [])
        if not disponiveis:
            print(f"[Aviso] Nenhum candidato elegível para {cwe} — pulando.")
            continue
        amostra = rng.sample(disponiveis, k=min(args.por_cwe, len(disponiveis)))
        selecionados.extend((cwe, caminho, linha, nome) for (caminho, linha, nome) in amostra)

    if not selecionados:
        sys.exit("[Erro] Nenhum caso selecionado — confira --cwes e o conteúdo de --juliet-dir.")

    pasta_bin = "./output/bin_juliet"
    if os.path.isdir(pasta_bin):
        shutil.rmtree(pasta_bin)
    os.makedirs(pasta_bin, exist_ok=True)
    os.makedirs(os.path.dirname(args.saida) or ".", exist_ok=True)

    print(f"\n[Info] {len(selecionados)} caso(s) selecionado(s), versão '{args.versao}'. "
          f"Rodando a cascata (Malha 1 -> Malha 2 -> Malha UBSan -> cwe.py)...\n")

    adjudicacao = carregar_adjudicacao()
    linhas_csv = []
    for i, (cwe_esperado, caminho, linha_defeito, nome_arquivo) in enumerate(selecionados, 1):
        print(f"[{i}/{len(selecionados)}] {nome_arquivo} (esperado: {cwe_esperado}, linha {linha_defeito})")
        inicio = time.time()
        try:
            cwe_obtido, cwe_nome, ferramenta, status, linha_sintoma, linha_causa = avaliar_caso(
                caminho, pasta_testcasesupport, pasta_bin, cwe_esperado, versao=args.versao
            )
        except Exception as e:  # caso travado/erro inesperado não aborta a rodada inteira
            cwe_obtido, cwe_nome, ferramenta, status = "-", "-", "Nenhuma", f"erro_interno: {e}"
            linha_sintoma, linha_causa = "-", "-"
        duracao = round(time.time() - inicio, 2)

        if args.versao == "good":
            # Versão corrigida: o certo é passar limpo; qualquer detecção é alarme falso.
            alarme = status == "detectado"
            natureza = "-"
            if alarme:
                with open(caminho, encoding="utf-8", errors="replace") as f:
                    natureza = natureza_do_alarme(f.read(), cwe_obtido)
            print(f"      -> {ferramenta} | status={status} | obtido={cwe_obtido} | "
                  f"{natureza if alarme else 'ok (limpo)'} ({duracao}s)")
            linhas_csv.append({
                "Arquivo": nome_arquivo,
                "CWE do Caso (Juliet)": cwe_esperado,
                "CWE Obtido (pipeline)": cwe_obtido,
                "Linha Sintoma (ferramenta)": linha_sintoma,
                "Ferramenta": ferramenta,
                "Status": status,
                "Detectou Algo": "sim" if alarme else "não",
                "Natureza da Detecção": natureza,
                "Tempo (s)": duracao,
            })
            continue

        acerto_estrito = (status == "detectado" and cwe_obtido == cwe_esperado)
        acerto_hierarquia = acerto_estrito or (
            status == "detectado" and (
                _PAI_NA_HIERARQUIA.get(cwe_esperado) == cwe_obtido
                or cwe_obtido in _EQUIVALENCIA_PROJETO.get(cwe_esperado, ())
            )
        )

        if acerto_estrito:
            causa = "-"
        elif acerto_hierarquia:
            causa = "convenção"
        elif status == "erro_compilacao":
            causa = "-"
        else:
            with open(caminho, encoding="utf-8", errors="replace") as f:
                causa = causa_da_divergencia(nome_arquivo, f.read(), cwe_esperado, cwe_obtido,
                                             status, adjudicacao)

        print(f"      -> {ferramenta} | status={status} | obtido={cwe_obtido} | "
              f"estrito={'OK' if acerto_estrito else 'X'} | hierarquia={'OK' if acerto_hierarquia else 'X'} "
              f"| causa={causa} ({duracao}s)")

        linhas_csv.append({
            "Arquivo": nome_arquivo,
            "CWE Esperado (Juliet)": cwe_esperado,
            "Linha do Defeito (manifest)": linha_defeito,
            "Linha Sintoma (ferramenta)": linha_sintoma,
            "Linha Causa (ferramenta)": linha_causa,
            "CWE Obtido (pipeline)": cwe_obtido,
            "Nome CWE Obtido": cwe_nome,
            "Ferramenta": ferramenta,
            "Status": status,
            "Acerto Estrito": "sim" if acerto_estrito else "não",
            "Acerto com Hierarquia/Convenção": "sim" if acerto_hierarquia else "não",
            "Causa": causa,
            "Tempo (s)": duracao,
        })

    with open(args.saida, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=linhas_csv[0].keys())
        writer.writeheader()
        writer.writerows(linhas_csv)
    print(f"\n[Info] CSV da rodada salvo em: {args.saida}")

    os.makedirs(os.path.dirname(args.historico) or ".", exist_ok=True)
    _registrar_historico(args.historico, args, cwes_pedidos, linhas_csv)
    print(f"[Info] Histórico acumulado em: {args.historico}")

    if args.versao == "good":
        total = len(linhas_csv)
        alarmes = [l for l in linhas_csv if l["Natureza da Detecção"] == NATUREZA_ALARME_FALSO]
        vazamentos = [l for l in linhas_csv if l["Natureza da Detecção"] == NATUREZA_VAZAMENTO_REAL]
        print("\n" + "=" * 60)
        print("RESUMO — VERSÕES CORRIGIDAS (good)")
        print("=" * 60)
        print(f"Total de casos:   {total}")
        print(f"Vazamentos reais no código corrigido (alocação sem free): {len(vazamentos)}")
        print(f"Alarmes falsos:   {len(alarmes)}/{total} ({100*len(alarmes)/total:.1f}%)")
        for l in alarmes:
            print(f"  {l['Arquivo']} -> {l['CWE Obtido (pipeline)']} ({l['Ferramenta']})")
        return

    os.makedirs(os.path.dirname(args.divergencias) or ".", exist_ok=True)
    _registrar_divergencias(args.divergencias, linhas_csv)
    print(f"[Info] Divergências acumuladas em: {args.divergencias}")

    # ── RESUMO ──
    compilacao_falhou = sum(1 for l in linhas_csv if l["Status"] == "erro_compilacao")
    lentes = resumo_por_lentes(linhas_csv)
    nomes_lentes = {
        "L1": "estrito (CWE igual ao rótulo)",
        "L2": "+ hierarquia/convenção",
        "L3": "L2 sem causas A e B (escopo)",
        "L4": "L3 + C e D (defeito verdadeiro)",
    }

    print("\n" + "=" * 60)
    print("RESUMO GERAL")
    print("=" * 60)
    print(f"Total de casos: {len(linhas_csv)}")
    for lente, (acertos, n) in lentes.items():
        print(f"  {lente} {nomes_lentes[lente]:<34} {acertos}/{n} ({100*acertos/n if n else 0:.1f}%)")
    if compilacao_falhou:
        print(f"Falha de COMPILAÇÃO (fora da amostra de acurácia): {compilacao_falhou}")

    print("\nCausas das divergências:")
    contagem = {}
    for l in linhas_csv:
        if l["Causa"] not in ("-", "convenção"):
            contagem[l["Causa"]] = contagem.get(l["Causa"], 0) + 1
    for causa in sorted(contagem):
        print(f"  {causa:<40} {contagem[causa]}")

    print("\nPor CWE (estrito):")
    for cwe in cwes_pedidos:
        linhas_cwe = [l for l in linhas_csv if l["CWE Esperado (Juliet)"] == cwe]
        if not linhas_cwe:
            continue
        acertos = sum(1 for l in linhas_cwe if l["Acerto Estrito"] == "sim")
        print(f"  {cwe:<10} {acertos}/{len(linhas_cwe)}")


if __name__ == "__main__":
    main()
