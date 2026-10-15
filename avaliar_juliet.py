"""
Harness de validação do pipeline determinístico contra o Juliet Test Suite (NIST SARD).

Diferente do `orquestrador.py` (modo catálogo, com feedback via LLM), este script roda SÓ a
parte determinística — Malha 1 (ASan+GDB), Malha 2 (Valgrind+vgdb) e `src/cwe.py` — e nunca
chama o Ollama. Para cada caso selecionado, compara o CWE devolvido pelo pipeline com o CWE
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
from src.parser_logs import limpar_log_gdb
from src.cwe import classificar_cwe, _NOME as CWES_SUPORTADOS  # mesma tabela do classificador


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

# Equivalências ADOTADAS PELO PROJETO — não é hierarquia oficial do MITRE (758 não é ancestral de
# 824/457 na árvore do CWE), mas uma convenção de classificação: quando o Juliet rotula um caso
# como CWE-758 ("Reliance on Undefined, Unspecified, or Implementation-Defined Behavior", um
# guarda-chuva genérico), o que a ferramenta observa na prática é sempre uma de duas causas
# específicas — ponteiro com lixo (CWE-824, via ASan/segfault) ou o valor não inicializado em si
# (CWE-457, via Valgrind, antes do ponteiro ser usado) — nunca o CWE-758 "genérico" de volta, já
# que esse código não tem regra para devolvê-lo. Investigado caso a caso (ver conversa): os 5
# casos de CWE-758 testados foram TODOS 824 ou 457, nenhum "errado" de fato — é o próprio Juliet
# rotulando pelo guarda-chuva onde a ferramenta soube ser mais específica. Decidido tratar como
# equivalente "por enquanto" (15/10/2026) — revisar se a diferenciação 758 x 824/457 importar
# para a pesquisa mais adiante.
_EQUIVALENCIA_PROJETO = {
    "CWE-758": {"CWE-824", "CWE-457"},
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
}
# Tetos de memória (ver docstrings em malha1_asan.executar_malha_1_asan e
# malha2_valgrind.executar_malha_2_valgrind): sem eles, uma alocação "absurda" mas ainda dentro do
# que a máquina consegue reservar (poucos GB) é tentada de verdade em vez de rejeitada na hora.
# Aplicados em TODO caso (não só CWE-789) como defesa extra — testado que não muda o resultado de
# casos normais (regressão com CWE-401 real: detecta o vazamento igual, com ou sem o teto).
LIMITE_ALOCACAO_ASAN_MB = 500      # Malha 1: acima disso, o ASan recusa a alocação na hora.
LIMITE_MEMORIA_VALGRIND_MB = 1024  # Malha 2: teto de memória virtual do processo (e do Valgrind
                                    # em si — 1 GB já é generoso para o próprio Valgrind iniciar).

# CWE-190 (overflow aritmético genérico, ex.: variantes "_preinc_"/"_postinc_"/"_square_" do
# Juliet) FICA DE FORA de propósito: a Malha 1 compila só com -fsanitize=address, e esse tipo de
# overflow só é detectável com -fsanitize=undefined (UBSan), que o pipeline não liga. Nenhuma
# entrada resolve isso — é limitação do conjunto de ferramentas, não de estímulo. Ver explicação
# no resumo final do script.
#
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

def avaliar_caso(caminho_fonte, pasta_testcasesupport, pasta_bin, cwe_esperado):
    """
    Roda a cascata determinística sobre um único arquivo do Juliet.
    Devolve (cwe_obtido, cwe_nome, ferramenta, status, log_bruto_ou_None).
    `status`: "detectado" | "passou_limpo" | "erro_compilacao".
    """
    flags_extra = [
        "-DINCLUDEMAIN",
        "-I", pasta_testcasesupport,
        os.path.join(pasta_testcasesupport, "io.c"),
    ]
    base = re.sub(r"[^A-Za-z0-9_.-]", "_", os.path.splitext(os.path.basename(caminho_fonte))[0])
    entrada = _ENTRADA_SINTETICA_POR_CWE.get(cwe_esperado)  # None = usa a heurística padrão

    resultado = executar_malha_1_asan(
        caminho_fonte,
        binario_saida=os.path.join(pasta_bin, f"{base}_asan"),
        entrada=entrada,
        flags_extra=flags_extra,
        limite_alocacao_mb=LIMITE_ALOCACAO_ASAN_MB,
    )
    ferramenta = "ASan+GDB"

    if resultado and resultado.get("tipo") == "compilacao":
        return "-", "-", "Compilador (gcc)", "erro_compilacao", resultado["log"]

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
            return "-", "-", "Compilador (gcc)", "erro_compilacao", resultado["log"]

    if not resultado:
        return "-", "-", "Nenhuma", "passou_limpo", None

    log_limpo = limpar_log_gdb(resultado["log"], os.path.basename(caminho_fonte))
    cwe_id, cwe_nome = classificar_cwe(log_limpo)
    return cwe_id, cwe_nome, ferramenta, "detectado", resultado["log"]


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


def _registrar_historico(caminho_historico, args, cwes_pedidos, linhas_csv):
    """Acrescenta (não sobrescreve) uma linha-resumo desta rodada em output/juliet_historico.csv."""
    total = len(linhas_csv)
    estritos = sum(1 for l in linhas_csv if l["Acerto Estrito"] == "sim")
    hierarquia = sum(1 for l in linhas_csv if l["Acerto com Hierarquia/Convenção"] == "sim")
    compilacao_falhou = sum(1 for l in linhas_csv if l["Status"] == "erro_compilacao")

    linha = {
        "Data/Hora (UTC)": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "Commit cwe.py": _commit_atual(),
        "CWEs Testados": ",".join(cwes_pedidos),
        "Por CWE": args.por_cwe,
        "Seed": args.seed,
        "Total de Casos": total,
        "Acerto Estrito": estritos,
        "Acerto Estrito (%)": round(100 * estritos / total, 1) if total else 0,
        "Acerto c/ Hierarquia": hierarquia,
        "Acerto c/ Hierarquia (%)": round(100 * hierarquia / total, 1) if total else 0,
        "Falhas de Compilação": compilacao_falhou,
    }
    existe = os.path.isfile(caminho_historico)
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
    existe = os.path.isfile(caminho_divergencias)
    with open(caminho_divergencias, "a", newline="", encoding="utf-8") as f:
        campos = ["Data/Hora (UTC)"] + list(divergentes[0].keys())
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
    args = ap.parse_args()

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

    print(f"\n[Info] {len(selecionados)} caso(s) selecionado(s). Rodando a cascata (Malha 1 -> Malha 2 -> cwe.py)...\n")

    linhas_csv = []
    for i, (cwe_esperado, caminho, linha_defeito, nome_arquivo) in enumerate(selecionados, 1):
        print(f"[{i}/{len(selecionados)}] {nome_arquivo} (esperado: {cwe_esperado}, linha {linha_defeito})")
        inicio = time.time()
        try:
            cwe_obtido, cwe_nome, ferramenta, status, _log = avaliar_caso(
                caminho, pasta_testcasesupport, pasta_bin, cwe_esperado
            )
        except Exception as e:  # caso travado/erro inesperado não aborta a rodada inteira
            cwe_obtido, cwe_nome, ferramenta, status = "-", "-", "Nenhuma", f"erro_interno: {e}"
        duracao = round(time.time() - inicio, 2)

        acerto_estrito = (status == "detectado" and cwe_obtido == cwe_esperado)
        acerto_hierarquia = acerto_estrito or (
            status == "detectado" and (
                _PAI_NA_HIERARQUIA.get(cwe_esperado) == cwe_obtido
                or cwe_obtido in _EQUIVALENCIA_PROJETO.get(cwe_esperado, ())
            )
        )

        print(f"      -> {ferramenta} | status={status} | obtido={cwe_obtido} | "
              f"estrito={'OK' if acerto_estrito else 'X'} | hierarquia={'OK' if acerto_hierarquia else 'X'} "
              f"({duracao}s)")

        linhas_csv.append({
            "Arquivo": nome_arquivo,
            "CWE Esperado (Juliet)": cwe_esperado,
            "Linha do Defeito (manifest)": linha_defeito,
            "CWE Obtido (pipeline)": cwe_obtido,
            "Nome CWE Obtido": cwe_nome,
            "Ferramenta": ferramenta,
            "Status": status,
            "Acerto Estrito": "sim" if acerto_estrito else "não",
            "Acerto com Hierarquia/Convenção": "sim" if acerto_hierarquia else "não",
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

    os.makedirs(os.path.dirname(args.divergencias) or ".", exist_ok=True)
    _registrar_divergencias(args.divergencias, linhas_csv)
    print(f"[Info] Divergências acumuladas em: {args.divergencias}")

    # ── RESUMO ──
    total = len(linhas_csv)
    estritos = sum(1 for l in linhas_csv if l["Acerto Estrito"] == "sim")
    hierarquia = sum(1 for l in linhas_csv if l["Acerto com Hierarquia/Convenção"] == "sim")
    compilacao_falhou = sum(1 for l in linhas_csv if l["Status"] == "erro_compilacao")

    print("\n" + "=" * 60)
    print("RESUMO GERAL")
    print("=" * 60)
    print(f"Total de casos:                {total}")
    print(f"Acerto estrito (CWE igual):    {estritos}/{total} ({100*estritos/total:.1f}%)")
    print(f"Acerto c/ hierarquia/convenção:    {hierarquia}/{total} ({100*hierarquia/total:.1f}%)")
    if compilacao_falhou:
        print(f"Falha de COMPILAÇÃO (fora da amostra de acurácia): {compilacao_falhou}")

    print("\nPor CWE:")
    for cwe in cwes_pedidos:
        linhas_cwe = [l for l in linhas_csv if l["CWE Esperado (Juliet)"] == cwe]
        if not linhas_cwe:
            continue
        acertos = sum(1 for l in linhas_cwe if l["Acerto Estrito"] == "sim")
        print(f"  {cwe:<10} {acertos}/{len(linhas_cwe)}")

    if "CWE-190" in cwes_pedidos:
        print(
            "\n[Aviso] CWE-190 (overflow aritmético genérico) tende a 0% de propósito: esses "
            "casos do Juliet só são detectáveis com -fsanitize=undefined (UBSan), que a Malha 1 "
            "não liga hoje (só -fsanitize=address). Não é falha do classificador nem de entrada."
        )


if __name__ == "__main__":
    main()
