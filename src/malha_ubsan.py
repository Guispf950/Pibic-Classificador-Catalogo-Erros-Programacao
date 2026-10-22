"""
Malha UBSan — UndefinedBehaviorSanitizer.

Pega comportamentos indefinidos que o ASan e o Valgrind não veem, porque não são acesso a
memória "envenenada":
  - estouro de inteiro COM SINAL (int/long): soma, produto, negação, INT_MIN / -1;
  - deslocamento de bits inválido (1 << 40, deslocamento negativo);
  - índice fora de vetor de TAMANHO CONHECIDO pelo compilador (local, global, VLA, vetor dentro
    de struct, linha/coluna de matriz) — MESMO quando o índice cai muito longe do vetor, onde o
    ASan só vê um segmentation fault genérico, e mesmo em m[1][10], que cai dentro da própria
    matriz e por isso o ASan/Valgrind nunca acusam.
O que ela NÃO pega (medido no sandbox, GCC 11.4): estouro de char/short/unsigned (em C não é
comportamento indefinido), índice em vetor alocado com malloc (o ponteiro não carrega o tamanho),
função sem `return` (o UBSan só acusa isso em C++).

Quando roda (ver `deve_refinar` e os chamadores):
  1. depois que as Malhas 1 e 2 saíram limpas — aceita qualquer relatório do UBSan;
  2. quando a Malha 1 terminou num crash genérico — aqui aceita SÓ o relatório que EXPLICA esse
     crash: num segmentation fault, índice fora do vetor (troca "ponteiro inválido" por "índice X
     fora de int[10]"); num SIGFPE, "INT_MIN / -1" (o processador dispara o MESMO sinal da divisão
     por zero, mas o divisor é -1 — é estouro, CWE-190). Um estouro de inteiro qualquer visto
     nesta passada pode ser incidental e não substitui o crash.

Por que não junto da Malha 1 (-fsanitize=address,undefined): a checagem de índice do UBSan
dispara ANTES do ASan e não diz se o acesso foi leitura ou escrita — a Malha 1 perderia a
distinção 121/126 etc. e os resultados já validados mudariam.

Estouro "incidental": o processador "dá a volta" no int de forma previsível, então um código
com estouro (ex.: hash h = h*31 + c, usado só módulo M) pode imprimir a saída esperada. Por
isso o UBSan só vira o erro reportado quando nada mais foi encontrado (decisão de projeto).
"""

import os
import re
import subprocess

from src.deteccao_entrada import stdin_para_analise


# halt_on_error=1: para no 1º comportamento indefinido (como o ASan faz no 1º erro).
# print_stacktrace=1: imprime a pilha de chamadas (função e arquivo:linha) depois da mensagem.
UBSAN_OPTIONS = "halt_on_error=1:print_stacktrace=1"

# Mensagens que valem na passada de REFINAMENTO de um crash (ver docstring).
_RX_EXPLICA_CRASH = re.compile(
    r"runtime error: (?:index -?\d+ out of bounds|variable length array bound|division of -?\d+ by -1)")
# Crash "genérico" da Malha 1: segmentation fault (crash cru pego pelo GDB ou SEGV relatado pelo
# ASan) ou SIGFPE.
_RX_CRASH_GENERICO = re.compile(
    r"received signal SIGSEGV|SEGV on unknown address|received signal SIGFPE|FPE on unknown address")


def deve_refinar(resultado_malha1):
    """True se a Malha 1 terminou num crash genérico (candidato a refinamento pelo UBSan)."""
    if not resultado_malha1 or resultado_malha1.get("tipo") not in ("crash", "asan"):
        return False
    return bool(_RX_CRASH_GENERICO.search(resultado_malha1.get("log", "")))


def executar_malha_ubsan(caminho_codigo, binario_saida="./bin_ubsan", entrada=None, flags_extra=None,
                         somente_indice=False):
    """
    Compila com -fsanitize=undefined e executa (sem GDB: a mensagem do UBSan já traz
    arquivo:linha:coluna e a pilha de chamadas).
    Retorna dict com 'tipo'="ubsan", 'erro' e 'log' se algo for detectado, ou None se limpo.
    `somente_indice=True`: modo refinamento — só aceita o que explica o crash (índice fora do
    vetor ou INT_MIN / -1).
    `flags_extra`: como em malha1_asan.executar_malha_1_asan (só o harness do Juliet usa).
    """
    # -fno-sanitize-recover=undefined: transforma o 1º relatório em parada (sem isso alguns
    #   tipos só avisam e o programa segue, podendo gerar vários relatórios).
    # -std=gnu11 / -g / -fno-omit-frame-pointer: mesmos motivos da Malha 1.
    compilacao = subprocess.run(
        ["gcc", "-std=gnu11",
         "-fsanitize=undefined",
         "-fno-sanitize-recover=undefined",
         "-fno-omit-frame-pointer",
         "-g", caminho_codigo, *(flags_extra or []), "-o", binario_saida],
        capture_output=True, text=True, errors="replace",
    )
    # Um erro de compilação já teria parado a Malha 1; aqui só não há o que executar.
    if compilacao.returncode != 0:
        return None

    env = dict(os.environ, UBSAN_OPTIONS=UBSAN_OPTIONS)
    stdin_analise = entrada if entrada is not None else stdin_para_analise(caminho_codigo)
    try:
        execucao = subprocess.run(
            [binario_saida], env=env, capture_output=True, text=True, errors="replace",
            input=stdin_analise, timeout=60,
        )
    except subprocess.TimeoutExpired:
        return None
    saida = execucao.stdout + execucao.stderr

    if "runtime error:" not in saida:
        return None
    if somente_indice and not _RX_EXPLICA_CRASH.search(saida):
        return None
    return {
        "tipo": "ubsan",
        "erro": "Detectado pelo UBSan",
        "log": saida,
    }
