"""
Classificação do erro para CWE (Common Weakness Enumeration, do MITRE).

A Common Weakness Enumeration, ou Enumeração de Fraquezas Comuns, é uma 
lista mantida pela organização MITRE, que cataloga fraquezas conhecidas 
em software, ou seja, erros recorrentes de design, arquitetura ou implementação
que podem levar a vulnerabilidades de segurança.
======================================================================

Mapeia, de forma DETERMINÍSTICA, o erro reportado pela FERRAMENTA (ASan/Valgrind) para
o identificador CWE correspondente. É um LOOKUP por regex sobre o relatório, NUNCA uma
pergunta ao LLM. Motivos:
  * a ferramenta já dá o tipo exato do erro; mapear para CWE é uma tabela fixa;
  * mantém a essência determinística do pipeline (sem reintroduzir alucinação);
  * o CWE vira também uma CHECAGEM DE CONSISTÊNCIA contra o `tipo_erro` que o LLM gera/devolve na etapa de análise forense.

Fundamentação: catálogo CWE do MITRE (cwe.mitre.org) e o Juliet Test Suite / NIST SARD,
o benchmark padrão de falhas em C/C++, que é rotulado por CWE.

Cada regra é `(regex_do_relatório, CWE_ID, nome)`, avaliada em ORDEM DE PRIORIDADE
(a primeira que casar vence). A ordem importa: erros que compartilham marcadores no log
(ex.: double-free e use-after-free ambos citam "free'd") são desambiguados pela ordem.
"""

import re


# ══════════════════════════════════════════════════════════════════════════════
# TABELA DE REGRAS: assinatura no log da ferramenta  ->  CWE
# ══════════════════════════════════════════════════════════════════════════════
# A ideia é simples: o ASan e o Valgrind imprimem, no relatório, uma FRASE característica
# para cada tipo de erro (ex.: "heap-use-after-free", "definitely lost"). Cada item abaixo
# é (regex, CWE_ID, nome): a gente procura a frase no log e devolve o CWE correspondente.
#
# Lembrete rápido dos símbolos de regex usados aqui:
#   |          -> "ou" (casa qualquer uma das alternativas)
#   \b         -> "fronteira de palavra" (evita casar dentro de outra palavra maior)
#   (?: ... )  -> agrupa alternativas sem "capturar" (só para organizar o "ou")
#   \d+        -> um ou mais dígitos
# A busca ignora maiúsculas/minúsculas (o re.IGNORECASE é aplicado na compilação, abaixo).
#
# A ORDEM IMPORTA: a primeira regra que casar vence. Por isso erros que dividem a mesma
# palavra no log (ex.: "free'd") precisam vir na sequência certa — ver o bloco de liberação.
_REGRAS_BRUTAS = [
    # ── LIBERAÇÃO INDEVIDA DE MEMÓRIA ────────────────────────────────────────────
    # Vêm PRIMEIRO de propósito: tanto o double-free quanto o use-after-free citam "free'd"
    # no relatório do Valgrind. Colocando as regras de liberação antes, elas "pegam" o caso
    # certo, e a de use-after-free (mais abaixo) só fica com o que sobra.

    # ASan imprime "attempting double-free". Liberar (free) o MESMO bloco duas vezes.
    (r"attempting double-free|\bdouble-free\b",                      "CWE-415", "Double Free"),
    # ASan: "attempting free on address which was not malloc()-ed" -> deu free em algo que
    # NÃO veio do heap (ex.: uma variável local, ou um ponteiro no meio de um bloco).
    (r"attempting free on address which was not malloc",            "CWE-590", "Free of Memory not on the Heap"),
    # Valgrind: "Mismatched free" -> alocou de um jeito e liberou de outro (típico de C++,
    # ex.: new[] liberado com delete). Incluído por completude.
    (r"Mismatched free",                                            "CWE-762", "Mismatched Memory Management Routines"),
    # "Invalid free" é a mensagem GENÉRICA do Valgrind para uma liberação inválida. Como
    # chegou aqui (não casou as de cima), tratamos como o caso mais comum: liberar 2x.
    (r"Invalid free",                                               "CWE-415", "Double Free"),  # Valgrind genérico -> caso comum

    # ── USO DE MEMÓRIA JÁ LIBERADA (ponteiro pendente / dangling) ────────────────
    # ASan usa o nome "heap-use-after-free". O Valgrind não usa esse nome, mas ao acessar
    # um bloco liberado ele descreve o endereço como "... free'd". Qualquer um dos dois =
    # usar memória DEPOIS do free.
    (r"heap-use-after-free|free'd",                                 "CWE-416", "Use After Free"),

    # ── USO DE VARIÁVEL LOCAL APÓS O FIM DE VIDA DELA ────────────────────────────
    # "stack-use-after-return": usar (via ponteiro) uma variável local depois que a função
    # que a criou já RETORNOU — a memória da pilha dela já foi reciclada.
    (r"stack-use-after-return",                                     "CWE-562", "Return of Stack Variable Address"),
    # "use-after-scope": usar uma variável local depois que o bloco { } dela FECHOU.
    (r"use-after-scope",                                            "CWE-825", "Expired Pointer Dereference"),

    # ── ACESSO FORA DOS LIMITES DE UM BUFFER (overflow) ──────────────────────────
    # O ASan é preciso e diz ONDE fica o buffer estourado (heap, pilha ou global). A gente
    # aproveita isso para escolher o CWE específico de cada localização.
    (r"heap-buffer-overflow",                                       "CWE-122", "Heap-based Buffer Overflow"),
    (r"stack-buffer-overflow",                                      "CWE-121", "Stack-based Buffer Overflow"),
    (r"global-buffer-overflow",                                     "CWE-787", "Out-of-bounds Write"),

    # ── USO DE VALOR NÃO INICIALIZADO ────────────────────────────────────────────
    # Valgrind: "Conditional jump ... depends on uninitialised value(s)" ou "Use of
    # uninitialised value". É usar uma variável ANTES de ter dado um valor a ela.
    (r"depends on uninitialised|Use of uninitialised value|uninitialized-value",
                                                                    "CWE-457", "Use of Uninitialized Variable"),

    # ── VAZAMENTO DE MEMÓRIA (leak) ──────────────────────────────────────────────
    # Valgrind: "... bytes ... are definitely/indirectly lost". Alocou e NUNCA liberou; o
    # programa perdeu a referência para o bloco (não afeta a saída, mas desperdiça memória).
    (r"(?:definitely|indirectly) lost",                            "CWE-401", "Missing Release of Memory after Effective Lifetime"),

    # ── ACESSO INVÁLIDO GENÉRICO (Valgrind, sem contexto de free) — por DIREÇÃO ──
    # Se não caiu em use-after-free (não tinha "free'd"), é um acesso fora dos limites de um
    # bloco ainda vivo. O Valgrind diz a DIREÇÃO do acesso, e usamos ela para o CWE:
    (r"Invalid write",                                             "CWE-787", "Out-of-bounds Write"),   # escrita fora dos limites
    (r"Invalid read",                                              "CWE-125", "Out-of-bounds Read"),    # leitura fora dos limites

    # ── CRASH POR SINAL: ponteiro nulo ───────────────────────────────────────────
    # Um "SIGSEGV / Segmentation fault" sem nenhuma assinatura acima é, em código de
    # iniciante, quase sempre desreferenciar um ponteiro NULL. O \bSEGV\b evita casar
    # "SEGV" dentro de outra palavra; "Segmentation fault" cobre a mensagem do GDB.
    (r"\bSEGV\b|Segmentation fault|null pointer",                  "CWE-476", "NULL Pointer Dereference"),
]

# Pré-compila cada padrão UMA vez (na carga do módulo). Compilar o regex é o passo caro;
# fazendo aqui, cada chamada de classificar_cwe() só REUTILIZA os padrões já prontos.
# re.IGNORECASE = casa maiúsculas/minúsculas (ex.: "SEGV" e "segv" dão no mesmo).
REGRAS_CWE = [(re.compile(rx, re.IGNORECASE), cid, nome) for (rx, cid, nome) in _REGRAS_BRUTAS]

# Resposta padrão quando o log não casa nenhuma classe conhecida — por exemplo, um erro de
# COMPILAÇÃO (que não é uma fraqueza de memória e portanto não tem CWE aqui). O "-" mantém
# o formato de tupla esperado pelo resto do pipeline (dois campos: id e nome).
SEM_CWE = ("-", "-")


def classificar_cwe(log):
    """
    Descobre o CWE do erro a partir do RELATÓRIO DA FERRAMENTA (ASan/Valgrind).

    Ideia: percorre as regras EM ORDEM e devolve o CWE da PRIMEIRA cujo padrão aparecer em
    qualquer parte do log. É determinístico — depende só do texto da ferramenta, nunca do LLM.

    Parâmetro:
        log: idealmente o log BRUTO (relatório completo, com todas as seções), como string.

    Retorna:
        (cwe_id, cwe_nome), ex.: ("CWE-416", "Use After Free"); ou ('-', '-') se nenhuma
        assinatura conhecida for encontrada (ex.: erro de compilação, log vazio).
    """
    # Sem log não há o que classificar (ex.: nenhuma malha reportou nada).
    if not log:
        return SEM_CWE

    # Testa cada regra na ORDEM da tabela. rx.search procura o padrão em QUALQUER posição
    # do texto (não precisa estar no começo da linha). A primeira que casar decide o CWE
    # e encerra a busca — é por isso que a ordem das regras na tabela importa.
    for rx, cid, nome in REGRAS_CWE:
        if rx.search(log):
            return (cid, nome)

    # Percorreu todas as regras e nenhuma assinatura conhecida apareceu.
    return SEM_CWE


# ══════════════════════════════════════════════════════════════════════════════
# NOME TÉCNICO DO ERRO (tipo_erro) — DETERMINÍSTICO, derivado do MESMO CWE
# ══════════════════════════════════════════════════════════════════════════════
# Antes, o `tipo_erro` (ex.: "use-after-free") era pedido ao LLM. Mas ele é redundante
# com o CWE, que já sai da assinatura da ferramenta — logo, é 100% determinístico.
# Este mapa traduz o CWE apurado para o nome técnico curto usado no diagnóstico.
# (Alguns CWEs cobrem duas assinaturas — ex.: CWE-787 = global-overflow e Invalid write;
#  o nome escolhido descreve bem os dois casos.)
_TIPO_POR_CWE = {
    "CWE-415": "double-free",
    "CWE-590": "invalid-free",
    "CWE-762": "mismatched-free",
    "CWE-416": "use-after-free",
    "CWE-562": "stack-use-after-return",
    "CWE-825": "use-after-scope",
    "CWE-122": "heap-buffer-overflow",
    "CWE-121": "stack-buffer-overflow",
    "CWE-787": "out-of-bounds-write",
    "CWE-457": "uninitialized-value",
    "CWE-401": "memory-leak",
    "CWE-125": "out-of-bounds-read",
    "CWE-476": "null-pointer-dereference",
}


def classificar_cwe_tipo(log):
    """
    Igual a classificar_cwe, mas também devolve o NOME TÉCNICO do erro (tipo_erro),
    tudo DETERMINÍSTICO (da assinatura da ferramenta — nunca do LLM).

    Retorna: (cwe_id, cwe_nome, tipo_erro). Sem assinatura conhecida -> ("-", "-", "-").
    """
    cwe_id, cwe_nome = classificar_cwe(log)
    return cwe_id, cwe_nome, _TIPO_POR_CWE.get(cwe_id, "-")
