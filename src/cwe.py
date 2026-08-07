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


# (regex, CWE ID, nome) — ordem = prioridade. Ver comentário de ordenação acima.
_REGRAS_BRUTAS = [
    # ── Erros de LIBERAÇÃO (vêm antes do use-after-free: ambos citam "free'd") ──
    (r"attempting double-free|\bdouble-free\b",                      "CWE-415", "Double Free"),
    (r"attempting free on address which was not malloc",            "CWE-590", "Free of Memory not on the Heap"),
    (r"Mismatched free",                                            "CWE-762", "Mismatched Memory Management Routines"),
    (r"Invalid free",                                               "CWE-415", "Double Free"),  # Valgrind genérico -> caso comum

    # ── USE-AFTER-FREE: "heap-use-after-free" (ASan) ou "free'd" no descritor (Valgrind) ──
    (r"heap-use-after-free|free'd",                                 "CWE-416", "Use After Free"),

    # ── Uso após fim de vida da variável local (escopo/retorno) ──
    (r"stack-use-after-return",                                     "CWE-562", "Return of Stack Variable Address"),
    (r"use-after-scope",                                            "CWE-825", "Expired Pointer Dereference"),

    # ── OVERFLOW por LOCALIZAÇÃO (o ASan sabe se é stack/heap/global) ──
    (r"heap-buffer-overflow",                                       "CWE-122", "Heap-based Buffer Overflow"),
    (r"stack-buffer-overflow",                                      "CWE-121", "Stack-based Buffer Overflow"),
    (r"global-buffer-overflow",                                     "CWE-787", "Out-of-bounds Write"),

    # ── Valor NÃO INICIALIZADO ──
    (r"depends on uninitialised|Use of uninitialised value|uninitialized-value",
                                                                    "CWE-457", "Use of Uninitialized Variable"),

    # ── VAZAMENTO de memória ──
    (r"(?:definitely|indirectly) lost",                            "CWE-401", "Missing Release of Memory after Effective Lifetime"),

    # ── Acesso inválido GENÉRICO (Valgrind, sem contexto de free) — por DIREÇÃO ──
    (r"Invalid write",                                             "CWE-787", "Out-of-bounds Write"),
    (r"Invalid read",                                              "CWE-125", "Out-of-bounds Read"),

    # ── Crash por sinal: deref de ponteiro nulo (caso dominante em iniciantes) ──
    (r"\bSEGV\b|Segmentation fault|null pointer",                  "CWE-476", "NULL Pointer Dereference"),
]

# Pré-compila os padrões uma vez.
REGRAS_CWE = [(re.compile(rx, re.IGNORECASE), cid, nome) for (rx, cid, nome) in _REGRAS_BRUTAS]

# Valor quando o log não casa nenhuma classe conhecida (ex.: erro de compilação).
SEM_CWE = ("-", "-")


def classificar_cwe(log):
    """
    Devolve (cwe_id, cwe_nome) determinado pelo RELATÓRIO DA FERRAMENTA, ou ('-', '-').

    Recebe idealmente o log BRUTO (relatório completo). A primeira regra cujo regex casar
    em qualquer parte do log define o CWE (por isso a ordem das regras importa).
    """
    if not log:
        return SEM_CWE
    for rx, cid, nome in REGRAS_CWE:
        if rx.search(log):
            return (cid, nome)
    return SEM_CWE
