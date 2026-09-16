"""
Classificação do erro para CWE (Common Weakness Enumeration, do MITRE) — a lista do MITRE
que cataloga fraquezas conhecidas de software.

Mapeia, de forma DETERMINÍSTICA, o erro reportado pela ferramenta (ASan/Valgrind) para o
CWE correspondente, por lookup de regex sobre o relatório — nunca por consulta ao LLM.
Assim mantém-se a essência determinística do pipeline, e o CWE serve também de checagem de
consistência contra o diagnóstico.

Fundamentação: catálogo CWE do MITRE (cwe.mitre.org) e o Juliet Test Suite / NIST SARD,
benchmark de falhas em C/C++ rotulado por CWE.
"""

import re


# Tabela (regex, CWE, nome), em ORDEM DE PRIORIDADE — a primeira regra que casa vence.
# A ordem desambigua erros que compartilham marcadores no log (ex.: double-free e
# use-after-free ambos citam "free'd"; as regras de liberação vêm antes por isso).
_REGRAS_BRUTAS = [
    # Liberação indevida (antes do use-after-free, que também cita "free'd")
    (r"attempting double-free|\bdouble-free\b",                      "CWE-415", "Double Free"),
    (r"attempting free on address which was not malloc",            "CWE-590", "Free of Memory not on the Heap"),
    (r"Mismatched free",                                            "CWE-762", "Mismatched Memory Management Routines"),
    (r"Invalid free",                                               "CWE-415", "Double Free"),  # genérico do Valgrind

    # Uso de memória já liberada (ASan: "heap-use-after-free"; Valgrind: bloco "free'd")
    (r"heap-use-after-free|free'd",                                 "CWE-416", "Use After Free"),

    # Uso de variável local após o fim de vida dela
    (r"stack-use-after-return",                                     "CWE-562", "Return of Stack Variable Address"),
    (r"use-after-scope",                                            "CWE-825", "Expired Pointer Dereference"),

    # Acesso fora dos limites de buffer (o ASan indica a localização)
    (r"heap-buffer-overflow",                                       "CWE-122", "Heap-based Buffer Overflow"),
    (r"stack-buffer-overflow",                                      "CWE-121", "Stack-based Buffer Overflow"),
    (r"global-buffer-overflow",                                     "CWE-787", "Out-of-bounds Write"),

    # Uso de valor não inicializado
    (r"depends on uninitialised|Use of uninitialised value|uninitialized-value",
                                                                    "CWE-457", "Use of Uninitialized Variable"),

    # Vazamento de memória
    (r"(?:definitely|indirectly) lost",                            "CWE-401", "Missing Release of Memory after Effective Lifetime"),

    # Acesso inválido genérico do Valgrind (sem "free'd"): CWE pela direção do acesso
    (r"Invalid write",                                             "CWE-787", "Out-of-bounds Write"),
    (r"Invalid read",                                              "CWE-125", "Out-of-bounds Read"),

    # Crash por sinal sem outra assinatura: em código de iniciante, quase sempre deref de NULL
    (r"\bSEGV\b|Segmentation fault|null pointer",                  "CWE-476", "NULL Pointer Dereference"),
]

# Padrões pré-compilados (compilar é o passo caro; feito uma vez na carga do módulo).
REGRAS_CWE = [(re.compile(rx, re.IGNORECASE), cid, nome) for (rx, cid, nome) in _REGRAS_BRUTAS]

# Retorno quando o log não casa nenhuma classe conhecida (ex.: erro de compilação).
SEM_CWE = ("-", "-")


def classificar_cwe(log):
    """
    Devolve (cwe_id, cwe_nome) a partir do relatório da ferramenta, ou ('-', '-').
    Percorre as regras em ordem e retorna o CWE da primeira cujo padrão aparece no log.
    """
    if not log:
        return SEM_CWE
    for rx, cid, nome in REGRAS_CWE:
        if rx.search(log):
            return (cid, nome)
    return SEM_CWE


# Nome técnico do erro (tipo_erro) derivado do CWE — também determinístico, evitando
# pedir esse rótulo ao LLM (seria redundante com o CWE, que já sai da ferramenta).
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
    Como classificar_cwe, mas devolve também o nome técnico (tipo_erro), tudo determinístico.
    Retorna (cwe_id, cwe_nome, tipo_erro); sem assinatura conhecida, ("-", "-", "-").
    """
    cwe_id, cwe_nome = classificar_cwe(log)
    return cwe_id, cwe_nome, _TIPO_POR_CWE.get(cwe_id, "-")
