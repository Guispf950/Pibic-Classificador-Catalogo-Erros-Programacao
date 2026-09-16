"""
Regras de detecção de SEÇÃO do relatório do ASan/Valgrind.

Concentra num único lugar o "contrato" com o texto que o ASan e o Valgrind imprimem. O
extrator de anotação inline (llm_client._extrair_pontos_anotacao) percorre o log e usa estas
regras para saber a que seção cada linha pertence — e qual PAPEL atribuir às linhas de código
que vierem em seguida:

    SINTOMA   -> onde o erro se manifesta (o acesso/uso que dispara a falha)
    CAUSA     -> onde o erro nasce (o free do bloco, ou a criação do valor não inicializado)
    VAZAMENTO -> a alocação cuja memória nunca é liberada (leaks)
    ORIGEM    -> onde o bloco foi alocado (extra, não anotada por padrão)

Cada regra é uma tupla (papel, rótulo, padrão_regex), avaliada em ORDEM DE PRIORIDADE (a
primeira cujo regex casar vence). O padrão é ancorado ao formato REAL das ferramentas.
Para ajustar uma classe (ex.: mudança de texto numa versão nova do Valgrind), edita-se apenas
a linha correspondente em REGRAS_SECAO — nada mais no pipeline muda.
"""

import re


# (papel, rótulo, padrão regex do cabeçalho da seção) — em ordem de prioridade.
_REGRAS_BRUTAS = [
    # ── SINTOMA (onde o erro se manifesta) ──
    ("SINTOMA", "uso de memória já liberada (heap-use-after-free)",
        r"heap-use-after-free"),
    ("SINTOMA", "acesso fora dos limites do bloco (buffer overflow)",
        r"(?:heap|stack|global)-buffer-overflow"),
    ("SINTOMA", "uso de variável local após o retorno da função (use-after-return)",
        r"stack-use-after-return"),
    ("SINTOMA", "uso de variável local após sair do escopo (use-after-scope)",
        r"use-after-scope"),
    ("SINTOMA", "liberação inválida de memória (double-free / free inválido)",
        r"attempting (?:double-)?free|double-free|Invalid free|Mismatched free"),
    ("SINTOMA", "acesso a endereço inválido (segmentation fault)",
        r"\bSEGV\b|Segmentation fault"),
    ("SINTOMA", "uso de valor NÃO INICIALIZADO nesta expressão",
        r"Conditional jump or move depends on uninitialised"),
    ("SINTOMA", "uso de valor NÃO INICIALIZADO aqui",
        r"Use of uninitialised value"),
    ("SINTOMA", "leitura inválida de memória (Invalid read)",
        r"Invalid read of size"),
    ("SINTOMA", "escrita inválida de memória (Invalid write)",
        r"Invalid write of size"),
    # ── CAUSA (onde o erro nasce) ──
    ("CAUSA", "o bloco de memória foi LIBERADO (free) aqui — depois disso o ponteiro ficou inválido",
        r"freed by thread|block of size \d+ .*free'd"),
    ("CAUSA", "o valor NÃO INICIALIZADO nasce neste ponto (variável local sem valor definido)",
        r"[Uu]ninitialised value was created"),
    # ── VAZAMENTO (leak: só a alocação) ──
    ("VAZAMENTO", "memória alocada aqui NUNCA é liberada (vazamento de memória)",
        r"blocks are (?:definitely|indirectly) lost"),
    # ── ORIGEM (alocação; extra, não anotada por padrão) ──
    ("ORIGEM", "o bloco envolvido foi alocado aqui",
        r"previously allocated by|Block was alloc'd"),
]

# Versão consumida pelo extrator, com padrões já compilados. Importar SEMPRE esta.
REGRAS_SECAO = [(papel, rotulo, re.compile(rx, re.IGNORECASE))
                for (papel, rotulo, rx) in _REGRAS_BRUTAS]
