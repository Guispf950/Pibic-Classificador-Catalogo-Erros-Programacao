# CWE-401 — Vazamento de Memória (Missing Release of Memory)

## O que é
Acontece quando o programa aloca memória (ex.: com `malloc`) e **nunca a libera**,
perdendo a referência para aquele bloco. A memória fica reservada, ocupada e inacessível
até o programa terminar — é a memória "vazando".

## Por que acontece em C
C **não tem coletor de lixo**: toda memória alocada dinamicamente precisa ser liberada
manualmente com `free()`. Se o programa perde o último ponteiro para um bloco (por
sobrescrevê-lo, sair de escopo, ou simplesmente esquecer de liberar), aquele bloco não
pode mais ser devolvido. Em iniciantes, é comum em estruturas encadeadas (listas,
árvores) que são construídas mas nunca desalocadas antes do fim do programa.

## Como interpretar o que a ferramenta apontou
Um detalhe importante: o vazamento **não altera a saída** do programa — por isso ele
passa despercebido por um juiz que só compara a saída. A ferramenta aponta a **alocação**
que ficou órfã (onde a memória nasceu). Não há um "sintoma" de uso indevido aqui; o
problema é a **ausência** da liberação correspondente.

## Princípio da correção (sem código)
A regra de ouro é simetria: **para cada alocação, deve existir uma liberação**
correspondente em todos os caminhos de saída (inclusive nos de erro). Em estruturas
compostas (uma árvore, uma lista), isso significa percorrer e liberar cada elemento antes
de encerrar. Pensar no "tempo de vida" de cada bloco — quando nasce e quando deve morrer —
é o que evita o vazamento.

## Nota do professor / convenção do curso (opcional)
<!-- Preenchido pelo professor quando houver algo específico do curso. -->

## Referência
- MITRE CWE-401: https://cwe.mitre.org/data/definitions/401.html
