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

## FORMATO DO FEEDBACK PARA ESTE TIPO DE ERRO
O feedback para CWE-401 segue sempre a mesma **estrutura de 4 movimentos** — a *forma* é fixa; o *conteúdo* é preenchido com a **variável e a linha reais** (a alocação que vazou). Objetivo: levar o aluno a rastrear o **tempo de vida** do bloco e a descobrir **em qual caminho** ele deixa de ser liberado, sem entregar a correção. (Diferente de um erro de acesso, o vazamento não tem "linha do sintoma": a âncora é a **linha da alocação**.)

1. **Situar (o quê + onde).** Cite a **linha da alocação** e a variável reais: "o bloco reservado na linha `<linha_vazamento>` (por `<variável> = malloc(...)`) nunca é devolvido antes de o programa/a função terminar; o último ponteiro para ele se perde".

2. **Conceito (o que aconteceu).** Em uma frase: um vazamento é reservar memória e **não devolvê-la** com `free`, deixando-a ocupada e inacessível até o fim. (Sem dizer a correção; pode notar que não altera a saída, mas ainda é um erro.)

3. **Investigar a causa (por quê).** Conduza o aluno a rastrear o **ciclo de vida** do bloco, apresentando **origens concretas** como **possibilidades a verificar** (nunca como afirmação): um **caminho de saída** (`return` normal ou de erro) que passa **sem** liberar; ao destruir uma lista/árvore, **nós internos** que não são percorridos e liberados (vazamento indireto); um ponteiro **sobrescrito** que perde a única referência ao bloco **antes** do `free`; ou a **ausência de uma rotina** que percorra e libere toda a estrutura. Evite frases circulares como "faltou dar free" — aponte **onde**, no fluxo, a liberação some.

4. **Pergunta socrática final.** Termine com uma pergunta **aberta**, citando a variável/linha reais. Prefira a forma "quem, no seu código, fica **responsável por devolver** o bloco de `<variável>` (linha `<linha>`), e em **quais caminhos** essa devolução pode não acontecer?" em vez de "onde você adiciona o `free`?" (esta última já dita o conserto).

**Regras invariantes deste molde:**
- Não revelar a solução: não escrever a liberação (ex.: `free(x)`) nem dizer o local exato onde inseri-la.
- Sempre citar a variável e a linha reais da alocação (nunca genérico).
- 3 a 5 frases, linguagem simples, sem código e sem listas; terminar com a pergunta do movimento 4.

**Exemplo de tom (caso hipotético — não copiar nomes/linhas):**
- *Ruim (entrega a resposta):* "Adicione `free(no)` no fim da função `destruir`."
- *Bom (leva a pensar):* "Cada nó da sua árvore é reservado na linha 14 (`no = malloc(...)`), mas, quando o programa termina, nada percorre a árvore devolvendo esses blocos — então o último ponteiro para cada nó interno se perde. Quem, no seu fluxo, fica encarregado de liberar cada nó antes do fim, e em que momento isso deveria acontecer?"

## Nota do professor / convenção do curso (opcional)
<!-- Preenchido pelo professor quando houver algo específico do curso. -->

## Referência
- MITRE CWE-401: https://cwe.mitre.org/data/definitions/401.html
