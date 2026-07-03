# 1. O Fluxo de Execução Analítico (Pipeline Determinístico em Cascata)

A avaliação dinâmica de códigos submetidos a juízes online sofre com o fenômeno
dos *Heisenbugs* — defeitos de memória cujo comportamento se altera ou desaparece
quando o ambiente de execução é modificado pela observação, seja pela presença de
um depurador, seja por variações de execução para execução (GRAY, 1986;
SALLINGER; WEISSENBACHER; ZULEGER, 2023). Tentar reproduzir uma falha de ponteiro
reexecutando o programa repetidas vezes compromete a integridade do diagnóstico,
pois o resultado passa a depender de fontes de não-determinismo do sistema
operacional — como a aleatorização do espaço de endereços (ASLR) e o estado
transitório do *heap* — que, conforme formalizado por Sallinger, Weissenbacher e
Zuleger (2023), são justamente as causas que tornam esses defeitos elusivos.

Para mitigar esse problema, o orquestrador **não** adota reexecução reativa e sim uma
arquitetura de **Captura de Estado Inline** (*single-execution interception*): cada
ferramenta é instrumentada para congelar o processo no instante exato da falha e
extrair dali o estado forense, em uma única execução. O ecossistema é projetado
estritamente para a observabilidade de falhas de memória e de interrupções do
sistema operacional. A verificação de equivalência lógica pura (erros de semântica
algorítmica que não violam o estado da máquina) é arquiteturalmente delegada ao
módulo de Análise Estática da plataforma, garantindo a separação de
responsabilidades.

O fluxo dinâmico opera como uma **esteira em cascata**: cada malha só é acionada se a
anterior não encontrou defeitos, e a detecção em qualquer malha interrompe a
descida (política *fail-fast*), poupando recursos do servidor. As duas primeiras
malhas — ativas e determinísticas — cobrem a integridade da memória; a terceira, de
perfilamento de desempenho, é um **módulo exploratório mantido fora do pipeline de
produção** pelas razões discutidas ao final desta seção.

> **Nota sobre entrada automática.** Programas de juiz online tipicamente leem seus
> dados via `scanf`. Para que os subprocessos de análise (GDB e Valgrind) não fiquem
> bloqueados aguardando entrada do terminal, um módulo compartilhado
> (`deteccao_entrada`) inspeciona o código-fonte por análise léxica: se identifica um
> `scanf("%d", &var)` cujo valor governa um laço ou uma alocação (`for`, `while`,
> `malloc`, `calloc`, VLA), sintetiza uma entrada mínima (`"5\n1 2 3 4 5\n"`) injetada
> via *pipe*; caso contrário, o processo herda o *stdin* do ambiente. Trata-se de uma
> heurística deliberadamente conservadora, cujas limitações são registradas na Malha 3.

---

## Malha 1 — Filtro Espacial de Falha Rápida (AddressSanitizer + GDB pós-morte)

Esta é a primeira barreira do pipeline, e ela se preocupa com **uma única família de
defeitos**: o programa tocar em uma região de memória que não lhe pertence — escrever
além do fim de um vetor, ler uma posição que nunca foi alocada ou usar um bloco que já
foi liberado. São os chamados erros **espaciais**, porque o problema está em *onde* na
memória o programa pisou. É a classe de defeito mais comum e mais destrutiva em código
C de aluno iniciante.

**Como o código prepara o terreno.** O programa do estudante é compilado com
`gcc -fsanitize=address -g`. A opção `-fsanitize=address` pede ao compilador que
construa o binário já com um *sistema de alarme* embutido, o AddressSanitizer (ASan).
Na prática, ele faz duas coisas: cerca cada variável e cada alocação com **zonas de
guarda** (*redzones*) — como se pintasse uma faixa de bytes "proibidos" em volta de
cada objeto — e mantém um **mapa paralelo da memória** (memória-sombra) que registra
quais regiões são legítimas de acessar. Antes de cada leitura ou escrita, esse mapa é
consultado. Já o `-g` preserva os nomes originais das variáveis e os números de linha,
para que o relatório final fale na linguagem do aluno, e não em endereços de máquina.
O ASan é hoje o verificador de memória padrão de fato dessa classe, adotado por seu
baixo *overhead* e alta precisão (SEREBRYANY et al., 2012).

**Como a falha é capturada.** Em vez de rodar o binário sozinho, o código o lança sob
o controle do GNU Debugger em modo lote (`gdb -q --batch`) — um depurador guiado por um
roteiro pré-escrito, sem intervenção humana. A peça central é a variável de ambiente
`ASAN_OPTIONS=abort_on_error=1`. No instante em que o programa cruza uma zona de guarda,
o ASan percebe imediatamente (ele consulta o mapa **antes** de consumar o acesso) e, em
vez de deixar o programa seguir corrompido, "puxa o freio de emergência": chama
`abort()`, que dispara o sinal `SIGABRT`. Como o processo está rodando dentro do GDB,
esse freio não simplesmente encerra o programa — ele o **congela exatamente onde
parou**. Com o processo paralisado, o roteiro do GDB executa o `bt full`, que é a
*fotografia* do estado: ele percorre toda a pilha de chamadas (qual função chamou qual)
e, em cada nível, mostra o valor das variáveis locais naquele exato momento. É aí que o
estado culpado fica visível — por exemplo, uma variável de índice guardando o valor 15
enquanto tenta acessar um vetor de tamanho 10.

O log resultante é **híbrido**. Primeiro vem o alerta vermelho do ASan, que tipifica o
erro estrutural (ex.: `==...==ERROR: AddressSanitizer: stack-buffer-overflow ...`):

(FOTO DO LOG DE ERRO DO ASAN AQUI)

Em seguida, anexa-se a fotografia em texto plano gerada pelo GDB, revelando o estado
lógico que provocou a falha:

(FOTO DO BACKTRACE DO GDB AQUI)

Para decidir se houve falha, o código apenas verifica a presença da assinatura
`ERROR: AddressSanitizer` na saída combinada.

Duas decisões de projeto merecem explicação. A primeira: por que capturar **depois** do
disparo (pós-morte) e não com um ponto de parada antes? Porque o `abort()` não desfaz a
pilha de chamadas — ele apenas paralisa o processo —, de modo que o *frame* culpado
continua vivo e a fotografia reflete, na prática, o momento da violação. A segunda: a
opção `detect_leaks=0` desliga **de propósito** o caçador de vazamentos (*LeakSanitizer*).
O motivo é que ele e o GDB disputam o mesmo mecanismo do sistema operacional para
observar o processo (o `ptrace`) e entrariam em conflito; por isso os vazamentos são
deixados para a Malha 2, onde o Valgrind faz esse trabalho com cobertura mais rica
(inclusive vazamentos indiretos). Fiel à sua natureza *fail-fast*, assim que detecta a
falha o orquestrador aborta o processo para poupar o servidor e despacha o log bruto à
filtragem. Um `timeout` protege contra travamentos, e a entrada mínima automática
(descrita na nota da introdução) é injetada quando o programa lê dados via `scanf`.

---

## Malha 2 — Filtro Semântico Profundo (Valgrind Memcheck + vgdb)

Se o código sobreviveu à Malha 1, ele não pisou fora dos limites da memória. Mas existe
uma classe de defeito mais sutil que os alarmes da Malha 1 não pegam: o programa usar um
valor que **nunca recebeu um conteúdo válido** — uma variável declarada e lida antes de
qualquer atribuição, ou seja, o "lixo" que já estava naquele endereço — ou esquecer de
liberar memória que alocou (vazamento). São os erros **semânticos**, porque o problema
não está em *onde* o programa tocou (o endereço é legítimo), e sim no *significado* do
dado que ele encontrou ali.

**Como o código prepara o terreno.** O programa é recompilado apenas com `gcc -g`,
**sem** o ASan. A razão é concreta: o ASan e o Valgrind instalam, cada um, sua própria
contabilidade de memória-sombra, e as duas colidem se convivem no mesmo binário. Por
isso esta etapa usa um binário limpo e o entrega ao **Valgrind Memcheck**. A intuição do
que o Valgrind faz: em vez de rodar o programa direto no processador real, ele executa o
código dentro de um **processador simulado** (um emulador). Isso lhe permite observar
cada operação em câmera lenta e manter, para cada porção de memória, uma "etiqueta de
validade" (os *V-bits*) que diz se aquele conteúdo é legítimo ou ainda é lixo. Quando um
`if` tenta tomar uma decisão baseada em um valor-lixo, o Memcheck levanta o alerta
`Conditional jump or move depends on uninitialised value(s)`. Essa escolha se apoia na
consolidação do Valgrind como *framework* de instrumentação binária dinâmica de
referência (NETHERCOTE; SEWARD, 2007).

(FOTO DO ALERTA DO VALGRIND MEMCHECK AQUI)

**Como fotografar o estado sem desestabilizar a simulação.** Rodar um depurador comum
por cima de um emulador seria instável. O Valgrind resolve isso trazendo seu próprio
servidor de depuração, o **vgdb**. O código lança o Valgrind em segundo plano (via
`Popen`) com `--vgdb-error=1` (pausar na primeira anomalia) e `--leak-check=full` (ao
final, relatório detalhado de vazamentos), além de um socket exclusivo por análise
(`--vgdb-prefix` com um identificador UUID) para evitar colisões entre execuções
concorrentes. No ciclo exato em que o erro ocorre, o emulador "congela o tempo" e abre
uma porta de comunicação; o orquestrador conecta o GDB a essa porta
(`target remote | vgdb ...`) e envia o roteiro de extração (`info locals`, `bt full`).
Sem que o programa saia do lugar, o GDB consegue olhar para dentro da memória emulada e
tirar a fotografia do contexto — revelando qual variável guardava o lixo:

(FOTO DA CAPTURA DO GDB VIA VGDB AQUI)

**Como o código decide o veredito.** A checagem é dupla. Se o Valgrind interrompeu o
programa em uma falha crítica de execução, o GDB emite a ordem de terminação e a frase
`monitor command request to kill this process` aparece na saída — isso confirma o erro.
Se, em vez disso, o programa terminou sem falha crítica, o código lê o relatório final
do Valgrind (com `timeout` e um *fallback* de `kill` contra travamentos) e reconhece um
vazamento pela marcação `definitely lost` ou por um `ERROR SUMMARY` diferente de zero.
Capturado o estado contaminado, o depurador é desconectado e o processo emulado é
encerrado, liberando o servidor do alto custo do Valgrind (a emulação é lenta por
natureza). Também aqui a entrada mínima automática é injetada quando necessária.

---

## Malha 3 — Perfilamento Algorítmico Empírico (módulo exploratório, em *stand-by*)

A terceira etapa audita a **eficiência** do algoritmo, buscando inferir sua
complexidade assintótica (notação Big-O) a partir da execução real. Diferentemente das
Malhas 1 e 2, este módulo **não integra atualmente o pipeline determinístico de
produção**: ele foi implementado, versionado e mantido em *stand-by* para refinamento
futuro, pelas razões de escopo e maturidade detalhadas adiante. Só faria sentido
executá-lo após as malhas de memória, pois o comportamento assintótico de um código
com *Undefined Behavior* é tecnicamente indefinido.

### Como foi implementado

O perfilador opera em cinco blocos. Primeiro, um **detector de parâmetro de escala**
identifica, por análise léxica, se o código lê um inteiro *N* (`scanf` com um único
`%d`) que governa laços ou alocações — o *Cenário A*, escalável; caso contrário
(*Cenário B*, entrada fixa), o módulo retorna `N/A`. Segundo, um **gerador de
entradas** sintetiza casos de teste geometricamente escalonados, usando valores
crescentes (1..N) em vez de constantes, para não permitir que o preditor de desvios da
CPU distorça a medição.

**Terceiro — a coleta de métrica.** Esta etapa mede efetivamente o custo de cada
execução e opera em dois níveis: um preferencial (contagem de instruções por hardware)
e um alternativo (tempo de parede), acionado apenas quando o primeiro não está
disponível.

O nível preferencial lê os **Contadores de Performance de Hardware (HPC)** por meio do
comando `perf stat -e instructions:u`. Todo processador possui uma unidade interna — a
PMU (*Performance Monitoring Unit*) — com registradores que contam eventos de baixo
nível; o `perf` consulta esses registradores e devolve o número exato de instruções de
máquina executadas em espaço de usuário. Essa é a métrica ideal por ser
**determinística**: para uma mesma entrada, a contagem de instruções é sempre a mesma,
independentemente da carga do servidor, de modo que seu crescimento em função de *N*
reflete puramente o algoritmo.

O `perf`, contudo, **só funciona quando o ambiente expõe a PMU física e concede
permissão de acesso a ela** — na prática, em Linux nativo (*bare metal*), com o `perf`
instalado e com `/proc/sys/kernel/perf_event_paranoid` em nível permissivo (≤ 1) ou
execução como *root*. Em ambientes virtualizados essa condição raramente é satisfeita:
no **WSL** (ambiente de desenvolvimento deste trabalho), o *kernel* roda sobre o
hipervisor Hyper-V, que não repassa a PMU à máquina virtual; o mesmo ocorre em
contêineres, VMs e executores de CI/nuvem, e o utilitário sequer existe fora do Linux
(por exemplo, no macOS). Para não travar nesses casos, o módulo executa um **pré-teste**
(`perf stat -- true`, com *timeout* de 3 s e resultado em cache) que decide, uma única
vez por execução, se a métrica de hardware está de fato disponível.

Quando o pré-teste falha, entra o nível alternativo — o ***fallback* de tempo de
parede** (*wall-clock*). Em vez de contar instruções, o módulo cronometra a duração
real de cada execução com um relógio de alta resolução (`perf_counter_ns`) e repete a
medição cinco vezes, tomando a **mediana** para descartar valores atípicos causados
pelo escalonador do sistema operacional. Como o tempo de parede é sensível à carga da
máquina — uma medida ruidosa —, o módulo ainda **descarta amostras abaixo de um limiar
de ruído** (execuções tão rápidas que o custo de criar o processo supera o do próprio
algoritmo) e exige valores de *N* maiores para que o sinal do algoritmo emerja do
ruído. É uma aproximação adequada a um protótipo, porém menos confiável que a contagem
de instruções — razão pela qual, no ambiente WSL atual, em que o `perf` está sempre
indisponível, a Malha 3 opera integralmente sobre essa métrica alternativa.

Quarto, a **inferência**:
uma regressão por mínimos quadrados não-lineares (`scipy.optimize.curve_fit`, com o
eixo *Y* normalizado por estabilidade numérica) ajusta os pontos coletados a uma
família de modelos — O(1), O(log N), O(N), O(N log N), O(N²), O(N³), O(2ᴺ) —
selecionando o de maior coeficiente de determinação (R²) e reportando um nível de
confiança proporcional. Quinto, o **orquestrador da malha** compila sem otimizações
(`gcc -O0 -g`, para não mascarar a complexidade real) e escolhe a escala de *N*
conforme a métrica disponível.

### Fundamentação e posicionamento no estado da arte

É importante distinguir duas tradições de literatura que raramente se cruzam. **No
estado da arte de avaliação de complexidade em juízes online, a análise estática
domina.** O trabalho de referência é o de Sikka *et al.* (2020), que introduziu o
*dataset* CoRCoD — extraído de submissões de juízes online — e tratou a predição da
classe Big-O como tarefa de aprendizado de máquina sobre atributos estáticos (contagem
de laços, condicionais, recursão) e *embeddings* de código, **sem executar o
programa**. Trabalhos subsequentes, como Pfitscher *et al.* (2023), seguem a mesma
linha, refinando atributos e modelos, mas mantendo a natureza puramente estática. A
razão da predominância é pragmática: juízes online avaliam milhares de submissões e a
análise estática não carrega o custo de reexecutar o programa múltiplas vezes com
entradas crescentes.

**A inferência dinâmica de complexidade, por sua vez, provém de uma literatura
distinta** — a de *empirical algorithmics* e de *profiling* de desempenho. Goldsmith,
Aiken e Wilkerson (2007) formalizaram a medição da *complexidade computacional
empírica* com a ferramenta *trend-prof*, ajustando o número de execuções de blocos
básicos a funções do tamanho da carga de trabalho. Zaparanuks e Hauswirth (2012)
consolidaram a noção de *algorithmic profiling* — um perfilador que estima uma *função*
de custo em vez de um valor pontual —, e Coppa, Demetrescu e Finocchi (2014)
apresentaram o *input-sensitive profiling* (ferramenta *aprof*, construída sobre o
Valgrind), que estima empiricamente a curva de crescimento e o "Big-O" das rotinas em
função do tamanho de entrada. Essas contribuições, contudo, foram publicadas em
*venues* de sistemas e linguagens de programação (ESEC-FSE, PLDI, IEEE TSE), e **não**
em fóruns de educação em computação.

O módulo aqui implementado situa-se exatamente nessa lacuna: aplica uma técnica
consolidada na literatura de sistemas a um contexto educacional onde ela raramente
aparece. Isso configura, potencialmente, uma **contribuição metodológica de
transferência entre domínios**. O argumento pedagógico a favor da abordagem dinâmica é
que a medição empírica não exige que um modelo "compreenda" o código: ela observa o
comportamento real, o que tende a ser mais robusto para código de aluno iniciante com
estruturas não-canônicas (laços com lógica irregular, recursão com caso-base
incorreto) que podem enganar um classificador estático treinado em código de
competição.

É preciso registrar, entretanto, o limite teórico comum a todas as abordagens: pelo
problema da parada de Turing e pelo Teorema de Rice (RICE, 1953), é impossível uma
função universal que decida a complexidade de todo programa — ponto reconhecido
explicitamente pela própria literatura da área (PFITSCHER *et al.*, 2023). Toda
solução, estática ou dinâmica, é necessariamente uma **aproximação**.

### Limitações atuais e a decisão de manter o módulo fora do pipeline

O perfilador, no estado em que foi implementado, apresenta limitações que justificam
mantê-lo como componente exploratório e não como malha de produção:

- **Ambiente de medição.** A métrica determinística ideal (`perf stat`/HPC) é
  indisponível no ambiente de desenvolvimento (WSL sem acesso à PMU do hipervisor),
  forçando o *fallback* de tempo de parede — ruidoso, dependente da carga do servidor e
  exigente de *N* maior para superar o limiar de ruído.
- **Cobertura da entrada automática.** A detecção do parâmetro de escala é uma
  heurística léxica deliberadamente estrita: ela só reconhece a leitura
  `scanf("%d", &var)` com **um único** `%d` e, além disso, exige que `var` reapareça no
  código como limite de laço ou tamanho de alocação (`for`, `while`, `malloc`, `calloc`
  ou índice de vetor `[var]`). Qualquer desvio desse padrão faz o código recair no
  *Cenário B* e ser marcado como `N/A`, ainda que seja, na prática, escalável. Ficam de
  fora, por exemplo: leituras compostas (`scanf("%d %d", ...)`); formatos com espaços ou
  quebras de linha (`" %d"`, `"%d\n"`), que quebram a expressão regular; outros tipos e
  funções de leitura (`%ld`, `fscanf`, `fgets`+`atoi`, `cin >>` em C++); o valor de
  escala obtido por vias indiretas (lido de `argv` ou copiado para outra variável antes
  do laço); e exercícios com **mais de um** parâmetro de tamanho (por exemplo, *T* casos
  de teste, cada um com seu próprio *N*). Há ainda uma segunda fragilidade: mesmo quando
  o parâmetro é corretamente detectado, a entrada sintetizada assume o *layout* canônico
  do CodeBench (linha 1 com *N*, linha 2 com *N* inteiros); se o exercício espera outra
  estrutura — uma matriz *N*×*N*, *N* pares de valores, *N* palavras —, os dados gerados
  não casam com os `scanf` do programa, que pode bloquear, ler valores incorretos ou
  falhar. *Exemplo:* um exercício que começa com `scanf("%d %d", &n, &alvo);` e depois
  percorre um vetor de tamanho `n` é genuinamente escalável em `n`; porém, como a leitura
  tem dois `%d`, o detector a rejeita e o classifica como entrada fixa (*Cenário B*),
  deixando de perfilá-lo — apesar de ser um caso perfeitamente adequado à Malha 3.
- **Rigor estatístico.** A regressão usa poucos pontos e mediana de cinco medições
  (adequado a um protótipo, não a uma avaliação validada em larga escala); com dados
  escassos ou ruidosos, classes vizinhas (por exemplo, O(N) e O(N log N)) podem ser
  confundidas.
- **Sensibilidade à entrada.** O módulo mede o comportamento observado para as entradas
  *geradas*, sem garantia de exercitar o pior caso — problema que a literatura de
  *input-sensitive profiling* (COPPA; DEMETRESCU; FINOCCHI, 2014) trata de forma bem
  mais rigorosa do que uma sonda de protótipo.
- **Risco de escopo.** O núcleo do projeto é a análise forense de memória e a geração de
  *feedback* pedagógico; a inferência de complexidade é uma oportunidade adjacente. Ferramentas de instrumentação binária pesada (Callgrind, Massif) impõem *overhead* de 50× a 100× sobre o tempo nativo (NETHERCOTE; SEWARD, 2007), inviáveis em juízes de alta concorrência — e a alternativa leve (leitura de HPC) esbarra na indisponibilidade descrita acima. Incorporá-la prematuramente ao pipeline determinístico comprometeria a previsibilidade e o baixo *overhead* que são premissas do sistema.

Por essas razões, o módulo foi preservado em *stand-by*: seu valor científico como
transferência de técnica é reconhecido, mas sua integração ao pipeline depende de
maior maturidade de ambiente (acesso a HPC), de ampliação da cobertura de entrada e de
validação estatística — tudo isso configurando uma direção promissora de trabalho
futuro, sem desviar o foco atual do projeto.

---

## Referências

COPPA, Emilio; DEMETRESCU, Camil; FINOCCHI, Irene. Input-sensitive profiling.
**IEEE Transactions on Software Engineering**, [*s. l.*], v. 40, n. 12, p. 1185–1205,
2014. DOI: 10.1109/TSE.2014.2339825.

GOLDSMITH, Simon F.; AIKEN, Alex S.; WILKERSON, Daniel S. Measuring empirical
computational complexity. *In*: PROCEEDINGS OF THE 6TH JOINT MEETING OF THE EUROPEAN
SOFTWARE ENGINEERING CONFERENCE AND THE ACM SIGSOFT SYMPOSIUM ON THE FOUNDATIONS OF
SOFTWARE ENGINEERING (ESEC-FSE '07), 2007, Dubrovnik. **Proceedings** [...].
New York: ACM, 2007. p. 395–404. DOI: 10.1145/1287624.1287681.

GRAY, Jim. Why do computers stop and what can be done about it? *In*: SYMPOSIUM ON
RELIABILITY IN DISTRIBUTED SOFTWARE AND DATABASE SYSTEMS, 5., 1986, Los Angeles.
**Proceedings** [...]. Los Alamitos: IEEE Computer Society, 1986. p. 3–12.

NETHERCOTE, Nicholas; SEWARD, Julian. Valgrind: a framework for heavyweight dynamic
binary instrumentation. *In*: PROCEEDINGS OF THE 28TH ACM SIGPLAN CONFERENCE ON
PROGRAMMING LANGUAGE DESIGN AND IMPLEMENTATION (PLDI '07), 2007, San Diego.
**Proceedings** [...]. New York: ACM, 2007. p. 89–100. DOI: 10.1145/1250734.1250746.

PFITSCHER, Ricardo José *et al.* Estimating code running time complexity with machine
learning. *In*: NALDI, Murilo C.; BIANCHI, Reinaldo A. C. (ed.). **Intelligent
Systems**: 12th Brazilian Conference (BRACIS 2023), Belo Horizonte, Proceedings,
Part II. Cham: Springer, 2023. (Lecture Notes in Computer Science, v. 14196).
DOI: 10.1007/978-3-031-45389-2_27.

RICE, Henry Gordon. Classes of recursively enumerable sets and their decision
problems. **Transactions of the American Mathematical Society**, [*s. l.*], v. 74,
n. 2, p. 358–366, 1953. DOI: 10.1090/S0002-9947-1953-0053041-6.

SALLINGER, Sarah; WEISSENBACHER, Georg; ZULEGER, Florian. A formalization of
Heisenbugs and their causes. *In*: INTERNATIONAL CONFERENCE ON SOFTWARE ENGINEERING
AND FORMAL METHODS (SEFM 2023), 21., 2023, Eindhoven. **Proceedings** [...]. Cham:
Springer, 2023. (Lecture Notes in Computer Science, v. 14323). p. 282–300.
DOI: 10.1007/978-3-031-47115-5_16.

SEREBRYANY, Konstantin; BRUENING, Derek; POTAPENKO, Alexander; VYUKOV, Dmitry.
AddressSanitizer: a fast address sanity checker. *In*: PROCEEDINGS OF THE 2012 USENIX
ANNUAL TECHNICAL CONFERENCE (USENIX ATC '12), 2012, Boston. **Proceedings** [...].
Berkeley: USENIX Association, 2012. p. 309–318.

SIKKA, Jagriti; SATYA, Kushal; KUMAR, Yaman; UPPAL, Shagun; SHAH, Rajiv Ratn;
ZIMMERMANN, Roger. Learning based methods for code runtime complexity prediction.
*In*: JOSE, Joemon M. *et al.* (ed.). **Advances in Information Retrieval**: 42nd
European Conference on IR Research (ECIR 2020), Lisboa, Proceedings, Part I. Cham:
Springer, 2020. (Lecture Notes in Computer Science, v. 12035). p. 313–325.
DOI: 10.1007/978-3-030-45439-5_21.

ZAPARANUKS, Dmitrijs; HAUSWIRTH, Matthias. Algorithmic profiling. *In*: PROCEEDINGS OF
THE 33RD ACM SIGPLAN CONFERENCE ON PROGRAMMING LANGUAGE DESIGN AND IMPLEMENTATION
(PLDI '12), 2012, Beijing. **Proceedings** [...]. New York: ACM, 2012. p. 67–76.
DOI: 10.1145/2254064.2254074.

---

### Nota sobre confiabilidade das fontes

Todas as referências acima são **revisadas por pares** e publicadas em *venues*
consolidados: PLDI, ESEC-FSE e USENIX ATC (topo em sistemas/linguagens); *IEEE
Transactions on Software Engineering* (periódico de primeira linha); ECIR e SEFM
(conferências internacionais Springer/LNCS); e *Transactions of the American
Mathematical Society* (Rice, 1953, resultado teórico fundacional). O trabalho de
Pfitscher *et al.* (2023) foi publicado no BRACIS, conferência brasileira de sistemas
inteligentes com anais Springer/LNCS — *venue* regional respeitado, revisado por pares,
porém de alcance menor que os demais; é citado por documentar explicitamente a linha
estática predominante e o limite teórico (Turing/Rice) no contexto de juízes online.
Não foram utilizados *preprints* não revisados na fundamentação.
