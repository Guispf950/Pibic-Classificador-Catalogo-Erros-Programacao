"""
Classificação do erro para CWE (Common Weakness Enumeration, do MITRE) — a lista do MITRE
que cataloga fraquezas conhecidas de software.

Mapeia, de forma DETERMINÍSTICA, o erro reportado pela ferramenta (ASan/Valgrind/GDB) para o
CWE correspondente, por regex sobre o relatório — nunca por consulta ao LLM.
Assim mantém-se a essência determinística do pipeline, e o CWE serve também de checagem de
consistência contra o diagnóstico.

A classificação tem duas camadas, avaliadas numa ÚNICA sequência de prioridade (_PASSOS):
  1. Regras simples: o NOME do erro no relatório decide o CWE (ex.: "double-free" -> CWE-415).
  2. Refinamentos: leem DETALHES do relatório além do nome:
     - acesso fora dos limites de um vetor: LEITURA x ESCRITA ("READ/WRITE of size N") e
       ANTES do início x DEPOIS do fim -> CWE-121/122/124/126/127/787. O lado vem, nesta
       ordem: da frase do heap/global ("to the left/right of", "before/after"); da fronteira
       de variável da pilha mais próxima do acesso; do texto "underflows/overflows this
       variable"; do byte marcado no mapa de memória-sombra (alloca/VLA); do nome do erro;
     - segmentation fault: o ENDEREÇO da falha (impresso pelo GDB a partir de $_siginfo, ver
       malha1_asan.py) separa ponteiro nulo, recursão sem fim, escrita em memória só-leitura
       e ponteiro com lixo -> CWE-476/674/758/824;
     - cópia com origem e destino sobrepostos: se o tamanho copiado passa do espaço do
       destino, o erro real é estouro (121/122/787) e a sobreposição é só efeito colateral;
     - relatório do UBSan (malha_ubsan.py): índice fora do vetor, estouro de inteiro com sinal,
       deslocamento de bits inválido etc. -> CWE-129/190/191/1335/369/476/758.

Os textos procurados foram conferidos no ambiente do sandbox (GCC 11.4, GDB 12.1,
Valgrind 3.18.1). Versões novas do ASan trocaram "to the left/right of" por "before/after";
as regras aceitam as duas formas.

Fundamentação: catálogo CWE do MITRE (cwe.mitre.org) e o Juliet Test Suite / NIST SARD,
benchmark de falhas em C/C++ rotulado por CWE.
"""

import re


# Nome oficial (MITRE) de cada CWE que o pipeline pode devolver.
_NOME = {
    "CWE-121": "Stack-based Buffer Overflow",
    "CWE-122": "Heap-based Buffer Overflow",
    "CWE-124": "Buffer Underwrite ('Buffer Underflow')",
    "CWE-125": "Out-of-bounds Read",
    "CWE-126": "Buffer Over-read",
    "CWE-127": "Buffer Under-read",
    "CWE-129": "Improper Validation of Array Index",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-191": "Integer Underflow (Wrap or Wraparound)",
    "CWE-195": "Signed to Unsigned Conversion Error",
    "CWE-369": "Divide By Zero",
    "CWE-401": "Missing Release of Memory after Effective Lifetime",
    "CWE-415": "Double Free",
    "CWE-416": "Use After Free",
    "CWE-457": "Use of Uninitialized Variable",
    "CWE-475": "Undefined Behavior for Input to API",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-562": "Return of Stack Variable Address",
    "CWE-590": "Free of Memory not on the Heap",
    "CWE-674": "Uncontrolled Recursion",
    "CWE-758": "Reliance on Undefined, Unspecified, or Implementation-Defined Behavior",
    "CWE-762": "Mismatched Memory Management Routines",
    "CWE-787": "Out-of-bounds Write",
    "CWE-789": "Memory Allocation with Excessive Size Value",
    "CWE-824": "Access of Uninitialized Pointer",
    "CWE-825": "Expired Pointer Dereference",
    "CWE-1335": "Incorrect Bitwise Shift of Integer",
}

# Retorno quando o log não casa nenhuma classe conhecida (ex.: erro de compilação).
SEM_CWE = ("-", "-")


# ── Limiares do refinamento do segmentation fault ─────────────────────────────
# Endereços abaixo de 4 KiB (a "página zero") são ponteiro NULL, puro ou somado a um
# deslocamento pequeno de campo/índice (ex.: p->v[10] com p == NULL falha em 0x2c).
LIMITE_PAGINA_ZERO = 0x1000
# Recursão sem fim esgota a pilha: a falha acontece colada ao topo da pilha (medido: 8 bytes
# abaixo do stack pointer). 64 KiB de folga cobre funções com variáveis locais grandes.
JANELA_PILHA = 64 * 1024
# si_code do SIGSEGV no Linux: 1 = endereço não mapeado; 2 = página existe mas sem permissão
# (típico de escrever numa string literal, que fica em memória só-leitura).
SEGV_ACCERR = 2
# 128 = SI_KERNEL: o processador recusou o endereço por ser "não canônico" (lixo absurdo, como
# 0x973b24f271683000) e o kernel informa addr=0. Sem este caso, um ponteiro com lixo seria
# confundido com NULL (medido na submissao_5303358.c).
SI_KERNEL = 128


# ══════════════════════════════════════════════════════════════════════════════
# 1. REGRAS SIMPLES: o nome do erro decide o CWE
# ══════════════════════════════════════════════════════════════════════════════
_RX_DOUBLE_FREE    = re.compile(r"attempting double-free|\bdouble-free\b", re.I)
_RX_FREE_FORA_HEAP = re.compile(r"attempting free on address which was not malloc", re.I)
_RX_MISMATCHED     = re.compile(r"Mismatched free", re.I)
_RX_INVALID_FREE   = re.compile(r"Invalid free", re.I)      # genérico do Valgrind
# Uso de memória já liberada (ASan: "heap-use-after-free"; Valgrind: "Address 0x... is 0 bytes
# inside a block of size 40 free'd"). Exige "block of size N free'd": um "free'd" solto também
# aparece em "Address 0x0 is not stack'd, malloc'd or (recently) free'd" (ponteiro NULL ou com
# lixo no Valgrind), que antes era rotulado, errado, como use-after-free.
_RX_USE_AFTER_FREE = re.compile(r"heap-use-after-free|block of size \d+ free'd", re.I)
# Uso de variável local após o fim de vida dela.
_RX_AFTER_RETURN   = re.compile(r"stack-use-after-return", re.I)
_RX_AFTER_SCOPE    = re.compile(r"use-after-scope", re.I)
# Recursão sem fim reportada diretamente pela ferramenta (fora do GDB).
_RX_RECURSAO       = re.compile(r"AddressSanitizer: stack-overflow|Stack overflow in thread", re.I)
# Pedido de alocação absurdo (ex.: malloc(n) com n lido errado / lixo).
_RX_ALOCACAO_ABSURDA = re.compile(r"allocation-size-too-big|requested allocation size", re.I)
# Cópia entre áreas de memória sobrepostas (strcpy(s, s+1), memcpy com overlap).
_RX_SOBREPOSICAO   = re.compile(r"-param-overlap|Source and destination overlap", re.I)
# Tamanho negativo passado a memcpy/memset (int negativo virando size_t gigante).
_RX_TAMANHO_NEGATIVO = re.compile(r"negative-size-param", re.I)
# O cálculo do tamanho da alocação estourou (count * size não cabe em size_t).
_RX_CALCULO_TAMANHO = re.compile(
    r"calloc-overflow|calloc parameters overflow|reallocarray-overflow|reallocarray parameters overflow",
    re.I)
# Uso de valor não inicializado (incl. passado ao sistema: "Syscall param write(buf) points
# to uninitialised byte(s)", que aparece ao imprimir um vetor nunca preenchido).
_RX_NAO_INICIALIZADO = re.compile(
    r"depends on uninitialised|Use of uninitialised value|uninitialised byte|uninitialized-value", re.I)
# Vazamento: só a linha de REGISTRO de perda ("N bytes in M blocks are definitely lost in
# loss record ..."). O resumo "definitely lost: 0 bytes in 0 blocks" NÃO pode casar — antes
# casava e rotulava vazamento em programas sem vazamento. "possibly lost" também é vazamento
# (ponteiro só para o meio do bloco) e o Valgrind já o conta como erro por padrão.
_RX_VAZAMENTO      = re.compile(r"blocks are (?:definitely|indirectly|possibly) lost", re.I)
# Estouro na pilha pego pelo PROTETOR DE PILHA do gcc (não pelo ASan): ao sair da função, o valor
# "sentinela" ao lado das variáveis locais foi sobrescrito -> "*** stack smashing detected ***".
# Acontece quando a escrita passa por uma função que o ASan não intercepta (ex.: wcscpy no GCC 11
# do sandbox — Juliet CWE121 ..._src_wchar_t_alloca_cpy_31). A linha apontada é o FIM da função
# (onde a sentinela é conferida), não a linha da cópia.
_RX_STACK_SMASHING = re.compile(r"stack smashing detected", re.I)
# Divisão por zero: GDB ("SIGFPE, Arithmetic exception"), ASan ("FPE on unknown address")
# e Valgrind ("Integer divide by zero" / "signal 8 (SIGFPE)").
_RX_DIVISAO_ZERO   = re.compile(
    r"received signal SIGFPE|\bFPE on unknown address|signal 8 \(SIGFPE\)|Integer divide by zero"
    r"|Arithmetic exception", re.I)


def _regra(rx, cwe_id):
    """Passo simples: devolve cwe_id se o padrão aparece no log, senão None."""
    return lambda log: cwe_id if rx.search(log) else None


# ══════════════════════════════════════════════════════════════════════════════
# 2. REFINAMENTO: acesso fora dos limites de um vetor
# ══════════════════════════════════════════════════════════════════════════════
# Nome do erro no ASan: região (heap/pilha/global/VLA) + overflow (depois do fim) ou
# underflow (antes do início). O ASan só usa "underflow" para variáveis de PILHA; no heap e no
# global o lado vem numa linha à parte.
_RX_ESTOURO_ASAN = re.compile(r"\b(heap|stack|global|dynamic-stack)-buffer-(overflow|underflow)\b", re.I)
_RX_ACESSO       = re.compile(r"\b(READ|WRITE) of size \d+")
# Heap e global: "0x... is located 4 bytes to the left of 40-byte region" (ASan antigo, o do
# sandbox) ou "... 4 bytes before ..." (ASan novo).
_RX_LADO_ASAN    = re.compile(r"is located \d+ bytes (?:to the )?(left|right|before|after)\b", re.I)
# Pilha: o ASan lista as variáveis da função ("[48, 148) 'dest'") e o deslocamento do acesso
# ("Memory access at offset 148"). O texto "underflows/overflows this variable" é relativo a
# UMA variável e pode apontar a vizinha errada: lendo `dest` além do fim, o ASan escreveu
# "partially underflows" da variável seguinte (Juliet CWE126 ..._CWE170_char_loop_01). Por isso
# o lado é decidido pela fronteira de variável MAIS PRÓXIMA do acesso; o texto fica de reserva.
_RX_VAR_PILHA    = re.compile(r"\[(\d+), (\d+)\) '[^']*'")
_RX_OFFSET_PILHA = re.compile(r"Memory access at offset (\d+)")
_RX_LADO_PILHA   = re.compile(r"\b(underflows|overflows) this variable", re.I)
# Vetor de tamanho dinâmico na pilha (alloca/VLA): o ASan não escreve o lado, mas marca no mapa
# de memória-sombra o byte onde o acesso caiu: "=>0x...: ca ca ca[ca]00 00 ...". Zonas
# proibidas: ca = à esquerda do alloca, cb = à direita; f1 = à esquerda da pilha, f3 = à direita.
_RX_BYTE_SOMBRA  = re.compile(r"^=>0x[0-9a-fA-F]+:[^\[\n]*\[([0-9a-fA-F]{2})\]", re.M)
_SOMBRA_ANTES    = {"ca", "f1"}
_SOMBRA_DEPOIS   = {"cb", "f3"}
# Valgrind (só vê o heap): "Address 0x... is 4 bytes before a block of size 40 alloc'd".
_RX_LADO_VALGRIND = re.compile(r"is \d+ bytes (before|after) a block of size \d+ alloc'd", re.I)
_RX_INVALIDO_VALGRIND = re.compile(r"Invalid (read|write) of size \d+", re.I)
# Valgrind, endereço fora de qualquer bloco: "Address 0x0 is not stack'd, malloc'd or (recently) free'd".
_RX_ENDERECO_SOLTO = re.compile(r"Address (0x[0-9a-fA-F]+) is not stack'd, malloc'd or \(recently\) free'd")


def _cwe_por_limites(regiao, acesso, lado):
    """
    Combina leitura/escrita com antes/depois:
        ESCRITA antes do início -> CWE-124 (Buffer Underwrite)
        LEITURA antes do início -> CWE-127 (Buffer Under-read)
        LEITURA depois do fim   -> CWE-126 (Buffer Over-read)
        ESCRITA depois do fim   -> pela região: heap 122, pilha 121, global 787
    Sem a informação de acesso (não deveria acontecer), mantém o CWE da região.
    """
    if acesso == "WRITE" and lado == "antes":
        return "CWE-124"
    if acesso == "READ" and lado == "antes":
        return "CWE-127"
    if acesso == "READ":
        return "CWE-126"
    return {"heap": "CWE-122", "stack": "CWE-121", "dynamic-stack": "CWE-121"}.get(regiao, "CWE-787")


def _lado_pela_pilha(log):
    """'antes'/'depois' pela fronteira de variável mais próxima do acesso; None se não der."""
    m = _RX_OFFSET_PILHA.search(log)
    if not m:
        return None
    deslocamento = int(m.group(1))
    melhor = None                                   # (distância, lado)
    for inicio, fim in ((int(a), int(b)) for a, b in _RX_VAR_PILHA.findall(log)):
        if deslocamento >= fim:
            candidato = (deslocamento - fim, "depois")
        elif deslocamento < inicio:
            candidato = (inicio - deslocamento, "antes")
        else:
            continue                                # começa dentro da variável: sem pista aqui
        if melhor is None or candidato[0] < melhor[0]:
            melhor = candidato
    return melhor[1] if melhor else None


def _classificar_estouro_asan(log):
    m = _RX_ESTOURO_ASAN.search(log)
    if not m:
        return None
    regiao, tipo = m.group(1).lower(), m.group(2).lower()
    acesso = _RX_ACESSO.search(log)
    acesso = acesso.group(1) if acesso else None
    lado = _RX_LADO_ASAN.search(log)
    sombra = _RX_BYTE_SOMBRA.search(log)
    sombra = sombra.group(1).lower() if sombra else ""
    if lado:
        lado = "antes" if lado.group(1).lower() in ("left", "before") else "depois"
    elif regiao == "dynamic-stack" and sombra in (_SOMBRA_ANTES | _SOMBRA_DEPOIS):
        # alloca/VLA nunca aparece na lista de variáveis do quadro; se o acesso acontece em OUTRA
        # função (o ponteiro foi passado adiante), o ASan descreve o endereço pelo quadro dessa
        # outra função e a "variável mais próxima" é de outro vetor. Medido no Juliet CWE124
        # ..._char_alloca_loop_45 (escrita ANTES do alloca saía 121). O byte de sombra é a pista certa.
        lado = "antes" if sombra in _SOMBRA_ANTES else "depois"
    elif _lado_pela_pilha(log):
        lado = _lado_pela_pilha(log)
    else:
        lado = _RX_LADO_PILHA.search(log)
        if lado:
            lado = "antes" if lado.group(1).lower() == "underflows" else "depois"
        else:
            if sombra in _SOMBRA_ANTES:
                lado = "antes"
            elif sombra in _SOMBRA_DEPOIS:
                lado = "depois"
            else:
                # Sem nenhuma pista de posição: o próprio nome do erro diz o lado.
                lado = "antes" if tipo == "underflow" else "depois"
    return _cwe_por_limites(regiao, acesso, lado)


def _classificar_invalido_valgrind(log):
    m = _RX_INVALIDO_VALGRIND.search(log)
    if not m:
        return None
    acesso = "READ" if m.group(1).lower() == "read" else "WRITE"
    resto = log[m.end():]                    # as linhas "Address ..." vêm logo depois do erro
    bloco = _RX_LADO_VALGRIND.search(resto)
    if bloco:
        lado = "antes" if bloco.group(1).lower() == "before" else "depois"
        return _cwe_por_limites("heap", acesso, lado)
    solto = _RX_ENDERECO_SOLTO.search(resto)
    if solto:
        return "CWE-476" if int(solto.group(1), 16) < LIMITE_PAGINA_ZERO else "CWE-824"
    # Sem detalhe de posição: classificação genérica pela direção do acesso.
    return "CWE-787" if acesso == "WRITE" else "CWE-125"


# ══════════════════════════════════════════════════════════════════════════════
# 3. REFINAMENTO: segmentation fault
# ══════════════════════════════════════════════════════════════════════════════
# Sob o GDB o sinal chega ao GDB ANTES do ASan, então o relatório do ASan não aparece; a
# Malha 1 pede ao GDB uma linha própria com o endereço da falha, o código do sinal e o topo
# da pilha: "PIPELINE_SIGINFO addr=0x2c code=1 sp=0x7fffffffebd0" (NULL aparece como "(nil)").
_RX_SEGFAULT = re.compile(
    r"received signal SIGSEGV|\bSEGV on unknown address|signal 11 \(SIGSEGV\)|Segmentation fault"
    r"|null pointer", re.I)
_RX_SIGINFO = re.compile(r"PIPELINE_SIGINFO addr=(\(nil\)|0x[0-9a-fA-F]+) code=(-?\d+) sp=(\(nil\)|0x[0-9a-fA-F]+)")
_RX_FAIXA_VALGRIND = re.compile(
    r"(Access not within mapped region|Bad permissions for mapped region) at address (0x[0-9a-fA-F]+)")
_RX_SEGV_ASAN = re.compile(r"SEGV on unknown address (0x[0-9a-fA-F]+)")


def _endereco(texto):
    return 0 if texto == "(nil)" else int(texto, 16)


def _classificar_segfault(log):
    if not _RX_SEGFAULT.search(log):
        return None

    info = _RX_SIGINFO.search(log)
    if info:
        endereco, codigo, topo = _endereco(info.group(1)), int(info.group(2)), _endereco(info.group(3))
        if topo and abs(endereco - topo) <= JANELA_PILHA:
            return "CWE-674"        # falha colada ao topo da pilha: recursão sem fim
        if codigo == SI_KERNEL:
            return "CWE-824"        # endereço não canônico: ponteiro com lixo (kernel diz addr=0)
        if endereco < LIMITE_PAGINA_ZERO:
            return "CWE-476"        # ponteiro NULL (puro ou + deslocamento pequeno)
        if codigo == SEGV_ACCERR:
            return "CWE-758"        # escrita em memória só-leitura (ex.: string literal)
        return "CWE-824"            # endereço não nulo e não mapeado: ponteiro com lixo

    faixa = _RX_FAIXA_VALGRIND.search(log)
    if faixa:
        if _endereco(faixa.group(2)) < LIMITE_PAGINA_ZERO:
            return "CWE-476"
        return "CWE-758" if faixa.group(1).startswith("Bad permissions") else "CWE-824"

    asan = _RX_SEGV_ASAN.search(log)
    if asan:
        return "CWE-476" if _endereco(asan.group(1)) < LIMITE_PAGINA_ZERO else "CWE-824"

    # Sem nenhum endereço no log: mantém o comportamento anterior (deref de NULL, o caso mais
    # comum em código de iniciante).
    return "CWE-476"


# ══════════════════════════════════════════════════════════════════════════════
# 4. REFINAMENTO: cópia com origem e destino sobrepostos
# ══════════════════════════════════════════════════════════════════════════════
# Ex. (Juliet CWE121 ..._CWE805_char_declare_ncpy_10): strncpy de 99 bytes num `char dest[50]`.
# A cópia passa do fim de dest e invade a variável vizinha, que é justamente a ORIGEM — o ASan
# checa a sobreposição primeiro e reporta "strncpy-param-overlap". O erro real é o estouro.
# Regra: o 1º intervalo do relatório é o DESTINO ([início, fim) = bytes que seriam escritos);
# se esse tamanho passa do espaço que o destino tem a partir do início, é estouro de escrita
# (121 pilha / 122 heap / 787 global); senão, é sobreposição de verdade (CWE-475).
_RX_INTERVALOS_SOBREPOSTOS = re.compile(
    r"-param-overlap: memory ranges \[(0x[0-9a-fA-F]+),\s*(0x[0-9a-fA-F]+)\)")
# Pilha: "Address 0x7ffd... is located in stack of thread T0 at offset 48 in frame", seguido da
# lista de variáveis da função ("[48, 98) 'dataBadBuffer'").
_RX_ENDERECO_PILHA = re.compile(
    r"Address (0x[0-9a-fA-F]+) is located in stack of thread \w+ at offset (\d+) in frame")
# Heap: "0x50e000000040 is located 0 bytes inside of 150-byte region [...]".
_RX_DENTRO_HEAP = re.compile(r"(0x[0-9a-fA-F]+) is located (\d+) bytes inside of (\d+)-byte region")
# Global: "... of global variable 'gdst' defined in 'x.c:4:6' (0x5c9c2178e1a0) of size 50".
_RX_GLOBAL = re.compile(r"global variable '[^']*' defined in '[^']*' \((0x[0-9a-fA-F]+)\) of size (\d+)")


def _espaco_do_destino(log, inicio):
    """(região, bytes disponíveis a partir de `inicio`) do destino da cópia; None se o log não diz."""
    for m in _RX_ENDERECO_PILHA.finditer(log):
        if int(m.group(1), 16) != inicio:
            continue
        deslocamento = int(m.group(2))
        for a, b in _RX_VAR_PILHA.findall(log[m.end():]):
            if int(a) <= deslocamento < int(b):
                return "stack", int(b) - deslocamento
        return None
    for m in _RX_DENTRO_HEAP.finditer(log):
        if int(m.group(1), 16) == inicio:
            return "heap", int(m.group(3)) - int(m.group(2))
    g = _RX_GLOBAL.search(log)
    if g:
        base, tamanho = int(g.group(1), 16), int(g.group(2))
        if base <= inicio < base + tamanho:
            return "global", base + tamanho - inicio
    return None


def _classificar_sobreposicao(log):
    if not _RX_SOBREPOSICAO.search(log):
        return None
    m = _RX_INTERVALOS_SOBREPOSTOS.search(log)      # Valgrind não dá os intervalos: fica 475
    if m:
        inicio, fim = int(m.group(1), 16), int(m.group(2), 16)
        destino = _espaco_do_destino(log, inicio)
        if destino and (fim - inicio) > destino[1]:
            return _cwe_por_limites(destino[0], "WRITE", "depois")
    return "CWE-475"


# ══════════════════════════════════════════════════════════════════════════════
# 5. RELATÓRIO DO UBSAN (malha_ubsan.py)
# ══════════════════════════════════════════════════════════════════════════════
# Formato: "arquivo.c:5:31: runtime error: <descrição>". Conferido no sandbox (GCC 11.4).
_RX_UBSAN = re.compile(r"runtime error: (.*)")
# "signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'". A DIREÇÃO
# (para cima = 190, para baixo = 191) sai da própria conta, refeita com inteiros do Python
# (sem limite): resultado verdadeiro negativo = passou do MENOR valor do tipo.
_RX_UB_ESTOURO = re.compile(r"signed integer overflow: (-?\d+) ([-+*]) (-?\d+) cannot be represented")
_RX_UB_NEGACAO = re.compile(r"negation of -?\d+ cannot be represented")
_RX_UB_DIV_MIN = re.compile(r"division of -?\d+ by -1 cannot be represented")   # INT_MIN / -1
_RX_UB_INDICE = re.compile(
    r"index -?\d+ out of bounds for type|variable length array bound evaluates to non-positive")
_RX_UB_SHIFT = re.compile(r"shift exponent|shift of negative value|left shift of")
_RX_UB_DIV_ZERO = re.compile(r"division by zero")
_RX_UB_NULO = re.compile(r"null pointer")


def _classificar_ubsan(log):
    m = _RX_UBSAN.search(log)
    if not m:
        return None
    msg = m.group(1)
    conta = _RX_UB_ESTOURO.search(msg)
    if conta:
        a, op, b = int(conta.group(1)), conta.group(2), int(conta.group(3))
        verdadeiro = a + b if op == "+" else a - b if op == "-" else a * b
        return "CWE-191" if verdadeiro < 0 else "CWE-190"
    if _RX_UB_NEGACAO.search(msg) or _RX_UB_DIV_MIN.search(msg):
        return "CWE-190"            # o resultado (positivo) não cabe no tipo
    if _RX_UB_INDICE.search(msg):
        return "CWE-129"            # índice/tamanho de vetor não validado
    if _RX_UB_SHIFT.search(msg):
        return "CWE-1335"
    if _RX_UB_DIV_ZERO.search(msg):
        return "CWE-369"
    if _RX_UB_NULO.search(msg):
        return "CWE-476"
    # Demais comportamentos indefinidos que o UBSan aponta (ex.: endereço desalinhado, valor
    # inválido para bool/enum): o próprio CWE genérico de comportamento indefinido.
    return "CWE-758"


# ══════════════════════════════════════════════════════════════════════════════
# SEQUÊNCIA DE PRIORIDADE — o primeiro passo que reconhece o log vence.
# ══════════════════════════════════════════════════════════════════════════════
# A ordem desambigua erros que compartilham marcadores no log (ex.: double-free e
# use-after-free ambos citam "free'd"; as regras de liberação vêm antes por isso). Os erros
# nomeados explicitamente pela ferramenta vêm antes dos sinais genéricos (SIGFPE/SIGSEGV).
_PASSOS = [
    # Liberação indevida (antes do use-after-free, que também cita "free'd")
    _regra(_RX_DOUBLE_FREE, "CWE-415"),
    _regra(_RX_FREE_FORA_HEAP, "CWE-590"),
    _regra(_RX_MISMATCHED, "CWE-762"),
    _regra(_RX_INVALID_FREE, "CWE-415"),
    # Uso de memória já liberada / variável local fora do tempo de vida
    _regra(_RX_USE_AFTER_FREE, "CWE-416"),
    _regra(_RX_AFTER_RETURN, "CWE-562"),
    _regra(_RX_AFTER_SCOPE, "CWE-825"),
    # Acesso fora dos limites (ASan): leitura/escrita x antes/depois
    _classificar_estouro_asan,
    # Outros erros nomeados pelo ASan
    _regra(_RX_RECURSAO, "CWE-674"),
    _regra(_RX_ALOCACAO_ABSURDA, "CWE-789"),
    _classificar_sobreposicao,
    _regra(_RX_TAMANHO_NEGATIVO, "CWE-195"),
    _regra(_RX_CALCULO_TAMANHO, "CWE-190"),
    # UBSan (o log da malha UBSan só tem o relatório dele)
    _classificar_ubsan,
    # Valgrind
    _regra(_RX_NAO_INICIALIZADO, "CWE-457"),
    _regra(_RX_VAZAMENTO, "CWE-401"),
    _classificar_invalido_valgrind,
    # Crash por sinal (o GDB pega antes do ASan)
    _regra(_RX_STACK_SMASHING, "CWE-121"),
    _regra(_RX_DIVISAO_ZERO, "CWE-369"),
    _classificar_segfault,
]


def classificar_cwe(log):
    """
    Devolve (cwe_id, cwe_nome) a partir do relatório da ferramenta, ou ('-', '-').
    Percorre os passos em ordem e retorna o CWE do primeiro que reconhece o log.
    """
    if not log:
        return SEM_CWE
    for passo in _PASSOS:
        cwe_id = passo(log)
        if cwe_id:
            return (cwe_id, _NOME[cwe_id])
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
    "CWE-124": "buffer-underwrite",
    "CWE-126": "buffer-over-read",
    "CWE-127": "buffer-under-read",
    "CWE-125": "out-of-bounds-read",
    "CWE-457": "uninitialized-value",
    "CWE-401": "memory-leak",
    "CWE-476": "null-pointer-dereference",
    "CWE-824": "invalid-pointer-dereference",
    "CWE-758": "write-to-read-only-memory",
    "CWE-674": "uncontrolled-recursion",
    "CWE-369": "division-by-zero",
    "CWE-789": "excessive-allocation-size",
    "CWE-475": "overlapping-memory-copy",
    "CWE-195": "negative-size-argument",
    "CWE-190": "integer-overflow",
    "CWE-191": "integer-underflow",
    "CWE-129": "array-index-out-of-bounds",
    "CWE-1335": "invalid-bit-shift",
}


def classificar_cwe_tipo(log):
    """
    Como classificar_cwe, mas devolve também o nome técnico (tipo_erro), tudo determinístico.
    Retorna (cwe_id, cwe_nome, tipo_erro); sem assinatura conhecida, ("-", "-", "-").
    """
    cwe_id, cwe_nome = classificar_cwe(log)
    return cwe_id, cwe_nome, _TIPO_POR_CWE.get(cwe_id, "-")
