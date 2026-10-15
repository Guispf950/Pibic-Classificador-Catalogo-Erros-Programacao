"""
Malha 1 — AddressSanitizer + GDB.

Detecta infrações espaciais de memória (buffer overflow, use-after-free,
stack-buffer-overflow, etc.) compilando com -fsanitize=address e executando
o binário sob o GDB para capturar o estado exato no momento da falha.

Memory leaks são delegados à Malha 2 (Valgrind+vgdb).
"""

import os
import re
import subprocess

from src.deteccao_entrada import stdin_para_analise


# Sinais fatais interceptáveis pelo GDB ANTES de o ASan imprimir seu relatório.
# Um crash "cru" (ex.: deref de ponteiro nulo -> SIGSEGV) chega ao GDB como sinal do SO;
# sob `gdb --batch` o processo para no ponto da falha e o handler do ASan não roda, então
# "ERROR: AddressSanitizer" NÃO aparece. Reconhecer os sinais evita que esses casos escapem.
# (SIGABRT entra aqui por ser o que o ASan usa ao abortar.)
_SINAIS_FATAIS = ("SIGSEGV", "SIGABRT", "SIGFPE", "SIGBUS", "SIGILL", "SIGSYS", "SIGTRAP")

# Profundidade máxima do backtrace (só os frames mais internos). Numa recursão sem fim o
# "bt full" sem limite despejava ~100 mil frames (8 MB de log, 30 s — medido no sandbox),
# estourando o tempo e inundando o prompt do LLM. Num erro normal são ~11 frames (ASan
# incluso), então 50 não corta nada útil.
MAX_FRAMES_BT = 50

# Como o sinal chega ao GDB antes do ASan, num segmentation fault o log só diria "SIGSEGV",
# sem dizer ONDE na memória foi a falha. Esta linha pede ao GDB o endereço da falha, o código
# do sinal (1 = endereço não mapeado, 2 = sem permissão) e o topo da pilha. O cwe.py usa os
# três para separar ponteiro nulo (endereço ~0), recursão sem fim (falha colada ao topo da
# pilha), escrita em string literal (código 2) e ponteiro com lixo (o resto).
COMANDO_SIGINFO = (
    'printf "PIPELINE_SIGINFO addr=%p code=%d sp=%p\\n", '
    '$_siginfo._sifields._sigfault.si_addr, $_siginfo.si_code, $sp'
)


def executar_malha_1_asan(caminho_codigo, binario_saida="./bin_asan", entrada=None, flags_extra=None,
                           limite_alocacao_mb=None):
    """
    Compila com AddressSanitizer e executa via GDB para capturar erros de acesso
    inválido (buffer overflow, use-after-free, stack overflow).
    Retorna dict com 'erro' e 'log' se algo for detectado, ou None se limpo.
    Memory leaks são delegados à Malha 2 (Valgrind+vgdb).

    `flags_extra`: lista opcional de argumentos extra do gcc, inseridos entre o arquivo-fonte e
    o `-o` (ex.: `-I`/caminho de include, defines como `-DINCLUDEMAIN`, ou um .c adicional para
    linkar). Usado só pelo harness de validação contra o Juliet (`avaliar_juliet.py`), que
    precisa compilar junto com `testcasesupport/io.c`; submissão de aluno (arquivo único, sem
    dependências externas) nunca passa isso, então o comportamento de produção não muda.

    `limite_alocacao_mb`: teto opcional (em MB) para o ASan rejeitar `malloc`/`calloc` de
    propósito (CWE-789, "Memory Allocation with Excessive Size Value"). Sem isso, o ASan só
    recusa pedidos ACIMA de ~1 TB por padrão — bem mais do que um `int` de 32 bits consegue
    expressar (no máximo umas dezenas de GB), então pedidos "absurdos" nos testes nunca cruzam
    esse teto: o ASan tenta alocar de verdade, o que é lento. Com `limite_alocacao_mb` definido,
    qualquer pedido acima do teto vira erro IMEDIATO ("requested allocation size ... exceeds
    maximum supported size"), independente de quanta RAM a máquina/sandbox tem. Também usado só
    pelo harness do Juliet — não passado pela chamada de produção.
    """

    # --- FASE 1: COMPILAÇÃO COM ASAN ---
    # -fsanitize=address injeta redzones ao redor das variáveis; acesso fora dos limites aborta.
    # -g preserva símbolos de depuração para o GDB gerar backtrace legível.
    # -std=gnu11: fixa o padrão para casar com o CodeBench. Sem isso, um GCC recente usa C23,
    #   onde `false`/`true`/`bool` viraram palavras-chave, quebrando códigos legados que fazem
    #   `typedef enum { false, true } bool;` e gerando falsos positivos ausentes no juiz.
    # -fsanitize-address-use-after-scope: detecta uso de variável local após sair de escopo.
    # -fno-omit-frame-pointer: backtraces mais fiéis (linha/função corretas), útil para
    #   apontar com precisão tanto o sintoma quanto a origem do erro.
    compilacao = subprocess.run(
        ["gcc", "-std=gnu11",
         "-fsanitize=address",
         "-fsanitize-address-use-after-scope",
         "-fno-omit-frame-pointer",
         "-g", caminho_codigo, *(flags_extra or []), "-o", binario_saida],
        capture_output=True,
        text=True, errors="replace"
    )

    # Falha de compilação: nada a executar. tipo="compilacao" marca uma categoria própria
    # (não é erro de memória nem foi o ASan/GDB que encontrou, e sim o gcc).
    if compilacao.returncode != 0:
        return {
            "tipo": "compilacao",
            "erro": "Erro de compilação",
            "log": compilacao.stderr,
        }

    # --- FASE 2: CONFIGURAÇÃO DO AMBIENTE ---
    env = os.environ.copy()

    # abort_on_error=1: ASan chama abort() no 1º erro, permitindo ao GDB congelar o processo
    #   e capturar o estado exato (backtrace + variáveis locais).
    # detect_leaks=0: desativa o LeakSanitizer de propósito. O LSan usa ptrace, assim como o
    #   GDB — dois usuários de ptrace no mesmo processo conflitam, e o LSan se autodesabilita
    #   sob debugger. Leaks ficam com a Malha 2 (Valgrind+vgdb), que cobre leaks indiretos
    #   (ex.: nós internos de lista) e permite pausar no ponto do leak e inspecionar variáveis,
    #   gerando log mais rico do que o stack trace simples do LSan.
    # (detect_stack_use_after_return NÃO entra aqui — ver FASE 5.)
    env["ASAN_OPTIONS"] = "abort_on_error=1:detect_leaks=0"
    if limite_alocacao_mb:
        # allocator_may_return_null=0 (padrão): ao exceder o teto, o ASan ABORTA e GERA o
        # relatório de erro, em vez de só devolver NULL silenciosamente — é o relatório que o
        # cwe.py espera para reconhecer CWE-789.
        env["ASAN_OPTIONS"] += f":max_allocation_size_mb={int(limite_alocacao_mb)}:allocator_may_return_null=0"

    # --- FASE 3: EXECUÇÃO VIA GDB (ANÁLISE POST-MORTEM) ---
    comando_gdb = [
        "gdb", "-q",        # modo silencioso
        "--batch",          # roda os comandos e sai
        "-ex", "run",       # inicia a execução
        "-ex", f"bt full {MAX_FRAMES_BT}",  # backtrace com variáveis locais (frames mais internos)
        "-ex", COMANDO_SIGINFO,             # endereço da falha (ver COMANDO_SIGINFO)
        "-ex", "quit",
        binario_saida
    ]

    # ENTRADA: se `entrada` foi fornecida (ex.: caso de teste do CodeBench via API), é
    # AUTORITATIVA — usada como veio (mesmo string vazia). Só com `entrada is None` (uso
    # offline) recorre-se à detecção por .in/heurística.
    if entrada is not None:
        stdin_analise = entrada
    else:
        stdin_analise = stdin_para_analise(caminho_codigo)

    execucao = subprocess.run(
        comando_gdb,
        env=env,
        capture_output=True,
        # errors="replace": o programa do aluno pode imprimir bytes que não são texto válido
        # (ex.: um vetor de char nunca preenchido). Sem isso a leitura da saída quebrava com
        # UnicodeDecodeError e a análise inteira caía como "erro interno" (medido).
        text=True, errors="replace",
        input=stdin_analise,   # None = sem input; string = injetado via pipe (ex.: "5\n1 2 3 4 5\n")
        timeout=60             # segurança contra travamento indefinido
    )

    # GDB e ASan podem escrever em canais diferentes; junta os dois.
    saida_completa = execucao.stdout + execucao.stderr

    # --- FASE 4: ANÁLISE DO RESULTADO ---
    # (A) Relatório do ASan: cobre os erros interceptados e relatados antes de abortar
    #     (buffer overflow, use-after-free, stack/global overflow, use-after-return). Aqui o
    #     log já traz linha e função — o mais rico possível. Leaks ficam de fora (detect_leaks=0).
    if "ERROR: AddressSanitizer" in saida_completa:
        return {
            "tipo": "asan",
            "erro": "Detectado pelo ASan",
            "log": saida_completa,
        }

    # (B) Crash por sinal capturado pelo GDB: num crash cru (ex.: deref de NULL -> SIGSEGV) o
    #     sinal chega primeiro ao GDB, o handler do ASan não roda e o teste (A) falha. Recupera-se
    #     o caso lendo a linha "Program received signal SIGSEGV, ...". O `bt full` já deixou o
    #     backtrace (arquivo:linha e função) na mesma saída, então o log segue rico o bastante.
    match_sinal = re.search(r"signal\s+(SIG[A-Z]+)", saida_completa)
    if match_sinal and match_sinal.group(1) in _SINAIS_FATAIS:
        sinal = match_sinal.group(1)
        return {
            "tipo": "crash",
            "erro": f"Crash por {sinal} capturado via GDB",
            "sinal": sinal,
            "log": saida_completa,
        }

    # --- FASE 5: 2ª PASSADA, SÓ PARA USE-AFTER-RETURN (CWE-562) ---
    # Usar o endereço de uma variável local depois que a função retornou só é detectado com
    # detect_stack_use_after_return=1, que no ASan do GCC 11 (o do sandbox) vem DESLIGADA: sem
    # ela, o programa de teste com esse erro terminou "normalmente" (medido).
    # Ela NÃO é ligada na passada principal porque muda o comportamento de programas com
    # variável local não inicializada: as variáveis passam a morar numa pilha auxiliar zerada,
    # o "lixo" vira 0 e o programa pode seguir outro caminho. Medido na submissao_5303358.c:
    # desligada, o programa sempre cai em altura() (linha 68, ponteiro com lixo), como cairia
    # no CodeBench, que roda sem ASan; ligada, cai em removeNo() (linha 46, ponteiro nulo) — um
    # erro DIFERENTE do que reprovou o aluno. Por isso ela roda só quando a passada principal
    # saiu limpa, e dela aproveita-se APENAS o relatório de use-after-return: qualquer outro
    # sintoma nessa passada pode ser efeito da pilha zerada e é descartado.
    env_uar = dict(env, ASAN_OPTIONS=env["ASAN_OPTIONS"] + ":detect_stack_use_after_return=1")
    execucao_uar = subprocess.run(
        comando_gdb, env=env_uar, capture_output=True, text=True, errors="replace",
        input=stdin_analise, timeout=60,
    )
    saida_uar = execucao_uar.stdout + execucao_uar.stderr
    if "AddressSanitizer: stack-use-after-return" in saida_uar:
        return {
            "tipo": "asan",
            "erro": "Detectado pelo ASan (use-after-return, 2ª passada)",
            "log": saida_uar,
        }

    # Nenhum erro de acesso nem crash: passa para a Malha 2 (Valgrind).
    return None
