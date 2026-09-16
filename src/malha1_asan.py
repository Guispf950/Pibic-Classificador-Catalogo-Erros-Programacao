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


def executar_malha_1_asan(caminho_codigo, binario_saida="./bin_asan", entrada=None):
    """
    Compila com AddressSanitizer e executa via GDB para capturar erros de acesso
    inválido (buffer overflow, use-after-free, stack overflow).
    Retorna dict com 'erro' e 'log' se algo for detectado, ou None se limpo.
    Memory leaks são delegados à Malha 2 (Valgrind+vgdb).
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
         "-g", caminho_codigo, "-o", binario_saida],
        capture_output=True,
        text=True
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
    env["ASAN_OPTIONS"] = "abort_on_error=1:detect_leaks=0"

    # --- FASE 3: EXECUÇÃO VIA GDB (ANÁLISE POST-MORTEM) ---
    comando_gdb = [
        "gdb", "-q",        # modo silencioso
        "--batch",          # roda os comandos e sai
        "-ex", "run",       # inicia a execução
        "-ex", "bt full",   # backtrace completo com variáveis locais de cada frame
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
        text=True,
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

    # Nenhum erro de acesso nem crash: passa para a Malha 2 (Valgrind).
    return None
