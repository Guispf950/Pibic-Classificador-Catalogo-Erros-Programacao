"""
Malha 1 — AddressSanitizer + GDB.

Detecta infrações espaciais de memória (buffer overflow, use-after-free,
stack-buffer-overflow, etc.) compilando com -fsanitize=address e executando
o binário sob o GDB para capturar o estado exato no momento da falha.

Memory leaks são intencionalmente delegados à Malha 2 (Valgrind+vgdb).
"""

import os
import subprocess

from src.deteccao_entrada import stdin_para_analise


def executar_malha_1_asan(caminho_codigo, binario_saida="./bin_asan"):
    """
    Compila com AddressSanitizer e executa via GDB para capturar erros de acesso
    inválido (buffer overflow, use-after-free, stack overflow).
    Retorna um dict com 'erro' e 'log' se algo for detectado, ou None se limpo.

    NOTA: Memory leaks são intencionalmente delegados à Malha 2 (Valgrind+vgdb).
    """

    # --- FASE 1: COMPILAÇÃO COM ASAN ---
    # -fsanitize=address injeta "redzones" (zonas de guarda) ao redor das variáveis
    # na memória. Qualquer acesso fora dos limites faz o programa abortar imediatamente.
    # -g preserva os símbolos de depuração (nomes de variáveis, números de linha)
    # para que o GDB consiga gerar um backtrace legível depois.
    compilacao = subprocess.run(
        ["gcc", "-fsanitize=address", "-g", caminho_codigo, "-o", binario_saida],
        capture_output=True,  # captura stdout e stderr sem exibir no terminal
        text=True             # decodifica a saída como string (não bytes)
    )

    # Se o código não compilou, não há nada a executar — retorna o erro do compilador
    if compilacao.returncode != 0:
        return {"erro": "Erro de compilação", "log": compilacao.stderr}

    # --- FASE 2: CONFIGURAÇÃO DO AMBIENTE ---
    # Copia as variáveis de ambiente do processo atual para não perder PATH, HOME etc.
    env = os.environ.copy()

    # abort_on_error=1: força o ASan a chamar abort() no primeiro erro de acesso
    # detectado, permitindo que o GDB congele o processo e capture o estado exato
    # da memória (backtrace + variáveis locais) no momento da falha.
    #
    # detect_leaks=0: desabilita o LeakSanitizer (LSan) intencionalmente.
    # Isso não é uma limitação — é uma decisão arquitetural do pipeline:
    #
    #   1. INCOMPATIBILIDADE TÉCNICA: O LSan usa ptrace para rastrear o heap.
    #      O GDB também usa ptrace para depurar o processo. Dois usuários de ptrace
    #      no mesmo processo causam conflito, então o LSan se autodesabilita
    #      ao detectar que está sendo executado dentro de um debugger.
    #      Mesmo que rodasse, o log seria poluído com alocações internas do GDB,
    #      gerando falsos positivos.
    #
    #   2. QUALIDADE DO DIAGNÓSTICO: O LSan reporta apenas o stack trace do malloc,
    #      sem acesso ao estado das variáveis no momento do leak. O Valgrind+vgdb
    #      (Malha 2) resolve isso: o vgdb permite pausar o processo no ponto exato
    #      do leak e inspecionar variáveis com o GDB, gerando um log muito mais
    #      rico para a IA classificar.
    #
    #     Conclusão: memory leaks são delegados ao Valgrind (Malha 2) por duas razões:
    #
    # (1) o Valgrind+Memcheck detecta vazamentos no heap com cobertura total,
    #     incluindo leaks indiretos (ex: nós internos de lista encadeada) que o LSan
    #     frequentemente classifica apenas como "still reachable" sem detalhar a cadeia;
    #
    # (2) o vgdb permite pausar o processo no momento exato do leak e inspecionar
    #     variáveis com o GDB, gerando um log muito mais rico para a IA do que o
    #     stack trace simples que o LSan produziria — mesmo que ele rodasse sem o GDB.
    #
    # O ponto fraco do Valgrind é a stack (erros de acesso imediatos como buffer
    # overflow), que é exatamente o que o ASan+GDB cobre na Malha 1.

    env["ASAN_OPTIONS"] = "abort_on_error=1:detect_leaks=0"

    # --- FASE 3: EXECUÇÃO VIA GDB (ANÁLISE POST-MORTEM) ---
    # O GDB executa o binário compilado com ASan. Se o ASan detectar um erro,
    # o processo aborta e o GDB captura automaticamente o estado naquele instante.
    comando_gdb = [
        "gdb", "-q",        # -q: modo silencioso (sem banner de versão)
        "--batch",          # --batch: roda os comandos abaixo e sai automaticamente
        "-ex", "run",       # inicia a execução do programa dentro do GDB
        "-ex", "bt full",   # se o programa parou (abort), imprime o backtrace completo
                            # com variáveis locais de cada frame da pilha
        "-ex", "quit",      # encerra o GDB ao final
        binario_saida       # caminho do executável a ser depurado
    ]

    # Detecta se o código lê N pelo stdin e gera entrada mínima automaticamente.
    # Sem isso, programas com scanf bloqueiam esperando input do terminal.
    stdin_analise = stdin_para_analise(caminho_codigo)

    # Executa o GDB passando o ambiente com ASAN_OPTIONS configurado.
    # O GDB em modo --batch repassa o `input` para o processo inferior (o binário do aluno).
    execucao = subprocess.run(
        comando_gdb,
        env=env,
        capture_output=True,
        text=True,
        input=stdin_analise,   # None = sem input automático; string = injetado via pipe
        timeout=60             # segurança: não pode travar indefinidamente
    )

    # Junta stdout e stderr porque o GDB e o ASan podem escrever em canais diferentes
    saida_completa = execucao.stdout + execucao.stderr

    # --- FASE 4: ANÁLISE DO RESULTADO ---
    # Verifica apenas erros de acesso inválido (Stack e Heap) — leaks são tratados pela Malha 2.
    # "ERROR: AddressSanitizer" cobre: buffer overflow, use-after-free,
    # stack-buffer-overflow, global-buffer-overflow, use-after-return, etc.
    if "ERROR: AddressSanitizer" in saida_completa:
        return {"erro": "Detectado pelo ASan", "log": saida_completa}

    # Nenhum erro de acesso encontrado: passa para a Malha 2 (Valgrind)
    return None
