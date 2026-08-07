"""
Malha 1 — AddressSanitizer + GDB.

Detecta infrações espaciais de memória (buffer overflow, use-after-free,
stack-buffer-overflow, etc.) compilando com -fsanitize=address e executando
o binário sob o GDB para capturar o estado exato no momento da falha.

Memory leaks são intencionalmente delegados à Malha 2 (Valgrind+vgdb).
"""

import os
import re
import subprocess

from src.deteccao_entrada import stdin_para_analise


# Sinais fatais que o GDB pode interceptar ANTES de o ASan imprimir seu relatório.
# Um crash "cru" (ex.: deref de ponteiro nulo -> SIGSEGV) é entregue ao GDB como um
# sinal do SO; sob `gdb --batch`, o GDB para o processo no ponto da falha e o handler
# do ASan não chega a rodar. Logo, a string "ERROR: AddressSanitizer" NÃO aparece e o
# erro escaparia da detecção se olhássemos só por ela. Por isso também reconhecemos os
# sinais reportados pelo GDB. (SIGABRT entra aqui porque é o que o ASan usa ao abortar,
# cobrindo o caso raro em que o relatório do ASan não é capturado por buffering.)
_SINAIS_FATAIS = ("SIGSEGV", "SIGABRT", "SIGFPE", "SIGBUS", "SIGILL", "SIGSYS", "SIGTRAP")


def executar_malha_1_asan(caminho_codigo, binario_saida="./bin_asan"):
    """
    Compila com AddressSanitizer e executa via GDB para capturar erros de acesso
    inválido (buffer overflow, use-after-free, stack overflow).
    Retorna um dict com 'erro' e 'log' se algo for detectado, ou None se limpo.

    NOTA: Memory leaks são delegados à Malha 2 (Valgrind+vgdb).
    """

    # --- FASE 1: COMPILAÇÃO COM ASAN ---
    # -fsanitize=address injeta "redzones" (zonas de guarda) ao redor das variáveis
    # na memória. Qualquer acesso fora dos limites faz o programa abortar imediatamente.
    # -g preserva os símbolos de depuração (nomes de variáveis, números de linha)
    # para que o GDB consiga gerar um backtrace legível depois.
    # -std=gnu11: fixa o padrão da linguagem para casar com o ambiente do CodeBench.
    # Sem isso, o GCC usa o default da versão instalada localmente (GCC recente => C23),
    # no qual `false`, `true` e `bool` viraram PALAVRAS-CHAVE. Códigos legados que fazem
    # `typedef enum { false, true } bool;` (válido em C99/C11/C17) passam a quebrar na
    # compilação, gerando FALSOS POSITIVOS que não ocorrem no juiz. gnu11 reproduz o
    # comportamento esperado do CodeBench e ainda mantém as extensões GNU usuais.
    # Flags adicionais para melhorar a IDENTIFICAÇÃO DA ORIGEM (causa raiz):
    #   -fsanitize-address-use-after-scope: detecta o uso de uma variável local
    #       DEPOIS de ela sair de escopo (ex.: retornar o endereço de algo dentro de
    #       um bloco { } que já fechou). Sem essa flag, esse erro passa despercebido.
    #   -fno-omit-frame-pointer: preserva o "frame pointer" em cada função, o que dá
    #       backtraces mais fiéis (linha/função corretas) — essencial para apontar com
    #       precisão tanto o SINTOMA quanto a ORIGEM do erro.
    compilacao = subprocess.run(
        ["gcc", "-std=gnu11",
         "-fsanitize=address",
         "-fsanitize-address-use-after-scope",   # novo: erros de uso fora de escopo
         "-fno-omit-frame-pointer",               # novo: backtraces mais precisos
         "-g", caminho_codigo, "-o", binario_saida],
        capture_output=True,  # captura stdout e stderr sem exibir no terminal
        text=True             # decodifica a saída como string (não bytes)
    )

    # Se o código não compilou, não há nada a executar — retorna o erro do compilador.
    # tipo="compilacao" permite ao orquestrador tratar isto como uma CATEGORIA PRÓPRIA
    # (não é erro de memória, nem foi o ASan/GDB que o encontrou, e sim o gcc).
    if compilacao.returncode != 0:
        return {
            "tipo": "compilacao",
            "erro": "Erro de compilação",
            "log": compilacao.stderr,
        }

    # --- FASE 2: CONFIGURAÇÃO DO AMBIENTE ---
    # Copia as variáveis de ambiente do processo atual para não perder PATH, HOME etc.
    env = os.environ.copy()

    # abort_on_error=1: força o ASan a chamar abort() no primeiro erro de acesso
    # detectado, permitindo que o GDB congele o processo e capture o estado exato
    # da memória (backtrace + variáveis locais) no momento da falha.
    #
    # detect_leaks=0: desabilita o LeakSanitizer (LSan) intencionalmente.
    # Isso  é uma decisão de arquitetura do pipeline:
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
        input=stdin_analise,   # Usa o caso de teste fornecido pelo codebench. Se: None = sem input automático; string = injetado via pipe (ex: "5\n1 2 3 4 5\n")
        timeout=60             # segurança: não pode travar indefinidamente
    )

    # Junta stdout e stderr porque o GDB e o ASan podem escrever em canais diferentes
    saida_completa = execucao.stdout + execucao.stderr

    # --- FASE 4: ANÁLISE DO RESULTADO ---
    #
    # (A) RELATÓRIO DO ASAN.
    # "ERROR: AddressSanitizer" cobre os erros que o ASan consegue interceptar e
    # RELATAR antes de abortar: buffer overflow, use-after-free, stack/global overflow,
    # use-after-return, etc. Nesses casos o relatório do ASan (com linha e função) já
    # está na saída — é o log mais rico possível. Leaks ficam de fora (detect_leaks=0).
    if "ERROR: AddressSanitizer" in saida_completa:
        return {
            "tipo": "asan",
            "erro": "Detectado pelo ASan",
            "log": saida_completa,
        }

    # (B) CRASH POR SINAL CAPTURADO PELO GDB.
    # Quando o programa sofre um crash "cru" (ex.: deref de ponteiro nulo -> SIGSEGV),
    # o SINAL chega primeiro ao GDB, que para o processo no ponto da falha. Nesse fluxo
    # o handler do ASan NÃO roda, então "ERROR: AddressSanitizer" fica ausente e o teste
    # (A) falha — foi exatamente o que fez crashes escaparem para a Malha 2 e saírem como
    # "indeterminado". Aqui recuperamos esse caso lendo a linha que o GDB imprime:
    #     "Program received signal SIGSEGV, Segmentation fault."
    # O `bt full` que pedimos ao GDB já deixou o backtrace (com arquivo:linha e função)
    # na mesma saída, então o log continua rico o suficiente para a IA classificar.
    match_sinal = re.search(r"signal\s+(SIG[A-Z]+)", saida_completa)
    if match_sinal and match_sinal.group(1) in _SINAIS_FATAIS:
        sinal = match_sinal.group(1)
        return {
            "tipo": "crash",
            "erro": f"Crash por {sinal} capturado via GDB",
            "sinal": sinal,
            "log": saida_completa,
        }

    # Nenhum erro de acesso nem crash encontrado: passa para a Malha 2 (Valgrind)
    return None
