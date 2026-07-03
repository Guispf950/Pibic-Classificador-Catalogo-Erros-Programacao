import os
import subprocess
import uuid
import time


def _stdin_para_analise(caminho_codigo):
    """
    Gera um stdin mínimo para exercitar o código durante análise de memória
    (Malha 1 e 2), evitando que o processo trave aguardando input do terminal.

    Lógica:
        Reutiliza a mesma heurística da Malha 3 (detectar_parametro_escala):
        se o código lê um inteiro N via scanf e usa como tamanho de array/laço,
        gera a string "5\\n1 2 3 4 5\\n" — suficiente para exercitar o algoritmo
        sem sobrecarregar a análise de memória.

        Se o código não tem parâmetro de escala (entrada fixa, ex: "some 3 números"),
        retorna None → o processo herda stdin do terminal normalmente
        (já que esses programas geralmente terminam rápido ou leem poucos valores).

    Por que N=5 e não N=100?
        Malha 1/2 testam CORREÇÃO de memória, não desempenho. N=5 é suficiente
        para exercitar malloc/free e detectar buffer overflow sem aumentar
        o tempo de análise do Valgrind.
    """
    try:
        from src.perfilador_desempenho import detectar_parametro_escala, gerar_entrada_para_n
        with open(caminho_codigo, 'r', encoding='utf-8', errors='replace') as f:
            codigo = f.read()
        if detectar_parametro_escala(codigo):
            return gerar_entrada_para_n(5)   # "5\n1 2 3 4 5\n"
    except Exception:
        pass
    return None  # sem stdin automático — herda do ambiente


def executar_malha_1_asan(caminho_codigo, binario_saida="./bin_asan"):
    """
    Malha 1: Compila com AddressSanitizer e executa via GDB para capturar
    erros de acesso inválido (buffer overflow, use-after-free, stack overflow).
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
    stdin_analise = _stdin_para_analise(caminho_codigo)

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



def executar_malha_2_valgrind(caminho_codigo, binario_saida="./bin_valgrind"):
    """
    Malha 2: Executa o programa sob monitoramento do Valgrind com conexão GDB via 
    vgdb para inspeção ao vivo. Detecta falhas de execução e vazamentos de memória.
    Retorna um dict com 'erro' e 'log' se algo for detectado, ou None se limpo.
    """

    # --- FASE 1: COMPILAÇÃO LIMPA (SEM ASAN) ---
    # ASan e Valgrind não podem coexistir no mesmo binário — instrumentações conflitantes.
    # Compilamos apenas com -g para manter os símbolos de depuração.
    subprocess.run(
        ["gcc", "-g", caminho_codigo, "-o", binario_saida],
        capture_output=True  # descarta a saída; erros de compilação são ignorados aqui
    )

    # --- FASE 2: IDENTIFICADOR ÚNICO PARA O SOCKET VGDB ---
    # O vgdb usa um arquivo de socket no /tmp para comunicação entre processos.
    # O prefixo único evita colisões se múltiplas análises rodarem em paralelo.
    id_unico = f"/tmp/vgdb_{uuid.uuid4().hex[:8]}"

    # --- FASE 3: INICIALIZAÇÃO DO VALGRIND EM BACKGROUND ---
    # --vgdb-error=1: suspende a execução do programa no 1º erro detectado,
    #   criando um "ponto de verificação" que o GDB pode inspecionar via vgdb.
    # --leak-check=full: ao final da execução, gera relatório detalhado
    #   de todos os blocos de memória que não foram liberados (definitely lost etc.).
    # --vgdb-prefix: define o caminho do socket vgdb (deve coincidir com o GDB abaixo).
    comando_valgrind = [
        "valgrind",
        "--vgdb-error=1",
        "--leak-check=full",
        f"--vgdb-prefix={id_unico}",
        binario_saida
    ]

    # Detecta se o código lê N pelo stdin para injetar entrada mínima automaticamente.
    # Sem stdin, programas com scanf bloqueiam o processo do Valgrind indefinidamente.
    stdin_analise = _stdin_para_analise(caminho_codigo)

    # Popen (não run) porque precisamos do processo rodando em paralelo enquanto
    # o GDB se conecta a ele. stdout/stderr capturados para leitura posterior.
    # stdin=PIPE permite escrever o input logo após o lançamento do processo.
    processo_valgrind = subprocess.Popen(
        comando_valgrind,
        stdin=subprocess.PIPE if stdin_analise else None,
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True
    )

    # Injeta o stdin mínimo imediatamente após o lançamento (antes do sleep).
    # Para inputs pequenos (< alguns KB), a escrita síncrona não causa deadlock
    # porque o kernel armazena o dado no pipe buffer enquanto o processo ainda
    # não leu. close() após a escrita sinaliza EOF ao binário do aluno.
    if stdin_analise and processo_valgrind.stdin:
        try:
            processo_valgrind.stdin.write(stdin_analise)
            processo_valgrind.stdin.close()
        except BrokenPipeError:
            pass  # processo já encerrou (ex: erro antes de ler stdin)

    # Aguarda o Valgrind inicializar e criar o socket vgdb antes de conectar.
    # 1.5s é uma estimativa; pode precisar de ajuste em máquinas mais lentas.
    time.sleep(1.5)

    # --- FASE 4: CONEXÃO GDB VIA VGDB (INSPEÇÃO AO VIVO) ---
    # O GDB se conecta ao processo suspenso pelo Valgrind como se fosse um
    # servidor remoto GDB — o vgdb faz a ponte entre os dois processos.
    comando_gdb = [
        "gdb", "-q", "--batch",
        # Conecta ao processo suspenso pelo Valgrind através do socket vgdb
        "-ex", f"target remote | vgdb --vgdb-prefix={id_unico}",
        # Imprime todas as variáveis locais do frame atual (onde o erro ocorreu)
        "-ex", "info locals",
        # Imprime o backtrace completo com variáveis de todos os frames da pilha
        "-ex", "bt full",
        # Envia comando ao Valgrind para matar o processo monitorado de forma limpa
        "-ex", "monitor v.kill",
        "-ex", "quit",          # encerra o GDB
        binario_saida
    ]

    execucao_gdb = subprocess.run(comando_gdb, capture_output=True, text=True)

    # Junta stdout e stderr do GDB (backtrace e mensagens de erro podem vir em canais diferentes)
    saida_completa_gdb = execucao_gdb.stdout + execucao_gdb.stderr

    # --- FASE 5: ANÁLISE DO RESULTADO ---

    # Caso 1: O Valgrind suspendeu o programa num erro crítico (ex: Invalid Write/Read)
    # e o GDB emitiu o comando de kill — isso confirma que houve falha de execução.
    if "monitor command request to kill this process" in saida_completa_gdb:
        return {"erro": "Falha de Execução (Valgrind)", "log": saida_completa_gdb}

    # Caso 2: O programa terminou sem erros críticos — agora lemos o relatório
    # final do Valgrind buscando por vazamentos de memória que passaram despercebidos.
    # communicate() aguarda o processo terminar e coleta todo o output restante.
    # timeout=120s: segurança contra Valgrind travado (ex: programa em loop infinito).
    try:
        stdout_v, stderr_v = processo_valgrind.communicate(timeout=120)
    except subprocess.TimeoutExpired:
        processo_valgrind.kill()
        stdout_v, stderr_v = processo_valgrind.communicate()
    log_final_valgrind = stdout_v + stderr_v

    # "definitely lost": blocos alocados com malloc/new que nunca foram liberados
    # e cujo ponteiro foi perdido — vazamento real, sem dúvida.
    # A segunda condição captura qualquer outro erro que o Valgrind contabilizou
    # no sumário final (ex: uso de memória não inicializada).
    if "definitely lost" in log_final_valgrind or (
        "ERROR SUMMARY" in log_final_valgrind
        and "ERROR SUMMARY: 0 errors" not in log_final_valgrind
    ):
        return {"erro": "Vazamento de Memória (Valgrind)", "log": log_final_valgrind}

    # Nenhum erro encontrado: retorna None para indicar que o código passou nesta malha
    return None

