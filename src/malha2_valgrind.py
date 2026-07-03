"""
Malha 2 — Valgrind + vgdb.

Executa o programa sob o Valgrind (Memcheck) com conexão GDB ao vivo via vgdb.
Detecta falhas de execução (acessos inválidos que passaram pela Malha 1) e,
sobretudo, vazamentos de memória no heap (definitely/indirectly lost) e uso de
memória não inicializada.

Só roda se a Malha 1 (ASan+GDB) passou limpa — arquitetura em cascata.
"""

import subprocess
import uuid
import time

from src.deteccao_entrada import stdin_para_analise


def executar_malha_2_valgrind(caminho_codigo, binario_saida="./bin_valgrind"):
    """
    Executa o programa sob monitoramento do Valgrind com conexão GDB via vgdb
    para inspeção ao vivo. Detecta falhas de execução e vazamentos de memória.
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
    stdin_analise = stdin_para_analise(caminho_codigo)

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
