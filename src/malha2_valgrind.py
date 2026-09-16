"""
Malha 2 — Valgrind + vgdb.

Executa o programa sob o Valgrind (Memcheck) com conexão GDB ao vivo via vgdb. Detecta falhas
de execução (acessos inválidos que passaram pela Malha 1) e, sobretudo, vazamentos de memória
no heap (definitely/indirectly lost) e uso de memória não inicializada.

Só roda se a Malha 1 (ASan+GDB) passou limpa — arquitetura em cascata.

SINCRONIZAÇÃO POR EVENTO (não por tempo fixo):
A versão anterior lançava o Valgrind e fazia `time.sleep(1.5)` antes de conectar o GDB — um
anti-padrão: uma espera fixa entra em corrida com o startup do Valgrind. Quando o startup passa
de 1,5s (agravado pelas flags de origem), o GDB conectava com o programa ainda carregando a
libc, fotografava o carregador dinâmico e matava o processo antes do `main`, gerando log inútil.
A solução é esperar por um EVENTO real, com teto de tempo de segurança:
  * o Valgrind CONGELA num erro (marcador no stderr) -> conecta-se o GDB;
  * ou o programa TERMINA sozinho (leak/limpo)        -> lê-se o relatório;
  * ou estoura o timeout (ex.: loop infinito)         -> encerra-se.
A lógica de espera fica isolada em `_aguardar_evento_valgrind` e nos parâmetros abaixo.
"""

import os
import subprocess
import uuid
import time
import threading

from src.deteccao_entrada import stdin_para_analise

# Parâmetros de tempo (teto e intervalo de poll) vêm do config central.
from src.config import VALGRIND_TIMEOUT_S, VALGRIND_POLL_S


# ══════════════════════════════════════════════════════════════════════════════
# PARÂMETROS DE SINCRONIZAÇÃO
# ══════════════════════════════════════════════════════════════════════════════
# Marcador que o Valgrind imprime no stderr QUANDO CONGELA num erro, aguardando o vgdb — sinal
# confiável de "há um erro de execução para inspecionar ao vivo". Não usar "TO DEBUG THIS PROCESS
# USING GDB": essa linha aparece em qualquer conexão do vgdb e não distingue erro real.
MARCADOR_ERRO_EXECUCAO = "(action on error) vgdb me"


# ══════════════════════════════════════════════════════════════════════════════
# FUNÇÕES AUXILIARES DE SINCRONIZAÇÃO (isoladas e substituíveis)
# ══════════════════════════════════════════════════════════════════════════════

def _drenar_em_background(stream, acumulador, lock):
    """
    Lê o stream (stderr do Valgrind) linha a linha numa thread separada, acumulando o texto em
    'acumulador' de forma thread-safe. Numa thread porque o stderr precisa ser inspecionado
    enquanto o processo ainda roda (para detectar o marcador de congelamento) sem bloquear a
    thread principal nem arriscar deadlock de pipe cheio.
    """
    try:
        for linha in iter(stream.readline, ''):
            with lock:
                acumulador.append(linha)
    except Exception:
        pass
    finally:
        try:
            stream.close()
        except Exception:
            pass


def _aguardar_evento_valgrind(processo, stderr_buffer, lock,
                              timeout=VALGRIND_TIMEOUT_S,
                              intervalo=VALGRIND_POLL_S):
    """
    Espera baseada em EVENTO (substitui o antigo time.sleep fixo). Fica em loop até um destes
    acontecer, retornando o status correspondente:
      "erro_execucao" -> Valgrind congelou num erro (marcador no stderr); fica parado aguardando
                         o vgdb, então não há corrida ao conectar o GDB.
      "terminou"      -> processo encerrou sozinho (leak/limpo): basta ler o relatório.
      "timeout"       -> estourou o teto de tempo (ex.: loop infinito).

    Mantida pequena e sem efeitos colaterais para permitir trocar a estratégia (marcador,
    timeout, forma de detecção) sem tocar no resto da malha.
    """
    inicio = time.time()
    while True:
        # 1) Valgrind congelou num erro? (procura o marcador no stderr acumulado)
        with lock:
            texto_ate_agora = "".join(stderr_buffer)
        if MARCADOR_ERRO_EXECUCAO in texto_ate_agora:
            return "erro_execucao"

        # 2) Processo terminou sozinho? (sem erro que o congelasse -> leak/limpo)
        if processo.poll() is not None:
            return "terminou"

        # 3) Estourou o teto de tempo? (proteção contra loop infinito)
        if time.time() - inicio > timeout:
            return "timeout"

        time.sleep(intervalo)


# ══════════════════════════════════════════════════════════════════════════════
# MALHA 2
# ══════════════════════════════════════════════════════════════════════════════

def executar_malha_2_valgrind(caminho_codigo, binario_saida="./bin_valgrind", entrada=None):
    """
    Executa o programa sob o Valgrind com conexão GDB via vgdb para inspeção ao vivo. Detecta
    falhas de execução e vazamentos de memória. Retorna dict com 'erro' e 'log', ou None se limpo.
    """

    # --- FASE 1: COMPILAÇÃO LIMPA (SEM ASAN) ---
    # ASan e Valgrind não coexistem no mesmo binário (instrumentações conflitantes); compila só
    # com -g para manter os símbolos. -std=gnu11: mesmo motivo da Malha 1 — alinha ao CodeBench
    # (um GCC recente usa C23, onde `false`/`true`/`bool` são keywords e quebram códigos legados).
    subprocess.run(
        ["gcc", "-std=gnu11", "-g", caminho_codigo, "-o", binario_saida],
        capture_output=True  # descarta a saída; erros de compilação são ignorados aqui
    )

    # --- FASE 2: IDENTIFICADOR ÚNICO PARA O SOCKET VGDB ---
    # O vgdb usa um socket em /tmp; o prefixo único evita colisões entre análises em paralelo.
    id_unico = f"/tmp/vgdb_{uuid.uuid4().hex[:8]}"

    # --- FASE 3: INICIALIZAÇÃO DO VALGRIND ---
    # --vgdb-error=1: suspende no 1º erro, criando um ponto de verificação inspecionável via vgdb.
    # --leak-check=full: relatório detalhado dos blocos não liberados (definitely lost etc.).
    # --vgdb-prefix: caminho do socket vgdb (deve coincidir com o GDB abaixo).
    # Flags de ORIGEM (causa raiz, não só o sintoma):
    #   --track-origins=yes: para valor não inicializado, rastreia onde o valor nasceu.
    #   --keep-stacktraces=alloc-and-free: para use-after-free, guarda alloc E free.
    #   --read-var-info=yes: nomeia a variável e a linha de declaração.
    comando_valgrind = [
        "valgrind",
        "--vgdb-error=1",
        "--leak-check=full",
        "--track-origins=yes",
        "--keep-stacktraces=alloc-and-free",
        "--read-var-info=yes",
        f"--vgdb-prefix={id_unico}",
        binario_saida
    ]

    # ENTRADA: se `entrada` foi fornecida (ex.: caso de teste do CodeBench via API), é
    # AUTORITATIVA. Só no uso offline (entrada is None) recorre-se à detecção por .in/heurística.
    if entrada is not None:
        stdin_analise = entrada
    else:
        stdin_analise = stdin_para_analise(caminho_codigo)

    # Popen (não run): o processo precisa rodar em paralelo enquanto se observa o stderr e (se
    # preciso) conecta o GDB. stderr=PIPE traz o relatório do Memcheck (observado ao vivo);
    # stdout=DEVNULL descarta a saída do programa (irrelevante à análise, e evita deadlock de pipe).
    processo_valgrind = subprocess.Popen(
        comando_valgrind,
        stdin=subprocess.PIPE if stdin_analise else None,
        stderr=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        text=True
    )

    # Injeta o stdin logo após o lançamento; close() sinaliza EOF ao binário.
    if stdin_analise and processo_valgrind.stdin:
        try:
            processo_valgrind.stdin.write(stdin_analise)
            processo_valgrind.stdin.close()
        except BrokenPipeError:
            pass  # processo já encerrou (ex.: erro antes de ler stdin)

    # Thread que drena o stderr do Valgrind em tempo real para um buffer compartilhado — é ele
    # que a espera por evento inspeciona e de onde sai o relatório final.
    stderr_buffer = []
    lock = threading.Lock()
    leitor = threading.Thread(
        target=_drenar_em_background,
        args=(processo_valgrind.stderr, stderr_buffer, lock),
        daemon=True
    )
    leitor.start()

    # --- FASE 4: SINCRONIZAÇÃO POR EVENTO (sem sleep fixo) ---
    status = _aguardar_evento_valgrind(processo_valgrind, stderr_buffer, lock)

    # ── Caso A: ERRO DE EXECUÇÃO (o Valgrind congelou e espera o vgdb) ──
    if status == "erro_execucao":
        # Valgrind parado no ponto exato do erro (código do aluno). Sem corrida: conecta-se o GDB
        # para fotografar backtrace + variáveis nesse instante.
        comando_gdb = [
            "gdb", "-q", "--batch",
            "-ex", f"target remote | vgdb --vgdb-prefix={id_unico}",
            "-ex", "bt full",          # backtrace completo com variáveis de cada frame
            "-ex", "monitor v.kill",   # encerra o processo monitorado de forma limpa
            "-ex", "quit",
            binario_saida
        ]
        execucao_gdb = subprocess.run(comando_gdb, capture_output=True, text=True)
        saida_gdb = execucao_gdb.stdout + execucao_gdb.stderr

        # Após o kill, o Valgrind finaliza e imprime o resto do relatório: aguarda-se o processo e
        # a thread leitora para capturar o veredito completo do Memcheck.
        try:
            processo_valgrind.wait(timeout=30)
        except subprocess.TimeoutExpired:
            processo_valgrind.kill()
        leitor.join(timeout=5)
        with lock:
            veredito_valgrind = "".join(stderr_buffer)

        # Combina o VEREDITO do Valgrind (o QUÊ + a ORIGEM) com o BACKTRACE do GDB (o ONDE + os
        # valores das variáveis). O parser depois separa sinal de ruído.
        log_combinado = (
            "===== VEREDITO DO VALGRIND (Memcheck) =====\n"
            + veredito_valgrind
            + "\n===== BACKTRACE E VARIAVEIS (GDB via vgdb) =====\n"
            + saida_gdb
        )
        return {"erro": "Falha de Execução (Valgrind)", "log": log_combinado}

    # ── Caso B: TIMEOUT (ex.: loop infinito) ──
    if status == "timeout":
        processo_valgrind.kill()
        leitor.join(timeout=5)
        # Nenhum diagnóstico confiável — deixa a cascata seguir (sem erro registrado).
        return None

    # ── Caso C: TERMINOU sozinho — procura VAZAMENTO no relatório final ──
    # Sem erro de execução que congelasse a run, o Valgrind rodou até o fim e imprimiu o
    # leak-check. Lê-se o buffer já acumulado pela thread leitora.
    leitor.join(timeout=5)
    with lock:
        log_final_valgrind = "".join(stderr_buffer)

    # "definitely lost": bloco alocado e nunca liberado, com ponteiro perdido (vazamento certo).
    # A segunda condição pega qualquer outro erro contabilizado no sumário final.
    if "definitely lost" in log_final_valgrind or (
        "ERROR SUMMARY" in log_final_valgrind
        and "ERROR SUMMARY: 0 errors" not in log_final_valgrind
    ):
        return {"erro": "Vazamento de Memória (Valgrind)", "log": log_final_valgrind}

    # Nenhum erro encontrado: retorna None (o código passou nesta malha).
    return None
