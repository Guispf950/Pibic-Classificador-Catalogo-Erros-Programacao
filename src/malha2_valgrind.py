"""
Malha 2 — Valgrind + vgdb.

Executa o programa sob o Valgrind (Memcheck) com conexão GDB ao vivo via vgdb.
Detecta falhas de execução (acessos inválidos que passaram pela Malha 1) e,
sobretudo, vazamentos de memória no heap (definitely/indirectly lost) e uso de
memória não inicializada.

Só roda se a Malha 1 (ASan+GDB) passou limpa — arquitetura em cascata.

SINCRONIZAÇÃO POR EVENTO (não por tempo fixo)
---------------------------------------------
Antes, a malha lançava o Valgrind e fazia `time.sleep(1.5)` antes de conectar o GDB.
Isso é um ANTI-PADRÃO clássico: uma espera de tempo fixo entra em CORRIDA com o
startup do Valgrind. Quando o startup demora mais que 1,5s (o que as flags de origem
agravaram), o GDB conectava com o programa ainda CARREGANDO a libc — fotografava o
carregador dinâmico e matava o processo antes do `main` rodar, produzindo um log
inútil e sem o relatório de erro/leak.

A solução (padrão na literatura de concorrência/testes) é esperar por um EVENTO real,
com um teto de tempo de segurança, em vez de um atraso fixo:
  * o Valgrind CONGELA num erro (imprime um marcador no stderr) -> conectamos o GDB;
  * ou o programa TERMINA sozinho (sem erro; caso leak/limpo)   -> lemos o relatório;
  * ou estoura o timeout (ex.: loop infinito)                   -> encerramos.

Toda a lógica de espera está isolada em `_aguardar_evento_valgrind` e nos parâmetros
abaixo, para que a estratégia possa ser ajustada depois sem mexer no resto da malha.
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
# VALGRIND_TIMEOUT_S e VALGRIND_POLL_S: importados de src/config.py (ajuste lá).
#
# Marcador que o Valgrind imprime no stderr QUANDO CONGELA num erro, aguardando o vgdb.
# É o sinal CONFIÁVEL de "há um erro de execução para inspecionar ao vivo".
# ATENÇÃO: NÃO usar "TO DEBUG THIS PROCESS USING GDB" — essa linha aparece em QUALQUER
# conexão do vgdb (inclusive numa interrupção manual), então não distingue erro real.
MARCADOR_ERRO_EXECUCAO = "(action on error) vgdb me"


# ══════════════════════════════════════════════════════════════════════════════
# FUNÇÕES AUXILIARES DE SINCRONIZAÇÃO (isoladas e substituíveis)
# ══════════════════════════════════════════════════════════════════════════════

def _drenar_em_background(stream, acumulador, lock):
    """
    Lê um stream (stderr do Valgrind) linha a linha numa thread separada, acumulando
    o texto em 'acumulador' de forma thread-safe.

    Por que numa thread? Porque precisamos INSPECIONAR o stderr enquanto o processo
    ainda roda (para detectar o marcador de congelamento) sem bloquear a thread
    principal — e sem risco de deadlock de pipe cheio.
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
    Espera baseada em EVENTO (substitui o antigo time.sleep fixo).

    Fica em loop até UM destes acontecer, e retorna o status correspondente:
      "erro_execucao" -> o Valgrind congelou num erro (marcador visto no stderr).
                         Ele fica PARADO aguardando o vgdb, então NÃO há corrida:
                         podemos conectar o GDB com calma para inspecionar o estado.
      "terminou"      -> o processo encerrou sozinho (nenhum erro de execução travou
                         a run). É o caminho de vazamento/limpo: basta ler o relatório.
      "timeout"       -> estourou o teto de tempo (ex.: programa em loop infinito).

    Esta função é propositalmente pequena e sem efeitos colaterais para você poder
    trocar a estratégia (marcador, timeout, forma de detecção) sem tocar no resto.
    """
    inicio = time.time()
    while True:
        # 1) O Valgrind congelou num erro? (procura o marcador no stderr acumulado)
        with lock:
            texto_ate_agora = "".join(stderr_buffer)
        if MARCADOR_ERRO_EXECUCAO in texto_ate_agora:
            return "erro_execucao"

        # 2) O processo terminou sozinho? (sem erro que o congelasse -> leak/limpo)
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
    Executa o programa sob monitoramento do Valgrind com conexão GDB via vgdb
    para inspeção ao vivo. Detecta falhas de execução e vazamentos de memória.
    Retorna um dict com 'erro' e 'log' se algo for detectado, ou None se limpo.
    """

    # --- FASE 1: COMPILAÇÃO LIMPA (SEM ASAN) ---
    # ASan e Valgrind não podem coexistir no mesmo binário — instrumentações conflitantes.
    # Compilamos apenas com -g para manter os símbolos de depuração.
    #
    # -std=gnu11: mesmo motivo da Malha 1 — fixa o padrão para casar com o CodeBench.
    # O GCC local recente usa C23 por default, onde `false`/`true`/`bool` são keywords;
    # isso quebra códigos legados que os redefinem e cria falsos positivos ausentes no
    # juiz. gnu11 alinha as duas malhas ao mesmo padrão de compilação.
    subprocess.run(
        ["gcc", "-std=gnu11", "-g", caminho_codigo, "-o", binario_saida],
        capture_output=True  # descarta a saída; erros de compilação são ignorados aqui
    )

    # --- FASE 2: IDENTIFICADOR ÚNICO PARA O SOCKET VGDB ---
    # O vgdb usa um arquivo de socket no /tmp para comunicação entre processos.
    # O prefixo único evita colisões se múltiplas análises rodarem em paralelo.
    id_unico = f"/tmp/vgdb_{uuid.uuid4().hex[:8]}"

    # --- FASE 3: INICIALIZAÇÃO DO VALGRIND ---
    # --vgdb-error=1: suspende a execução do programa no 1º erro detectado,
    #   criando um "ponto de verificação" que o GDB pode inspecionar via vgdb.
    # --leak-check=full: ao final da execução, gera relatório detalhado
    #   de todos os blocos de memória que não foram liberados (definitely lost etc.).
    # --vgdb-prefix: define o caminho do socket vgdb (deve coincidir com o GDB abaixo).
    # Flags de ORIGEM (causa raiz), não só o sintoma:
    #   --track-origins=yes: para VALOR NÃO INICIALIZADO, rastreia ONDE o valor nasceu.
    #   --keep-stacktraces=alloc-and-free: para USE-AFTER-FREE, guarda alloc E free.
    #   --read-var-info=yes: nomeia a variável e a linha em que foi declarada.
    # (Com a sincronização por evento, o custo de startup dessas flags não causa mais
    #  corrida: esperamos o evento real, não um tempo fixo.)
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

    # ENTRADA: se `entrada` foi fornecida (ex.: a API repassando o caso de teste do
    # CodeBench), ela é AUTORITATIVA. Só no uso offline (entrada is None) caímos na
    # detecção por .in/heurística.
    if entrada is not None:
        stdin_analise = entrada
    else:
        stdin_analise = stdin_para_analise(caminho_codigo)

    # Popen (não run) porque precisamos do processo rodando em paralelo enquanto
    # observamos o stderr e (se preciso) conectamos o GDB.
    #   stderr=PIPE: o relatório do Memcheck vem por aqui — é o que observamos ao vivo.
    #   stdout=DEVNULL: a saída impressa pelo programa do aluno não interessa à análise
    #                   de memória, e descartá-la evita qualquer risco de deadlock de pipe.
    processo_valgrind = subprocess.Popen(
        comando_valgrind,
        stdin=subprocess.PIPE if stdin_analise else None,
        stderr=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        text=True
    )

    # Injeta o stdin (caso de teste real) imediatamente após o lançamento.
    # close() após a escrita sinaliza EOF ao binário do aluno.
    if stdin_analise and processo_valgrind.stdin:
        try:
            processo_valgrind.stdin.write(stdin_analise)
            processo_valgrind.stdin.close()
        except BrokenPipeError:
            pass  # processo já encerrou (ex: erro antes de ler stdin)

    # Thread que drena o stderr do Valgrind em tempo real para um buffer compartilhado.
    # É esse buffer que a espera por evento inspeciona (e de onde sai o relatório final).
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

    # ── Caso A: ERRO DE EXECUÇÃO (o Valgrind congelou e espera o vgdb) ──────────
    if status == "erro_execucao":
        # O Valgrind está PARADO no ponto exato do erro (código do aluno). Sem corrida:
        # conectamos o GDB para fotografar backtrace + variáveis nesse instante.
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

        # Depois do kill, o Valgrind finaliza e imprime o resto do relatório: aguardamos
        # o processo e a thread leitora para capturar o VEREDITO completo do Memcheck.
        try:
            processo_valgrind.wait(timeout=30)
        except subprocess.TimeoutExpired:
            processo_valgrind.kill()
        leitor.join(timeout=5)
        with lock:
            veredito_valgrind = "".join(stderr_buffer)

        # Combina o VEREDITO do Valgrind (o QUÊ + a ORIGEM) com o BACKTRACE do GDB (o ONDE
        # + os valores das variáveis). O parser depois separa sinal de ruído.
        log_combinado = (
            "===== VEREDITO DO VALGRIND (Memcheck) =====\n"
            + veredito_valgrind
            + "\n===== BACKTRACE E VARIAVEIS (GDB via vgdb) =====\n"
            + saida_gdb
        )
        return {"erro": "Falha de Execução (Valgrind)", "log": log_combinado}

    # ── Caso B: TIMEOUT (ex.: loop infinito) ───────────────────────────────────
    if status == "timeout":
        processo_valgrind.kill()
        leitor.join(timeout=5)
        # Nenhum diagnóstico confiável — deixa a cascata seguir (sem erro registrado).
        return None

    # ── Caso C: TERMINOU sozinho — procura VAZAMENTO no relatório final ─────────
    # Sem erro de execução que congelasse a run: o Valgrind rodou até o fim e imprimiu
    # o relatório de leak-check. Lemos o buffer já acumulado pela thread leitora.
    leitor.join(timeout=5)
    with lock:
        log_final_valgrind = "".join(stderr_buffer)

    # "definitely lost": bloco alocado e nunca liberado, com ponteiro perdido (vazamento
    # certo). A segunda condição pega qualquer outro erro contabilizado no sumário final.
    if "definitely lost" in log_final_valgrind or (
        "ERROR SUMMARY" in log_final_valgrind
        and "ERROR SUMMARY: 0 errors" not in log_final_valgrind
    ):
        return {"erro": "Vazamento de Memória (Valgrind)", "log": log_final_valgrind}

    # Nenhum erro encontrado: retorna None (o código passou nesta malha).
    return None
