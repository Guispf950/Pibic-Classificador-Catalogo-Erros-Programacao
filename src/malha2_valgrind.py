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
import re
import resource
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
# Marcadores que o Valgrind imprime no stderr QUANDO CONGELA, aguardando o vgdb — sinal
# confiável de "há algo para inspecionar ao vivo". Não usar "TO DEBUG THIS PROCESS USING GDB":
# essa linha aparece em qualquer conexão do vgdb e não distingue erro real.
# Existem DOIS marcadores, não um: "(action on error) vgdb me" quando é o PRÓPRIO Memcheck que
# detecta o erro (ex.: leitura inválida), e "(action on fatal signal) vgdb me" quando o processo
# morre por um SINAL FATAL que o Valgrind não gerou (ex.: SIGABRT do "stack smashing detected"
# do glibc, __stack_chk_fail — a proteção de pilha do próprio compilador reagindo a um overflow
# antes do Memcheck ter chance de reportar). Faltava o segundo caso: sem reconhecê-lo, o laço de
# espera nunca via o processo "travado" (ele está mesmo parado, esperando o vgdb) nem "terminado"
# (não terminou, só está pausado) — ficava girando até estourar VALGRIND_TIMEOUT_S (120s) e
# devolvia "passou limpo" para um programa que na verdade travou com stack smashing. MEDIDO:
# reproduzido fora do pipeline com um binário real (Valgrind 3.22, Juliet
# CWE121_..._alloca_cpy_31.c) — sem o marcador fatal, 120,7s e nenhum diagnóstico; com ele, cai
# no mesmo fluxo de "erro de execução" que já existia, rápido.
MARCADORES_ERRO_EXECUCAO = ("(action on error) vgdb me", "(action on fatal signal) vgdb me")

# Linha de registro de um vazamento real (ver uso no Caso C, no fim do arquivo).
_RX_REGISTRO_VAZAMENTO = re.compile(r"blocks are (?:definitely|indirectly|possibly) lost")


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
        # 1) Valgrind congelou num erro ou sinal fatal? (procura os marcadores no stderr acumulado)
        with lock:
            texto_ate_agora = "".join(stderr_buffer)
        if any(marcador in texto_ate_agora for marcador in MARCADORES_ERRO_EXECUCAO):
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

def executar_malha_2_valgrind(caminho_codigo, binario_saida="./bin_valgrind", entrada=None, flags_extra=None,
                               limite_memoria_mb=None):
    """
    Executa o programa sob o Valgrind com conexão GDB via vgdb para inspeção ao vivo. Detecta
    falhas de execução e vazamentos de memória. Retorna dict com 'erro' e 'log', ou None se limpo.

    `flags_extra`: ver docstring equivalente em `malha1_asan.executar_malha_1_asan` — mesmo uso
    (harness do Juliet), mesma garantia de não afetar a submissão de aluno (sem esse argumento).

    `limite_memoria_mb`: teto opcional (em MB) de memória VIRTUAL (RLIMIT_AS) para o processo do
    Valgrind (e, por herança do fork/exec, para o programa analisado dentro dele). Sem isso, um
    `malloc` de alguns GB (ex.: CWE-789 com valor "absurdo" mas ainda representável num `int` de
    32 bits) fica dentro do que a máquina/sandbox consegue reservar de verdade — o Linux aceita
    (overcommit) e o Valgrind tenta satisfazer o pedido de verdade, o que é lento (MEDIDO: >100s
    num caso real) e trava a Malha 2 até o VALGRIND_TIMEOUT_S. Com o teto, o mesmo `malloc` falha
    rápido (`malloc` devolve NULL) — MEDIDO: um `malloc(8 GB)` sob Valgrind com este teto em 1024
    MB cai de >100s para <1s, sem afetar o restante do relatório do Memcheck (testado também com
    um caso de vazamento real, que continuou detectado normalmente). Use um valor generoso o
    bastante para o PRÓPRIO Valgrind iniciar (medido: 1 GB já é suficiente) e ainda assim bem
    menor que a alocação "absurda" que se quer rejeitar. Só usado pelo harness do Juliet.
    """

    # --- FASE 1: COMPILAÇÃO LIMPA (SEM ASAN) ---
    # ASan e Valgrind não coexistem no mesmo binário (instrumentações conflitantes); compila só
    # com -g para manter os símbolos. -std=gnu11: mesmo motivo da Malha 1 — alinha ao CodeBench
    # (um GCC recente usa C23, onde `false`/`true`/`bool` são keywords e quebram códigos legados).
    compilacao = subprocess.run(
        ["gcc", "-std=gnu11", "-g", caminho_codigo, *(flags_extra or []), "-o", binario_saida],
        capture_output=True, text=True, errors="replace"
    )
    if compilacao.returncode != 0:
        return {"tipo": "compilacao", "erro": "Erro de compilação", "log": compilacao.stderr}

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

    def _aplicar_limite_memoria():
        # Roda DENTRO do processo filho, entre o fork() e o exec() do valgrind — por isso afeta
        # tanto o próprio Valgrind quanto (por herança) o programa analisado dentro dele.
        limite_bytes = limite_memoria_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (limite_bytes, limite_bytes))

    # Popen (não run): o processo precisa rodar em paralelo enquanto se observa o stderr e (se
    # preciso) conecta o GDB. stderr=PIPE traz o relatório do Memcheck (observado ao vivo);
    # stdout=DEVNULL descarta a saída do programa (irrelevante à análise, e evita deadlock de pipe).
    processo_valgrind = subprocess.Popen(
        comando_valgrind,
        stdin=subprocess.PIPE if stdin_analise else None,
        stderr=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        text=True, errors="replace",
        preexec_fn=_aplicar_limite_memoria if limite_memoria_mb else None,
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
        execucao_gdb = subprocess.run(comando_gdb, capture_output=True, text=True, errors="replace")
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

    # Vazamento: só a linha de REGISTRO de perda ("N bytes in M blocks are definitely lost in loss
    # record ..."), a mesma regra do cwe.py. Antes bastava o texto "definitely lost", que também
    # aparece no RESUMO ("definitely lost: 0 bytes in 0 blocks") sempre que sobra memória ainda
    # alcançável no fim — o programa sem vazamento saía "detectado" e sem CWE. MEDIDO no Juliet
    # CWE127 ..._malloc_wchar_t_cpy_45 (versão corrigida).
    # A segunda condição pega qualquer outro erro contabilizado no sumário final.
    if _RX_REGISTRO_VAZAMENTO.search(log_final_valgrind) or (
        "ERROR SUMMARY" in log_final_valgrind
        and "ERROR SUMMARY: 0 errors" not in log_final_valgrind
    ):
        return {"erro": "Vazamento de Memória (Valgrind)", "log": log_final_valgrind}

    # Nenhum erro encontrado: retorna None (o código passou nesta malha).
    return None
