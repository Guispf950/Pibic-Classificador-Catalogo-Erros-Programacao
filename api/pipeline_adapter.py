"""
pipeline_adapter.py — a "cola" entre a API (app.py) e o pipeline (src/).
========================================================================
Por que existe um adaptador?
  A API não deve conhecer os detalhes do pipeline. Ela só chama duas funções:
      analisar(codigo, entrada, nome)   -> dict com o diagnóstico
      stream_feedback(analise, codigo)  -> gerador que produz o texto token a token
  Aqui decidimos se essas funções respondem com dados MOCK (padrão, para testar a
  API/SSE já) ou chamam o PIPELINE REAL (sandbox Docker + src/llm_client).

ARQUITETURA DO MODO REAL (escolhas confirmadas com o pesquisador):
  • DETECÇÃO -> roda ISOLADA no contêiner Docker (sandbox.py), reaproveitando as suas
    Malhas 1 e 2. Devolve o log determinístico do erro.
  • CLASSIFICAÇÃO e FEEDBACK -> rodam no HOST (precisam de rede para o Ollama, que o
    contêiner não tem). classificar_erro() e gerar_feedback_stream() vêm do seu src/.

Como alternar (variáveis de ambiente):
  USAR_PIPELINE_REAL=1   -> liga o pipeline real (senão, MOCK).
  MODO_SANDBOX=docker    -> detecção no contêiner (senão, sandbox devolve mock).
  Rode a API a partir da RAIZ do projeto (ver README) para o `import src...` e a base
  de conhecimento (./base_conhecimento) resolverem.
"""

import os
import sys
import time

# ── Shim de caminho: garante que a RAIZ do projeto está no sys.path ───────────
# Assim `from src...` funciona mesmo se a API for iniciada de dentro de api/.
# (A raiz é a pasta-mãe de api/, onde ficam src/ e base_conhecimento/.)
_RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _RAIZ not in sys.path:
    sys.path.insert(0, _RAIZ)

# Chave que liga/desliga o pipeline real. Padrão "0" = MOCK (testável sem dependências).
USAR_PIPELINE_REAL = os.environ.get("USAR_PIPELINE_REAL", "0") == "1"


# ══════════════════════════════════════════════════════════════════════════════
# FUNÇÃO 1 — analisar(): devolve o diagnóstico determinístico do erro
# ══════════════════════════════════════════════════════════════════════════════
def analisar(codigo: str, entrada: str, nome_arquivo: str) -> dict:
    if not USAR_PIPELINE_REAL:
        # ---- MODO MOCK: diagnóstico fixo, só para a API responder e testar o contrato.
        return {
            "tipo_erro": "use-after-free",
            "cwe_id": "CWE-416",
            "cwe_nome": "Use After Free",
            "linha_sintoma": "23",
            "linha_causa": "20",
            "evidencia_log": "==1234== Invalid read of size 8",
            "mock": True,
        }

    # ---- MODO REAL ------------------------------------------------------------
    # Imports adiados (só quando o modo real está ligado): evita exigir src/ e rede
    # quando você só quer testar a API em mock.
    from sandbox import rodar_em_sandbox               # detecção isolada (Docker)
    from src.llm_client import classificar_erro         # 1ª chamada ao LLM (host)

    # 1) DETECÇÃO no contêiner: roda ASan/Valgrind sobre o código do aluno.
    deteccao = rodar_em_sandbox(codigo, entrada, nome_arquivo)

    # 2) Sem erro detectado -> resposta explícita (nada de LLM).
    if not deteccao.get("erro_encontrado"):
        return {
            "tipo_erro": "nenhum",
            "cwe_id": "-",
            "cwe_nome": "-",
            "linha_sintoma": "-",
            "linha_causa": "-",
            "evidencia_log": "-",
            "ferramenta": deteccao.get("ferramenta", "Nenhuma"),
            "sem_erro": True,
        }

    # 3) CLASSIFICAÇÃO no host — agora 100% DETERMINÍSTICA (sem LLM): CWE + tipo_erro +
    #    linhas + anotação inline (// @@). É rápida, então serve ao diagnóstico imediato.
    analise = classificar_erro(
        deteccao["log_limpo"],
        codigo,
        nome_arquivo,
        log_bruto=deteccao["log_bruto"],
    )
    # Erro de compilação não tem CWE de memória: rotula explicitamente para o front.
    if deteccao.get("categoria") == "compilacao":
        analise["tipo_erro"] = "compilation-error"
    # Anexa a ferramenta que detectou (útil para o front e para depurar).
    analise["ferramenta"] = deteccao.get("ferramenta", "-")
    return analise


# ══════════════════════════════════════════════════════════════════════════════
# FUNÇÃO 2 — stream_feedback(): PRODUZ o texto do feedback token a token
# ══════════════════════════════════════════════════════════════════════════════
# É um GERADOR (usa `yield`): entrega pedaços conforme são produzidos — o que
# permite o streaming (SSE) até o navegador.
def stream_feedback(analise: dict, codigo: str):
    # Se a análise indicou que NÃO houve erro, não há feedback a gerar.
    if analise.get("sem_erro"):
        yield "Nenhum erro de memória foi detectado neste código."
        return

    if not USAR_PIPELINE_REAL:
        # ---- MODO MOCK: simula o LLM "digitando" (para ver o efeito de streaming).
        texto = (
            "Repare no ponteiro usado na linha indicada: ele aponta para uma "
            "regiao de memoria que ja foi liberada antes desse ponto. O que "
            "acontece quando um programa acessa memoria depois de libera-la? "
            "Volte ao ponto onde a liberacao ocorre e pense na ordem das operacoes."
        )
        for palavra in texto.split(" "):
            yield palavra + " "
            time.sleep(0.05)
        return

    # ---- MODO REAL: streama tokens de verdade do Ollama (texto puro) ----------
    # gerar_feedback_stream reutiliza o MESMO prompt socrático/anti-vazamento do
    # gerar_feedback (via montar_prompt_feedback), mas em modo texto e em stream.
    from src.llm_client import gerar_feedback_stream
    for token in gerar_feedback_stream(codigo, analise):
        yield token
